# SPDX-License-Identifier: Apache-2.0
"""Real MI300X (gfx942) backend: PM4 over an AQL compute queue.

On MI300X (8 XCCs) raw PM4 on a plain COMPUTE queue is consumed but NOT executed. The
reachable path is a COMPUTE_AQL queue whose 64-byte ring packets are VENDOR_SPECIFIC AQL
packets that each wrap a PM4 INDIRECT_BUFFER pointing at a separate PM4 command buffer.
Every constant below is a hardware fact verified on MI300X (via tinygrad as ground
truth): no compute bit on IB PM4; ring+cmdbuf EXECUTABLE+NO_SUBSTITUTE; EOP/CWSR in VRAM;
an sfence before the 64-bit doorbell; CWSR sizing from node props; RUNTIME_ENABLE.

The oracle arms the three KFD events (SIGNAL/MEMORY/HW_EXCEPTION) at setup and reads them
via WAIT_EVENTS: a MEMORY event carries the faulting VA (vm_fault), HW_EXCEPTION means an
illegal packet, and no event + no completion is a hang. A faulting/hanging case leaves the
single queue dead, so ``recover`` destroys and recreates it for the next case.
"""
from __future__ import annotations

import ctypes
import mmap as _mmap
import os
import struct

from ..campaign.finding import RawSignals
from ..fuzz.gen import GenCase
from ..pm4.spec import PACKET_TYPE3
from .stream import build_stream

# A real store fence (x86-64 `sfence; ret`): the ring/cmdbuf/wptr live in write-combining
# memory; without a fence the doorbell can ring before those stores are globally visible.
_SFENCE = b"\x0f\xae\xf8\xc3"
_sfence_page = _mmap.mmap(-1, len(_SFENCE), prot=_mmap.PROT_READ | _mmap.PROT_WRITE | _mmap.PROT_EXEC)
_sfence_page.write(_SFENCE)
_sfence = ctypes.CFUNCTYPE(None)(ctypes.addressof(ctypes.c_char.from_buffer(_sfence_page)))

RING_SIZE = 16 << 20     # 16 MiB AQL ring (matches ROCr/tinygrad; a tiny ring did not execute)
BO_SIZE = 0x1000
CMDBUF_SIZE = 0x1000
# dst is the write target (page 0) + a multi-page canary guard (pages 1..): a packet that
# overruns the target spills into the guard, which we fill before each case and re-check after.
# A changed guard word = an out-of-bounds write the packet had no business making
# (SILENT_CORRUPTION). src is oversized so an over-long copy reads valid source and writes the
# guard WITHOUT a src-side fault first — otherwise the overrun would always hide behind a vm_fault.
_SRC_SIZE = 0x8000
_DST_SIZE = 0x8000
_CANARY_OFF = 0x1000
_CANARY_LEN = _DST_SIZE - _CANARY_OFF   # guard spans dst pages 1.. ; refilled per case
_PAGE = 0x1000
_AQL_PKT_DWORDS = 16     # an AQL packet is 64 bytes

# --- discovered constants (HSA + PM4 headers; see tinygrad ops_amd.py / amd_gpu.py) ---
_INDIRECT_BUFFER = 0x3F
_INDIRECT_BUFFER_VALID = 1 << 23
_AQL_HDR = (1 << 8) | (2 << 9) | (2 << 11)          # BARRIER | SCACQUIRE=SYS | SCRELEASE=SYS
_AQL_VENDOR_HDR = _AQL_HDR | (0 << 0) | (1 << 16)   # type VENDOR_SPECIFIC + amd_format PM4_IB
# amd_queue_t (256 bytes) field byte-offsets
_Q_WRITE_DISPATCH_ID = 56
_Q_MAX_CU_ID = 72
_Q_MAX_WAVE_ID = 76
_Q_READ_DISPATCH_ID = 128
_Q_RD_FIELD_BASE_OFFSET = 136
_Q_PROPERTIES = 180
_AMD_QUEUE_SIZE = 256
_AMD_QUEUE_PROPERTIES_IS_PTR64 = 2
_AMD_QUEUE_PROPERTIES_ENABLE_PROFILING = 8
# KFD event constants + kfd_event_data (48 B) field offsets within each entry
_EVENT_SIGNAL, _EVENT_MEMORY, _EVENT_HW_EXCEPTION = 0, 8, 3
_EVENT_SIZE = 48
_EV_ID_OFF = 40
_EV_MEM_VA_OFF = 16
_EV_MEM_GPUID_OFF = 24
_EV_HW_GPUID_OFF = 12


def _ru(x: int, a: int) -> int:
    return (x + a - 1) // a * a


def _pm4_indirect_buffer_packet(cmd_addr: int, n_dwords: int) -> list[int]:
    header = (PACKET_TYPE3 << 30) | (_INDIRECT_BUFFER << 8) | (2 << 16)  # n=2 -> 3 body dwords
    return [header, cmd_addr & 0xFFFFFFFF, cmd_addr >> 32, n_dwords | _INDIRECT_BUFFER_VALID]


def _aql_vendor_packet(cmd_addr: int, n_dwords: int) -> list[int]:
    """A 64-byte VENDOR_SPECIFIC AQL packet wrapping the IB (16 dwords)."""
    ib = _pm4_indirect_buffer_packet(cmd_addr, n_dwords)
    pkt = [_AQL_VENDOR_HDR, *ib, 10] + [0] * 10   # trailing dw_count_remain=10 + pad to 64 B
    assert len(pkt) == _AQL_PKT_DWORDS
    return pkt


def _queue_props(props: dict) -> dict:
    """Sizing + queue-descriptor values from the node's props (gfx9/kfd_queue.c formula)."""
    assert props["gfx_target_version"] // 10000 == 9, "gfx9 only"
    xccs = props.get("num_xcc", 1) or 1
    simd_per_cu = props["simd_per_cu"]
    cu_cnt = props["simd_count"] // simd_per_cu // xccs
    se_cnt = props["array_count"] // props["simd_arrays_per_engine"] // xccs
    waves_per_cu = props["max_waves_per_simd"] * simd_per_cu
    wave_cnt = min(cu_cnt * 40, se_cnt * xccs * 512)
    sgrp, hwreg, lds, vgpr = 0x4000, 0x1000, 0x10000, 0x80000
    wg_data = _ru((vgpr + sgrp + lds + hwreg) * cu_cnt, _PAGE)
    ctl_stack = _ru(8 * wave_cnt + 8 + 40, _PAGE)
    ctx_save_restore = wg_data + ctl_stack   # matches ROCr/tinygrad (0x1621000 on MI300X)
    debug_mem = _ru(wave_cnt * 32, 64)
    cwsr_buf = _ru((ctx_save_restore + debug_mem) * xccs, _PAGE)
    return {"eop": 0x1000, "cwsr_buf": cwsr_buf, "ctx_save_restore_size": ctx_save_restore,
            "ctl_stack_size": ctl_stack, "max_cu_id": cu_cnt * xccs - 1,
            "max_wave_id": waves_per_cu - 1}


class Mi300Backend:
    def __init__(self, gpu_index: int = 0):
        self.gpu_index = gpu_index
        self._dev = None
        self._io = None
        self._ring = self._gart = self._cmdbuf = None
        self._signal = self._src = self._dst = None
        self._canary = b""   # the guard pattern for the in-flight case (set per submit)
        self._eop = self._cwsr = self._event_page = None
        self._doorbell = None
        self._queue_id = None
        self._wptr = 0
        self._q = None                 # cached _queue_props
        self._events = None            # ctypes array of 3 kfd_event_data
        self._events_addr = 0

    # --- setup ------------------------------------------------------------
    def setup(self, inject=None) -> None:
        from ..kfd import KFDDevice, get_ioctls
        from ..kfd.device import _parse_properties
        from ..kfd.memory import alloc_gtt
        self._io = get_ioctls()
        if inject is not None:
            self._dev = inject
        else:
            self._dev = KFDDevice(self.gpu_index)
            self._dev.open()
            self._io.get_version(self._dev.kfd_fd)
            self._io.acquire_vm(self._dev.kfd_fd, gpu_id=self._dev.gpu_id, drm_fd=self._dev.drm_fd)
            self._runtime_enable()
            self._setup_events()

        self._ring = alloc_gtt(self._dev, RING_SIZE, coherent=True, executable=True)
        self._gart = alloc_gtt(self._dev, _AMD_QUEUE_SIZE, coherent=True)
        self._cmdbuf = alloc_gtt(self._dev, CMDBUF_SIZE, coherent=True, executable=True)
        self._signal = alloc_gtt(self._dev, BO_SIZE, coherent=True)
        self._src = alloc_gtt(self._dev, _SRC_SIZE, coherent=True)   # oversized: feeds over-long copies
        self._dst = alloc_gtt(self._dev, _DST_SIZE, coherent=True)   # target page + canary guard pages

        props = _parse_properties(self._dev.gpu.node_path / "properties")
        self._q = _queue_props(props)
        self._eop = alloc_gtt(self._dev, self._q["eop"], cpu_access=False, vram=True, executable=True)
        self._cwsr = alloc_gtt(self._dev, self._q["cwsr_buf"], cpu_access=False, vram=True, executable=True)
        self._create_queue()

    def _setup_events(self) -> None:
        """Register the event page + arm SIGNAL/MEMORY/HW_EXCEPTION, keeping their ids in a
        kfd_event_data[3] array for WAIT_EVENTS."""
        from ..kfd.autogen import kfd as k
        from ..kfd.memory import alloc_gtt
        self._event_page = alloc_gtt(self._dev, 0x8000, cpu_access=False)
        self._io.create_event(self._dev.kfd_fd, event_page_offset=self._event_page.handle)
        self._events = (k.struct_kfd_event_data * 3)()
        self._events_addr = ctypes.addressof(self._events)
        self._event_ids = []
        self._arm_events()

    def _arm_events(self) -> None:
        """Create (or recreate) the 3 fault events and write their ids into the wait array.
        MEMORY/HW_EXCEPTION are not auto-reset: once a fault signals them they stay set, so
        after reading a fault we must recreate them to get fresh per-case fault state."""
        self._event_ids = []
        for etype in (_EVENT_SIGNAL, _EVENT_MEMORY, _EVENT_HW_EXCEPTION):
            res = self._io.create_event(self._dev.kfd_fd, event_type=etype,
                                        auto_reset=int(etype == _EVENT_SIGNAL))
            self._event_ids.append(res.event_id)
        ctypes.memset(self._events_addr, 0, _EVENT_SIZE * 3)
        for i, eid in enumerate(self._event_ids):
            struct.pack_into("<I", self._events, i * _EVENT_SIZE + _EV_ID_OFF, eid)

    def _rearm_events(self) -> None:
        for eid in self._event_ids:
            try:
                self._io.destroy_event(self._dev.kfd_fd, event_id=eid)
            except Exception:
                pass
        self._arm_events()

    def _create_queue(self) -> None:
        from ..kfd.autogen import kfd as k
        self._wptr = 0
        self._write_amd_queue_descriptor(self._q)
        res = self._io.create_queue(
            self._dev.kfd_fd,
            ring_base_address=self._ring.addr, ring_size=RING_SIZE,
            read_pointer_address=self._gart.addr + _Q_READ_DISPATCH_ID,
            write_pointer_address=self._gart.addr + _Q_WRITE_DISPATCH_ID,
            gpu_id=self._dev.gpu_id,
            queue_type=k.KFD_IOC_QUEUE_TYPE_COMPUTE_AQL,
            queue_percentage=100, queue_priority=7,
            eop_buffer_address=self._eop.addr, eop_buffer_size=self._q["eop"],
            ctx_save_restore_address=self._cwsr.addr,
            ctx_save_restore_size=self._q["ctx_save_restore_size"],
            ctl_stack_size=self._q["ctl_stack_size"],
        )
        self._queue_id = res.queue_id
        self._map_doorbell(res.doorbell_offset)

    def _write_amd_queue_descriptor(self, q: dict) -> None:
        buf = bytearray(_AMD_QUEUE_SIZE)
        struct.pack_into("<I", buf, _Q_MAX_CU_ID, q["max_cu_id"])
        struct.pack_into("<I", buf, _Q_MAX_WAVE_ID, q["max_wave_id"])
        struct.pack_into("<I", buf, _Q_RD_FIELD_BASE_OFFSET, _Q_READ_DISPATCH_ID)
        struct.pack_into("<I", buf, _Q_PROPERTIES,
                         _AMD_QUEUE_PROPERTIES_IS_PTR64 | _AMD_QUEUE_PROPERTIES_ENABLE_PROFILING)
        ctypes.memmove(self._gart.addr, bytes(buf), _AMD_QUEUE_SIZE)

    def _runtime_enable(self) -> None:
        """AMDKFD_IOC_RUNTIME_ENABLE (nr 0x25, _IOWR, 16-B args) — turns on the process
        runtime so the CP/MES executes queue packets. Called directly: absent from older
        uapi headers, so generated bindings may lack it, but the kernel supports it."""
        import fcntl
        ioc = (3 << 30) | (16 << 16) | (ord("K") << 8) | 0x25
        buf = bytearray(16)
        struct.pack_into("<I", buf, 8, 1)   # mode_mask = KFD_RUNTIME_ENABLE_MODE_ENABLE
        fcntl.ioctl(self._dev.kfd_fd, ioc, buf)

    def _map_doorbell(self, doorbell_offset: int) -> None:
        import os

        from ..kfd.memory import _libc
        base = doorbell_offset & ~0x1FFF
        page = _libc.mmap(None, 0x2000, _mmap.PROT_READ | _mmap.PROT_WRITE,
                          _mmap.MAP_SHARED, self._dev.kfd_fd, base)
        if page == ctypes.c_void_p(-1).value:
            errno = ctypes.get_errno()
            raise OSError(errno, f"doorbell mmap failed: {os.strerror(errno)}")
        self._doorbell = page + (doorbell_offset - base)

    # --- materialize (hardware-free; shared with the fake) ----------------
    def materialize(self, case: GenCase) -> list[int]:
        bo_vas = {"src": self._src.addr, "dst": self._dst.addr}
        return build_stream(case, bo_vas, self._signal.addr)

    # --- submit -----------------------------------------------------------
    def submit(self, dwords: list[int]) -> None:
        self._write_signal(0)
        self._fill_canary()   # arm the guard page past dst before the GPU runs this case
        cmd = ctypes.cast(self._cmdbuf.addr, ctypes.POINTER(ctypes.c_uint32))
        for i, dw in enumerate(dwords):
            cmd[i] = dw
        pkt = _aql_vendor_packet(self._cmdbuf.addr, len(dwords))
        slot = (self._wptr % (RING_SIZE // 64)) * _AQL_PKT_DWORDS
        ring = ctypes.cast(self._ring.addr, ctypes.POINTER(ctypes.c_uint32))
        for i, dw in enumerate(pkt):
            ring[slot + i] = dw
        self._wptr += 1
        ctypes.memmove(self._gart.addr + _Q_WRITE_DISPATCH_ID,
                       ctypes.byref(ctypes.c_uint64(self._wptr)), 8)
        _sfence()  # ring/cmdbuf/wptr must be globally visible before the doorbell
        ctypes.cast(self._doorbell, ctypes.POINTER(ctypes.c_uint64))[0] = self._wptr - 1

    def _write_signal(self, v: int) -> None:
        ctypes.cast(self._signal.addr, ctypes.POINTER(ctypes.c_uint32))[0] = v

    def _read_signal(self) -> int:
        return ctypes.cast(self._signal.addr, ctypes.POINTER(ctypes.c_uint32))[0]

    def _fill_canary(self) -> None:
        # a fresh RANDOM pattern per case: a fixed constant could be the exact value an OOB write
        # (or an over-long copy of source bytes) happens to store, hiding the corruption.
        self._canary = os.urandom(_CANARY_LEN)
        ctypes.memmove(self._dst.addr + _CANARY_OFF, self._canary, _CANARY_LEN)

    def _check_canary(self) -> int | None:
        """Byte offset of the first overwritten guard byte, or None if the guard is intact.
        Bulk compare at C speed (string_at); the per-byte scan only runs on an actual hit."""
        got = ctypes.string_at(self._dst.addr + _CANARY_OFF, _CANARY_LEN)
        if got == self._canary:
            return None
        i = next(k for k in range(_CANARY_LEN) if got[k] != self._canary[k])
        return _CANARY_OFF + i

    # --- observe: completion (signal VA) + fault events (WAIT_EVENTS) -----
    def _clear_events(self) -> None:
        for i in range(3):
            ctypes.memset(self._events_addr + i * _EVENT_SIZE, 0, _EV_ID_OFF)  # zero union, keep id

    def _ev_u32(self, entry: int, off: int) -> int:
        return ctypes.cast(self._events_addr + entry * _EVENT_SIZE + off,
                           ctypes.POINTER(ctypes.c_uint32))[0]

    def _ev_u64(self, entry: int, off: int) -> int:
        return ctypes.cast(self._events_addr + entry * _EVENT_SIZE + off,
                           ctypes.POINTER(ctypes.c_uint64))[0]

    def observe(self, timeout_ms: float) -> RawSignals:
        import dataclasses
        import time
        self._clear_events()
        deadline = time.monotonic() + timeout_ms / 1000.0
        sig = RawSignals(signal_timeout=True, rptr_advanced=False)  # fall-through = hang
        while time.monotonic() < deadline:
            if self._read_signal() == 1:
                sig = RawSignals(kfd_events=("SIGNAL",), signal_written=True)
                break
            self._io.wait_events(self._dev.kfd_fd, events_ptr=self._events_addr,
                                 num_events=3, wait_for_all=0, timeout=2)
            if self._ev_u32(1, _EV_MEM_GPUID_OFF):          # MEMORY event -> VM fault
                va = self._ev_u64(1, _EV_MEM_VA_OFF)
                sig = RawSignals(kfd_events=("MEMORY",), faulting_va=va,
                                 dmesg=(f"MMU fault at 0x{va:x}",))
                break
            if self._ev_u32(2, _EV_HW_GPUID_OFF):           # HW_EXCEPTION -> illegal packet
                sig = RawSignals(kfd_events=("HW_EXCEPTION",))
                break
        # on ANY outcome, check whether the case overran dst into the guard page
        off = self._check_canary()
        if off is not None:
            sig = dataclasses.replace(sig, canary_corrupted=True, canary_offset=off)
        return sig

    # --- recovery: a faulting/hanging case kills the queue; rebuild it ----
    def recover(self) -> bool:
        """Destroy and recreate the compute queue after a queue-killing case, reusing the
        buffers. Returns True if the queue came back (the GPU is still alive), False if the
        device is wedged (recreate failed)."""
        try:
            self._io.destroy_queue(self._dev.kfd_fd, queue_id=self._queue_id)
        except Exception:
            pass
        self._rearm_events()   # clear any signaled MEMORY/HW_EXCEPTION so next case is fresh
        try:
            self._create_queue()
            return True
        except Exception:
            return False

    def liveness_probe(self) -> bool:
        return self._dev is not None and self._dev.is_open

    def teardown(self) -> None:
        if self._dev is not None and self._queue_id is not None:
            try:
                self._io.destroy_queue(self._dev.kfd_fd, queue_id=self._queue_id)
            except Exception:
                pass
        if self._dev is not None:
            self._dev.close()
