# SPDX-License-Identifier: Apache-2.0
"""Memory management for KFD devices."""

from __future__ import annotations

import ctypes
import mmap
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .device import KFDDevice

# Load libc once at module level
_libc = ctypes.CDLL("libc.so.6", use_errno=True)
_libc.mmap.argtypes = [
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_long,
]
_libc.mmap.restype = ctypes.c_void_p
_libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
_libc.munmap.restype = ctypes.c_int

# Python's mmap module doesn't expose MAP_FIXED on all platforms; it's 0x10 on Linux.
MAP_FIXED = getattr(mmap, "MAP_FIXED", 0x10)


@dataclass
class MemoryRegion:
    """
    A mapped memory region with automatic cleanup.

    Usage:
        with mmap_anonymous(0x1000) as mem:
            # mem.addr is the virtual address
            # mem.size is the size
            pass
    """

    addr: int
    size: int
    _unmapped: bool = field(default=False, repr=False)

    def unmap(self) -> None:
        """Unmap this memory region."""
        if self._unmapped:
            return
        ret = _libc.munmap(ctypes.c_void_p(self.addr), self.size)
        if ret != 0:
            errno = ctypes.get_errno()
            raise OSError(errno, os.strerror(errno))
        self._unmapped = True

    def __enter__(self) -> MemoryRegion:
        return self

    def __exit__(self, *_) -> None:
        self.unmap()


def mmap_anonymous(
    size: int,
    prot: int = mmap.PROT_READ | mmap.PROT_WRITE,
    addr: int | None = None,
) -> MemoryRegion:
    """
    Create an anonymous memory mapping.

    Args:
        size: Size in bytes
        prot: Memory protection flags (default: PROT_READ | PROT_WRITE)
        addr: Desired address hint (optional)

    Returns:
        MemoryRegion that will auto-unmap on context exit
    """
    flags = mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS
    result = _libc.mmap(
        ctypes.c_void_p(addr) if addr else None,
        size,
        prot,
        flags,
        -1,
        0,
    )
    if result == ctypes.c_void_p(-1).value:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return MemoryRegion(addr=result, size=size)


@dataclass
class GPUMemory:
    """
    GPU memory allocation with handle for KFD operations.

    Created via allocate_gpu_memory(), cleaned up via free_gpu_memory().
    """

    region: MemoryRegion
    handle: int
    gpu_ids: list[int] = field(default_factory=list)

    @property
    def addr(self) -> int:
        """Virtual address of this allocation."""
        return self.region.addr

    @property
    def size(self) -> int:
        """Size of this allocation."""
        return self.region.size


def allocate_gpu_memory(
    device: KFDDevice,
    size: int,
    flags: int,
    map_to_gpu: bool = True,
) -> GPUMemory:
    """
    Allocate GPU-accessible memory.

    Args:
        device: KFD device to allocate on
        size: Size in bytes
        flags: KFD allocation flags (e.g., KFD_IOC_ALLOC_MEM_FLAGS_GTT)
        map_to_gpu: Whether to map to GPU immediately

    Returns:
        GPUMemory object
    """
    from .ioctl import get_ioctls

    ioctls = get_ioctls()

    # Create anonymous mapping first
    region = mmap_anonymous(size, prot=0)

    try:
        # Allocate via KFD
        result = ioctls.alloc_memory_of_gpu(
            device.kfd_fd,
            va_addr=region.addr,
            size=size,
            gpu_id=device.gpu_id,
            flags=flags,
            mmap_offset=0,
        )

        mem = GPUMemory(region=region, handle=result.handle)

        if map_to_gpu:
            map_to_gpu_memory(device, mem)

        return mem
    except Exception:
        region.unmap()
        raise


def map_to_gpu_memory(device: KFDDevice, mem: GPUMemory) -> None:
    """Map GPU memory to the device."""
    from .ioctl import get_ioctls

    ioctls = get_ioctls()

    if device.gpu_id in mem.gpu_ids:
        return  # already mapped to this GPU; re-mapping would double-count gpu_ids
    mem.gpu_ids.append(device.gpu_id)
    gpu_array = (ctypes.c_int32 * len(mem.gpu_ids))(*mem.gpu_ids)

    result = ioctls.map_memory_to_gpu(
        device.kfd_fd,
        handle=mem.handle,
        device_ids_array_ptr=ctypes.addressof(gpu_array),
        n_devices=len(mem.gpu_ids),
    )

    if result.n_success != len(mem.gpu_ids):
        raise RuntimeError(f"Map failed: {result.n_success}/{len(mem.gpu_ids)} succeeded")


def alloc_gtt(device: KFDDevice, size: int, cpu_access: bool = True,
              coherent: bool = False, executable: bool = False,
              vram: bool = False) -> GPUMemory:
    """Allocate a GTT buffer the CPU and GPU share.

    ``cpu_access`` re-maps the SAME virtual address over the GTT backing (MAP_FIXED +
    the kernel-returned ``mmap_offset`` against the DRM fd, the tinygrad pattern) so the
    CPU can read/write it.

    ``coherent`` adds COHERENT|UNCACHED so the GPU's writes are immediately visible to
    the CPU. Use it ONLY for buffers the GPU WRITES and the CPU reads back (signal, dst):
    applying it to the ring makes the CP's fetcher fault (observed: CPF permission fault),
    because the ring/rptr-wptr the CP reads must stay in the default cacheable path.
    """
    from .autogen import kfd as k

    domain = k.KFD_IOC_ALLOC_MEM_FLAGS_VRAM if vram else k.KFD_IOC_ALLOC_MEM_FLAGS_GTT
    # NO_SUBSTITUTE on every buffer (as ROCr/tinygrad do): without it the kernel may migrate
    # the backing after the GPU mapping, so the CP reads stale physical memory.
    flags = domain | k.KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE | k.KFD_IOC_ALLOC_MEM_FLAGS_NO_SUBSTITUTE
    if cpu_access:
        # PUBLIC makes the BO CPU-mmappable via the DRM node. WITHOUT it the MAP_FIXED
        # remap does not back the BO, so CPU and GPU address the SAME va but DIFFERENT
        # physical memory — the GPU drains a zero ring (rptr advances, no fault) and no
        # write is ever visible. This is required on every CPU-shared buffer.
        flags |= k.KFD_IOC_ALLOC_MEM_FLAGS_PUBLIC
    if coherent:
        # COHERENT|UNCACHED: GPU writes visible to the CPU.
        flags |= k.KFD_IOC_ALLOC_MEM_FLAGS_COHERENT | k.KFD_IOC_ALLOC_MEM_FLAGS_UNCACHED
    if executable:
        # the CP fetches/EXECUTES PM4 from these BOs. EXECUTABLE alone made the CP fetcher
        # fault earlier; it needs NO_SUBSTITUTE alongside it (the ROCr/tinygrad combination).
        flags |= k.KFD_IOC_ALLOC_MEM_FLAGS_EXECUTABLE | k.KFD_IOC_ALLOC_MEM_FLAGS_NO_SUBSTITUTE
    from .ioctl import get_ioctls

    ioctls = get_ioctls()
    region = mmap_anonymous(size, prot=0)
    try:
        res = ioctls.alloc_memory_of_gpu(
            device.kfd_fd, va_addr=region.addr, size=size,
            gpu_id=device.gpu_id, flags=flags, mmap_offset=0,
        )
        mem = GPUMemory(region=region, handle=res.handle)
        map_to_gpu_memory(device, mem)
        if cpu_access:
            # remap the reserved VA onto the GTT backing so CPU stores are visible to the GPU
            p = _libc.mmap(
                ctypes.c_void_p(region.addr), size,
                mmap.PROT_READ | mmap.PROT_WRITE,
                mmap.MAP_SHARED | MAP_FIXED, device.drm_fd, res.mmap_offset,
            )
            if p == ctypes.c_void_p(-1).value:
                errno = ctypes.get_errno()
                raise OSError(errno, os.strerror(errno))
        return mem
    except Exception:
        region.unmap()
        raise


def free_gpu_memory(device: KFDDevice, mem: GPUMemory) -> None:
    """Free GPU memory and unmap from all GPUs."""
    from .ioctl import get_ioctls

    ioctls = get_ioctls()

    # Unmap from GPUs first
    if mem.gpu_ids:
        gpu_array = (ctypes.c_int32 * len(mem.gpu_ids))(*mem.gpu_ids)
        ioctls.unmap_memory_from_gpu(
            device.kfd_fd,
            handle=mem.handle,
            device_ids_array_ptr=ctypes.addressof(gpu_array),
            n_devices=len(mem.gpu_ids),
        )

    # Free KFD allocation
    ioctls.free_memory_of_gpu(device.kfd_fd, handle=mem.handle)

    # Unmap virtual memory
    mem.region.unmap()
