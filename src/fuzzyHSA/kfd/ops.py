# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import fcntl
import ctypes, mmap
import pathlib
from typing import Dict, List, Any, Optional

# importing generated files via the fuzzyHSA package
import fuzzyHSA.kfd.autogen.kfd as kfd  
import fuzzyHSA.kfd.autogen.hsa as hsa
import fuzzyHSA.kfd.autogen.amd_gpu as amd_gpu
from fuzzyHSA.utils import read_file, read_properties
from .utils import ioctls_from_header, is_usable_gpu, handle_union_field, assert_size_matches, init_c_struct_t, round_up, to_mv

from .defaults import AQL_PACKET_SIZE, SDMA_MAX_COPY_SIZE, PAGE_SIZE, SIGNAL_SIZE, SIGNAL_COUNT


class MemoryManager:
    """A class to encapsulate memory mapping functionality using libc."""

    def __init__(self):
        """Load libc and set up mmap and munmap function prototypes."""
        self.libc = ctypes.CDLL("libc.so.6")
        self.libc.mmap.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_long,
        ]
        self.libc.mmap.restype = ctypes.c_void_p
        self.libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        self.libc.munmap.restype = ctypes.c_int

    def mmap(
        self,
        size: int,
        prot: int,
        flags: int,
        fd: int,
        start_addr: ctypes.c_void_p = None,
        offset: int = 0,
    ) -> ctypes.c_void_p:
        """
        Memory map a file or device.

        Args:
            size: The size of the mapping.
            prot: Desired memory protection of the mapping (e.g., PROT_READ | PROT_WRITE).
            flags: Determines the visibility of the updates to the mapping (e.g., MAP_SHARED).
            fd: File descriptor of the file or device to map.
            start_addr: The desired starting address for the mapping. If None, the kernel chooses the address.
            offset: Offset from the beginning of the file/device to start the mapping.

        Returns:
            A pointer to the mapped memory region.
        """
        addr = self.libc.mmap(start_addr, size, prot, flags, fd, offset)
        if addr == ctypes.c_void_p(-1).value:
            errno = ctypes.get_errno()
            raise OSError(errno, os.strerror(errno))
        return addr

    def munmap(self, addr: ctypes.c_void_p, size: int) -> None:
        """
        Unmap a previously mapped memory region.

        Args:
            addr: The starting address of the memory region to unmap.
            size: The size of the memory region.

        Raises:
            OSError: If munmap fails.
        """
        ret = self.libc.munmap(addr, size)
        if ret != 0:
            raise OSError("munmap failed")


class KFDDevice(MemoryManager):
    """
    Represents a Kernel Fusion Driver (KFD) device, providing a high-level interface
    for interacting with the device through IOCTL commands and memory management operations.

    Attributes:
        KFD_IOCTL (object): An object containing dynamically created IOCTL operations.
        fd (int): File descriptor for the /dev/kfd device, allowing direct communication with the device.
        node_id (int): The unique identifier for the KFD device node.

    Methods:
        close(): Closes the device file descriptor.
        ioctl(cmd, arg): Performs an IOCTL operation on the device.
        create_queue(): Creates a queue on the KFD device using specific IOCTL commands.
        allocate_memory(size): Allocates memory on the device (placeholder method).
        print_ioctl_functions(): Prints the names of all generated IOCTL functions.
    """

    # class attributes
    kfd: int = -1
    event_page: Any = (
        None
    )
    signals_page: Any = None
    signal_number: int = 16
    gpus: List[pathlib.Path] = []

    @classmethod
    def initialize_class(cls):
        if cls.kfd == -1:
            try:
                cls.kfd = os.open("/dev/kfd", os.O_RDWR | os.O_CLOEXEC)
                cls.gpus = [
                    g.parent
                    for g in pathlib.Path(
                        "/sys/devices/virtual/kfd/kfd/topology/nodes"
                    ).glob("*/gpu_id")
                    if is_usable_gpu(g)
                ]
            except Exception as e:
                cls.kfd = -1
                raise RuntimeError(
                    f"Failed to initialize KFDDevice class with error: {e}"
                ) from e

    def __init__(self, device: str):
        super().__init__()
        self.__class__.initialize_class()
        self.KFD_IOCTL = ioctls_from_header()

        try:
            self.device_id = int(device.split(":")[1]) if ":" in device else 0
            gpu_path = self.__class__.gpus[self.device_id]
            self.gpu_id = int((gpu_path / "gpu_id").read_text().strip())
            properties = (gpu_path / "properties").read_text().strip().split("\n")
            self.properties = {
                line.split()[0]: int(line.split()[1]) for line in properties
            }
            self.drm_fd = os.open(
                f"/dev/dri/renderD{self.properties['drm_render_minor']}", os.O_RDWR
            )
            target = self.properties["gfx_target_version"]
            self.arch = (
                f"gfx{target // 10000}{(target // 100) % 100:02x}{target % 100:02x}"
            )

            self.KFD_IOCTL.acquire_vm(self.kfd, drm_fd=self.drm_fd, gpu_id=self.gpu_id)

            # FLAG CONFIGS
            kfd_common_flags = kfd.KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE
                            | kfd.KFD_IOC_ALLOC_MEM_FLAGS_EXECUTABLE
                            | kfd.KFD_IOC_ALLOC_MEM_FLAGS_NO_SUBSTITUTE
                            | kfd.KFD_IOC_ALLOC_MEM_FLAGS_COHERENT
            aql_ring_flags = {
                "mmap_prot": mmap.PROT_READ | mmap.PROT_WRITE,
                "mmap_flags": mmap.MAP_SHARED | mmap.MAP_ANONYMOUS,
                "kfd_flags": kfd.KFD_IOC_ALLOC_MEM_FLAGS_GTT
                | kfd.KFD_IOC_ALLOC_MEM_FLAGS_UNCACHED
                | kfd_common_flags,
            }
            eop_buffer_flags = {
                "mmap_prot": mmap.PROT_READ | mmap.PROT_WRITE,
                "mmap_flags": mmap.MAP_SHARED | mmap.MAP_ANONYMOUS,
                "kfd_flags": kfd.KFD_IOC_ALLOC_MEM_FLAGS_GTT
                | kfd_common_flags,
            }
            sdma_ring_flags = {
                "mmap_prot": 0,
                "mmap_flags": mmap.MAP_SHARED | mmap.MAP_ANONYMOUS,
                "kfd_flags": kfd.KFD_IOC_ALLOC_MEM_FLAGS_GTT
                | kfd.KFD_IOC_ALLOC_MEM_FLAGS_UNCACHED
                | kfd_common_flags,
            }
            self.gart_aql = self._allocate_memory(0x1000, aql_ring_flags)
            self.aql_ring = self._allocate_memory(0x100000, aql_ring_flags)
            self.eop_buffer = self._allocate_memory(0x100000, eop_buffer_flags)
            self.ctx_save_restore_address = self._allocate_memory(0x100000, eop_buffer_flags)
            self.gart_sdma = self._allocate_memory(0x100000, aql_ring_flags)
            self.sdma_ring = self._allocate_memory(0x100000, sdma_ring_flags)


            # AQL Queue
            self.amd_aql_queue = hsa.amd_queue_t.from_address(self.gart_aql.va_addr)
            self.amd_aql_queue.write_dispatch_id = 0
            self.amd_aql_queue.read_dispatch_id = 0
            self.amd_aql_queue.read_dispatch_id_field_base_byte_offset = getattr(hsa.amd_queue_t, 'read_dispatch_id').offset
            self.amd_aql_queue.queue_properties = hsa.AMD_QUEUE_PROPERTIES_IS_PTR64 | hsa.AMD_QUEUE_PROPERTIES_ENABLE_PROFILING

            self.amd_aql_queue.max_cu_id = self.properties['simd_count'] // self.properties['simd_per_cu'] - 1
            self.amd_aql_queue.max_wave_id = self.properties['max_waves_per_simd'] * self.properties['simd_per_cu'] - 2

            # scratch setup
            self.max_private_segment_size = 4096
            wave_scratch_len = round_up(((self.amd_aql_queue.max_wave_id + 1) * self.max_private_segment_size), 256) # gfx11 requires alignment of 256
            self.scratch_len = (self.amd_aql_queue.max_cu_id + 1) * self.properties['max_slots_scratch_cu'] * wave_scratch_len
            self.scratch = self._allocate_memory(self.scratch_len, eop_buffer_flags)
            self.amd_aql_queue.scratch_backing_memory_location = self.scratch.va_addr
            self.amd_aql_queue.scratch_backing_memory_byte_size = self.scratch_len
            self.amd_aql_queue.scratch_wave64_lane_byte_size = self.max_private_segment_size * (self.amd_aql_queue.max_wave_id + 1) // 64
            self.amd_aql_queue.scratch_resource_descriptor[0] = self.scratch.va_addr & 0xFFFFFFFF
            self.amd_aql_queue.scratch_resource_descriptor[1] = ((self.scratch.va_addr >> 32) & 0xFFFF) | (1 << 30) # va_hi | SWIZZLE_ENABLE
            self.amd_aql_queue.scratch_resource_descriptor[2] = self.scratch_len & 0xFFFFFFFF
            self.amd_aql_queue.scratch_resource_descriptor[3] = 0x20814fac # FORMAT=BUF_FORMAT_32_UINT,OOB_SELECT=2,ADD_TID_ENABLE=1,TYPE=SQ_RSRC_BUF,SQ_SELs
            engines = self.properties['array_count'] // self.properties['simd_arrays_per_engine']
            self.amd_aql_queue.compute_tmpring_size = (wave_scratch_len // 256) << 12 | (self.scratch_len // (wave_scratch_len * engines))

            self.aql_queue = self._create_aql_queue()

            self.doorbells_base = self.aql_queue.doorbell_offset & (~0x1fff)  # doorbell is two pages
            self.doorbells = self.mmap(size=0x2000, prot=mmap.PROT_READ|mmap.PROT_WRITE, flags=mmap.MAP_SHARED, fd=self.kfd, offset=self.doorbells_base)
            self.aql_doorbell = to_mv(self.doorbells + self.aql_queue.doorbell_offset - self.doorbells_base, 4).cast("I")
            self.aql_doorbell_value = 0

            self.sdma_queue = self._create_sdma_queue()

            self.sdma_read_pointer = to_mv(self.sdma_queue.read_pointer_address, 8).cast("Q")
            self.sdma_write_pointer = to_mv(self.sdma_queue.write_pointer_address, 8).cast("Q")
            self.sdma_doorbell = to_mv(self.doorbells + self.sdma_queue.doorbell_offset - self.doorbells_base, 4).cast("I")
            self.sdma_doorbell_value = 0
            #
            # # PM4 stuff
            self.pm4_indirect_buf = self._allocate_memory(0x1000, aql_ring_flags)
            pm4_indirect_cmd = (ctypes.c_uint32*13)(amd_gpu.PACKET3(amd_gpu.PACKET3_INDIRECT_BUFFER, 2), self.pm4_indirect_buf.va_addr & 0xffffffff,
            │ │ │ │ │ │ │ │ │ │ │ │ │ │ │ │ │ │     (self.pm4_indirect_buf.va_addr>>32) & 0xffffffff, 8 | amd_gpu.INDIRECT_BUFFER_VALID, 0xa)

            ctypes.memmove(ctypes.addressof(pm4_cmds:=(ctypes.c_uint16*27)(1))+2, ctypes.addressof(pm4_indirect_cmd), ctypes.sizeof(pm4_indirect_cmd))
            self.pm4_packet = hsa.hsa_ext_amd_aql_pm4_packet_t(header=VENDOR_HEADER, pm4_command=pm4_cmds,
            │ │ │ │ │ │ │ │ │ │ │ │ │ │ │ │ │ │                completion_signal=hsa.hsa_signal_t(ctypes.addressof(self.completion_signal)))
            # super().__init__(device, KFDAllocator(self), KFDCompiler(self.arch), functools.partial(KFDProgram, self))


        except Exception as e:
            raise RuntimeError(
                f"Failed to initialize KFDDevice instance with error: {e}"
            ) from e

    def _allocate_memory(
        self, size: int, memory_flags: Dict[str, int], map_to_gpu: Optional[bool] = None
    ) -> Any:
        """
        Allocates memory on the KFD device using configuration flags for both mmap and KFD.

        Args:
            size (int): The size of the memory to allocate in bytes.
            memory_flags (Dict[str, int]): Configuration dictionary containing mmap and KFD flags.
            map_to_gpu (Optional[bool], optional): If set to True, maps the allocated memory to the GPU after allocation.

        Returns:
            The allocated memory object with optional GPU mapping.
        """

        mmap_prot = memory_flags["mmap_prot"]
        mmap_flags = memory_flags["mmap_flags"]
        kfd_flags = memory_flags["kfd_flags"]

        addr = self.mmap(size=size, prot=mmap_prot, flags=mmap_flags, fd=-1, offset=0)

        mem = self.KFD_IOCTL.alloc_memory_of_gpu(
            self.kfd,
            va_addr=addr,
            size=size,
            gpu_id=self.gpu_id,
            flags=kfd_flags,
            mmap_offset=0,
        )
        if map_to_gpu:
            self._map_memory_to_gpu(mem)
        return mem

    def _map_memory_to_gpu(self, mem: Any) -> None:
        """
        Maps memory to GPU using IOCTL commands.

        Args:
            mem: Memory object with GPU memory details.
        """
        mem.__setattr__(
            "mapped_gpu_ids", getattr(mem, "mapped_gpu_ids", []) + [self.gpu_id]
        )

        c_gpus = (ctypes.c_int32 * len(mem.mapped_gpu_ids))(*mem.mapped_gpu_ids)
        stm = self.KFD_IOCTL.map_memory_to_gpu(
            self.kfd,
            handle=mem.handle,
            device_ids_array_ptr=ctypes.addressof(c_gpus),
            n_devices=len(mem.mapped_gpu_ids),
        )
        assert stm.n_success == len(
            mem.mapped_gpu_ids
        ), "Not all GPUs were mapped successfully"

    def _create_event(self, event_page: Optional[object] = None) -> object:
        """
        Create a synchronization event for the GPU.

        Args:
            event_page (Optional[object]): The event page handle. If None, a new event page is created.

        Returns:
            object: The created synchronization event.

        Raises:
            AssertionError: If the event creation fails.
        """
        if event_page is None:
            sync_event = self.KFD_IOCTL.create_event(self.kfd, auto_reset=1)
        else:
            sync_event = self.KFD_IOCTL.create_event(self.kfd, event_page_offset=event_page.handle, auto_reset=1)
        
        assert sync_event is not None, "Failed to create event."
        return sync_event

    def _create_aql_queue(self) -> object:
        """
        Create an Asynchronous Queuing Library (AQL) queue for the GPU with specified configuration.

        This function sets up an AQL queue which is used for dispatching compute commands to the GPU.

        Returns:
            object: The created AQL queue.
        """
        aql_queue = self.KFD_IOCTL.create_queue(
            KFDDevice.kfd,
            ring_base_address=self.aql_ring.va_addr,
            ring_size=self.aql_ring.size,
            gpu_id=self.gpu_id,
            queue_type=kfd.KFD_IOC_QUEUE_TYPE_COMPUTE_AQL,
            queue_percentage=kfd.KFD_MAX_QUEUE_PERCENTAGE,
            queue_priority=kfd.KFD_MAX_QUEUE_PRIORITY,
            eop_buffer_address=self.eop_buffer.va_addr,
            eop_buffer_size=self.eop_buffer.size,
            ctx_save_restore_address=self.ctx_save_restore_address.va_addr,
            ctx_save_restore_size=self.ctx_save_restore_address.size,
            ctl_stack_size=0xa000,
            write_pointer_address=self.gart_aql.va_addr,
            read_pointer_address=self.gart_aql.va_addr + 8,
        )
        return aql_queue

    def _create_sdma_queue(self) -> object:
        """
        Create an SDMA (System Direct Memory Access) queue for the GPU with specified configuration.

        This function sets up an SDMA queue which is used for efficient data transfers between memory regions on the GPU.

        Returns:
            object: The created SDMA queue.
        """
        sdma_queue = self.KFD_IOCTL.create_queue(
            self.kfd,
            ring_base_address=self.sdma_ring.va_addr,
            ring_size=self.sdma_ring.size,
            gpu_id=self.gpu_id,
            queue_type=kfd.KFD_IOC_QUEUE_TYPE_SDMA,
            queue_percentage=kfd.KFD_MAX_QUEUE_PERCENTAGE,
            queue_priority=kfd.KFD_MAX_QUEUE_PRIORITY,
            write_pointer_address=self.gart_sdma.va_addr,
            read_pointer_address=self.gart_sdma.va_addr + 8,
        )
        return sdma_queue

    def _create_sdma_packets(self) -> type:
        """
        Create SDMA packet structures for various operations on the GPU.

        This function dynamically generates and returns a class containing SDMA packet structures,
        which can be used for constructing and submitting SDMA commands.

        Returns:
            type: A dynamically created class containing SDMA packet structures.
        """
        structs = {}
        packet_definitions = {
            name: struct
            for name, struct in amd_gpu.__dict__.items()
            if name.startswith("struct_SDMA_PKT_") and name.endswith("_TAG")
        }

        for name, pkt in packet_definitions.items():
            fields, names = [], set()

            for field_name, field_type in pkt._fields_:
                if field_name.endswith("_UNION"):
                    handle_union_field(fields, field_name, field_type, names)
                else:
                    fields.append((field_name, field_type))

            # Structure renaming for consistency and readability
            new_name = name[16:-4].lower()
            struct_type = init_c_struct_t(tuple(fields))
            structs[new_name] = struct_type

            assert_size_matches(struct_type, pkt)

        return type("SDMA_PKTS", (object,), structs)

    def free_gpu_memory(self, memory: Any) -> None:
        """
        Unmaps memory from the GPUs and frees it.

        Parameters:
        memory (Any): An object containing GPU memory information,
                               including mapped GPU IDs and memory addresses.

        Raises:
        Exception: If the number of successfully unmapped devices does not match the expected count.
        """
        try:
            # Unmap memory from GPUs if any GPUs are mapped
            gpu_ids = getattr(memory, "mapped_gpu_ids", [])
            if gpu_ids:
                # Prepare the array of device IDs for the C library call
                gpu_ids_array = (ctypes.c_int32 * len(gpu_ids))(*gpu_ids)
                result = self.KFD_IOCTL.unmap_memory_from_gpu(
                    self.kfd,
                    handle=memory.handle,
                    device_ids_array_ptr=ctypes.addressof(gpu_ids_array),
                    n_devices=len(gpu_ids),
                )

                if result.n_success != len(gpu_ids):
                    raise Exception(
                        f"Failed to unmap memory from all GPUs. Success count: {result.n_success}"
                    )

            # Unmap virtual address and free memory
            self.munmap(memory.va_addr, memory.size)
            self.KFD_IOCTL.free_memory_of_gpu(self.kfd, handle=memory.handle)

        except Exception as e:
            raise OSError(f"Error freeing GPU memeory: {e}")
