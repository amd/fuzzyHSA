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
from posix import O_RDWR
from typing import Dict, List, Any, Optional

import fuzzyHSA.kfd.kfd as kfd  # importing generated files via the fuzzyHSA package
from .utils import ioctls_from_header, is_usable_gpu


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
        __enter__, __exit__: Enable resource management using the 'with' statement.
        close(): Closes the device file descriptor.
        ioctl(cmd, arg): Performs an IOCTL operation on the device.
        create_queue(): Creates a queue on the KFD device using specific IOCTL commands.
        allocate_memory(size): Allocates memory on the device (placeholder method).
        print_ioctl_functions(): Prints the names of all generated IOCTL functions.
    """

    # class attributes
    kfd: int = -1
    event_page: Any = (
        None  # TODO: fix types in kfd, Optional[kfd.struct_kfd_ioctl_alloc_memory_of_gpu_args]
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
        self.device_id = int(device.split(":")[1]) if ":" in device else 0
        try:
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
        except Exception as e:
            raise RuntimeError(
                f"Failed to initialize KFDDevice instance with error: {e}"
            ) from e

    def __enter__(self):
        """
        Enables the use of 'with' statement for this class, allowing for automatic
        resource management.

        Returns:
            self (KFDDevice): The instance itself.
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Ensures the device is properly closed when exiting a 'with' block.

        Args:
            exc_type: Exception type.
            exc_val: Exception value.
            exc_tb: Exception traceback.
        """
        self.close()

    def close(self):
        """Closes the device file descriptor, freeing up system resources."""
        os.close(self.__class__.kfd)

    # TODO: not sure I need this since I'm getting the actual ioctls from the headers
    def ioctl(self, cmd: int, arg: ctypes.Structure) -> ctypes.Structure:
        """
        Performs an IOCTL operation using the device's file descriptor.

        Args:
            cmd (int): The IOCTL command to execute.
            arg (ctypes.Structure): The argument structure passed to the IOCTL command.

        Returns:
            ctypes.Structure: The potentially modified argument structure after the IOCTL call.

        Raises:
            OSError: If the IOCTL operation fails.
        """
        try:
            ret = fcntl.ioctl(self.__class__.kfd, cmd, arg)
            return arg
        except IOError as e:
            raise OSError(f"IOCTL operation failed: {e}")

    def create_queue(self):
        """
        Creates a compute queue on the KFD device, utilizing ioctl commands.
        """
        # TODO: setup all the necessary instance attributes to create this queue
        # queue_args = {
        #     "ring_base_address": self.aql_ring.va_addr,
        #     "ring_size": self.aql_ring.size,
        #     "gpu_id": self.gpu_id,
        #     "queue_type": kfd.KFD_IOC_QUEUE_TYPE_COMPUTE_AQL,
        #     "queue_percentage": kfd.KFD_MAX_QUEUE_PERCENTAGE,
        #     "queue_priority": kfd.KFD_MAX_QUEUE_PRIORITY,
        #     "eop_buffer_address": self.eop_buffer.va_addr,
        #     "eop_buffer_size": self.eop_buffer.size,
        #     "ctx_save_restore_address": self.ctx_save_restore_address.va_addr,
        #     "ctx_save_restore_size": self.ctx_save_restore_address.size,
        #     "ctl_stack_size": 0xA000,
        #     "write_pointer_address": self.gart_aql.va_addr
        #     + getattr(hsa.amd_queue_t, "write_dispatch_id").offset,
        #     "read_pointer_address": self.gart_aql.va_addr
        #     + getattr(hsa.amd_queue_t, "read_dispatch_id").offset,
        # }
        # size = 0x1000
        # addr_flags = mmap.MAP_SHARED | mmap.MAP_ANONYMOUS
        #
        # addr = kfd_device.mmap(size=size, prot=0, flags=addr_flags, fd=-1, offset=0)
        #
        # flags = kfd.KFD_IOC_ALLOC_MEM_FLAGS_GTT
        # mem = kfd_device.KFD_IOCTL.alloc_memory_of_gpu(
        #     kfd_device.kfd,
        #     va_addr=addr,
        #     size=size,
        #     gpu_id=kfd_device.gpu_id,
        #     flags=flags,
        #     mmap_offset=0,
        # )
        #
        # mem.__setattr__(
        #     "mapped_gpu_ids", getattr(mem, "mapped_gpu_ids", []) + [kfd_device.gpu_id]
        # )
        # c_gpus = (ctypes.c_int32 * len(mem.mapped_gpu_ids))(*mem.mapped_gpu_ids)
        #
        # stm = kfd_device.KFD_IOCTL.map_memory_to_gpu(
        #     kfd_device.kfd,
        #     handle=mem.handle,
        #     device_ids_array_ptr=ctypes.addressof(c_gpus),
        #     n_devices=len(mem.mapped_gpu_ids),
        # )
        # assert stm.n_success == len(mem.mapped_gpu_ids)
        #
        # self.aql_queue = self.KFD_IOCTL.create_queue(KFDDevice.kfd, **queue_args)

    def allocate_memory(
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
        # TODO: should create this function first from the gpu_allocation tests that passes
        # then can use in the subsequent test that need it like create_queue
        # Still need to test this new function, just wanted to get what I was thinking down first

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

    def _map_memory_to_gpu(self, mem) -> None:
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

    def print_ioctl_functions(self):
        """
        Prints the names of all IOCTL functions generated by the ioctls_from_header function.
        """
        print("Available IOCTL Functions:")
        for func_name in dir(self.KFD_IOCTL):
            if callable(
                getattr(self.KFD_IOCTL, func_name)
            ) and not func_name.startswith("__"):
                print(f"  - {func_name}")
