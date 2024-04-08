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
import ctypes

from .utils import ioctls_from_header


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
        self, size: int, prot: int, flags: int, fd: int, offset: int = 0
    ) -> ctypes.c_void_p:
        """
        Memory map a file or device.

        Args:
            size: The size of the mapping.
            prot: Desired memory protection of the mapping (e.g., PROT_READ | PROT_WRITE).
            flags: Determines the visibility of the updates to the mapping (e.g., MAP_SHARED).
            fd: File descriptor of the file or device to map.
            offset: Offset from the beginning of the file/device to start the mapping.

        Returns:
            A pointer to the mapped memory region.
        """
        addr = self.libc.mmap(None, size, prot, flags, fd, offset)
        if addr == ctypes.c_void_p(-1).value:
            raise OSError("mmap failed")
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
    def __init__(self, node_id: int):
        super().__init__()  # Initialize MemoryManager, if it has an __init__
        self.kfd_ops = ioctls_from_header()  # Dynamically create ioctl operations
        self.fd = os.open("/dev/kfd", os.O_RDWR | os.O_CLOEXEC)
        self.node_id = node_id

    def __enter__(self):
        """Enable use of 'with' statement for automatic resource management."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Ensure the device is closed when exiting a 'with' block."""
        self.close()

    def close(self):
        """Close the device file descriptor."""
        os.close(self.fd)

    def ioctl(self, cmd: int, arg: ctypes.Structure) -> ctypes.Structure:
        """
        Perform an ioctl operation, wrapping the static method functionality.
        Automatically uses the device's file descriptor.
        """
        try:
            ret = fcntl.ioctl(self.fd, cmd, arg)
            return arg
        except IOError as e:
            raise OSError(f"IOCTL operation failed: {e}")

    def create_queue(self):
        """
        Create a queue on the KFD device using IOCTL commands.
        """
        # Example assumes existence of a method to properly set up the command structure
        cmd = self.kfd_ops.create_queue_struct(self.node_id)  # Hypothetical method
        self.ioctl(self.kfd_ops.AMDKFD_IOC_CREATE_QUEUE, cmd)

    # Example: Method to allocate memory, assuming such functionality is common
    def allocate_memory(self, size: int):
        """Allocate memory on the device."""
        # This is a placeholder. Implementation depends on your MemoryManager and KFD specifics.
        pass
