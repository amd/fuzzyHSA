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
import ctypes
import fcntl
import errno

import fuzzyHSA.kfd.kfd as kfd  # importing generated files via the fuzzyHSA package
from .utils import node_sysfs_path  # Ensure this utility is properly defined elsewhere


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


class KFDManager(MemoryManager):
    """
    A class for managing KFD devices, including IOCTL operations and memory mapping.
    Inherits memory mapping functionality from MemoryManager.
    """

    @staticmethod
    def ioctl(fd: int, cmd: int, arg: ctypes.Structure) -> ctypes.Structure:
        """
        Perform an ioctl operation.

        Args:
            fd: File descriptor of the device.
            cmd: Ioctl command code.
            arg: Argument structure for the command.

        Returns:
            The argument structure filled with any output data.
        """
        ret = fcntl.ioctl(fd, cmd, arg)
        if ret != 0:
            raise OSError(errno.errorcode[ret], os.strerror(ret))
        return arg


class KFDDevice:
    def __init__(self, node_id: int, manager: KFDManager):
        """
        Initialize the KFD device.

        Args:
            node_id: The node ID for the KFD device.
            manager: An instance of KFDManager for handling IOCTL and memory management.
        """
        self.fd = os.open("/dev/kfd", os.O_RDWR | os.O_CLOEXEC)
        self.node_id = node_id
        self.manager = manager  # Store the KFDManager instance

    def close(self) -> None:
        """Close the device file descriptor."""
        os.close(self.fd)

    def create_queue(self) -> None:
        """
        Create a queue on the KFD device.

        This method needs to be adapted based on actual IOCTL commands and their expected parameters.
        """
        # Create the structure for the IOCTL command
        cmd = kfd.struct_kfd_ioctl_create_queue(queue_id=self.node_id)

        # Use the manager to submit the IOCTL command
        self.manager.ioctl(self.fd, kfd.AMDKFD_IOC_CREATE_QUEUE, cmd)

    def submit_command(self, cmd: ctypes.Structure) -> None:
        """
        Submit an arbitrary IOCTL command.

        Args:
            cmd: The IOCTL command structure.
        """
        # Use the manager to submit the IOCTL command
        self.manager.ioctl(self.fd, 0xC008BF00, cmd)  # Placeholder IOCTL command
