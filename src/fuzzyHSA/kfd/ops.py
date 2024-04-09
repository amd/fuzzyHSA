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
import inspect

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

    def __init__(self, node_id: int):
        """
        Initializes a new KFDDevice instance.

        Args:
            node_id (int): The node ID for the KFD device. This ID is used to identify
                           the device within the system.
        """
        super().__init__()
        self.KFD_IOCTL = ioctls_from_header()  # Load IOCTL commands dynamically
        print(self.KFD_IOCTL)
        self.fd = os.open("/dev/kfd", os.O_RDWR | os.O_CLOEXEC)
        self.node_id = node_id

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
        os.close(self.fd)

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
            ret = fcntl.ioctl(self.fd, cmd, arg)
            return arg
        except IOError as e:
            raise OSError(f"IOCTL operation failed: {e}")

    def create_queue(self):
        """
        Creates a compute queue on the KFD device, utilizing IOCTL commands.

        This method prepares and sends the necessary command structure to the device
        to initialize a new compute queue. Details such as queue type and properties
        are determined internally.

        Raises:
            OSError: If the IOCTL operation to create the queue fails.
        """
        # This assumes the existence of a create_queue method within the KFD_IOCTL object
        # and may need adjustment based on actual implementation.
        cmd = self.KFD_IOCTL.create_queue(
            self.node_id
        )  # Placeholder for command structure preparation
        self.ioctl(self.KFD_IOCTL.AMDKFD_IOC_CREATE_QUEUE, cmd)

    def allocate_memory(self, size: int):
        """
        Allocates memory on the KFD device. Placeholder for demonstration.

        Args:
            size (int): The size of the memory to allocate in bytes.

        Returns:
            A reference or pointer to the allocated memory. Actual return type and mechanism
            depend on the implementation of memory management within the device context.
        """
        # TODO:
        pass

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
