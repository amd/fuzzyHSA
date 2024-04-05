
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

#!/usr/bin/env python3

import os
import fcntl
import ctypes
import mmap
import time
import pathlib
import re
import kfd

# TODO: setup kfd operations here.

# Helper function for memory views
def to_mv(ptr, sz) -> memoryview:
    return memoryview(ctypes.cast(ptr, ctypes.POINTER(ctypes.c_uint8 * sz)).contents).cast("B")

# Initialize libc and set argument and return types for mmap and munmap
libc = ctypes.CDLL("libc.so.6")
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
libc.mmap.restype = ctypes.c_void_p
libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc.munmap.restype = ctypes.c_int

# Extract IOCTLs from header
def ioctls_from_header():
    hdr = pathlib.Path("/usr/include/linux/kfd_ioctl.h").read_text().replace("\\\n", "")
    pattern = r'#define\s+(AMDKFD_IOC_[A-Z0-9_]+)\s+AMDKFD_(IOW?R?)\((0x[0-9a-fA-F]+),\s+struct\s([A-Za-z0-9_]+)\)'
    matches = re.findall(pattern, hdr, re.MULTILINE)
    return type("KIO", (object,), {name: (getattr(kfd, "struct_" + sname), int(nr, 0x10), {"IOW": 1, "IOR": 2, "IOWR": 3}[idir]) for name, idir, nr, sname in matches})

# Function to perform IOCTL operations
def kfd_ioctl(tt, st):
    ret = fcntl.ioctl(fd, ioctl_nr(tt[2], ctypes.sizeof(st), ord('K'), tt[1]), st)
    assert ret == 0

# Main execution logic
if __name__ == "__main__":
    kio = ioctls_from_header()
    fd = os.open("/dev/kfd", os.O_RDWR)
    drm_fd = os.open("/dev/dri/renderD128", os.O_RDWR)

    # Example usage of IOCTLs
    st = kio.AMDKFD_IOC_GET_VERSION[0]()
    kfd_ioctl(kio.AMDKFD_IOC_GET_VERSION, st)

    # Allocate GPU memory and map it
    MAP_NORESERVE = 0x4000
    buf_addr = libc.mmap(0, 0x1000, mmap.PROT_READ | mmap.PROT_WRITE, mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, -1, 0)
    assert buf_addr != -1, "mmap failed"

    st = kio.AMDKFD_IOC_ALLOC_MEMORY_OF_GPU[0]()
    st.va_addr = buf_addr
    st.size = 0x1000
    st.gpu_id = 0xBFE4  # Example GPU ID
    st.flags = 0xD6000002
    kfd_ioctl(kio.AMDKFD_IOC_ALLOC_MEMORY_OF_GPU, st)

    # Example operation on allocated memory
    mv = to_mv(buf_addr, 0x1000)
    mv[0] = 101  # Example write operation
    print(f"First byte: {mv[0]}")

    time.sleep(2)
