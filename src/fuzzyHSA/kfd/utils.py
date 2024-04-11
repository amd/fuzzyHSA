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

import ctypes
import pathlib
import re
import functools
import fcntl
import os
from typing import Type, Any

import fuzzyHSA.kfd.kfd as kfd  # importing generated files via the fuzzyHSA package


def is_usable_gpu(gpu_id):
    try:
        with gpu_id.open() as f:
            return int(f.read()) != 0
    except OSError:
        return False


def kfd_ioctl(
    idir: int,
    nr: int,
    user_struct: Type[ctypes.Structure],
    fd: int,
    made_struct: ctypes.Structure = None,
    **kwargs,
) -> ctypes.Structure:
    """
    Execute an ioctl command on a KFD device.

    Args:
        idir: The direction of data transfer.
        nr: The number associated with the ioctl command.
        user_struct: The structure type for the ioctl command.
        fd: The file descriptor of the KFD device.
        made_struct: An instance of the structure to be used (optional).
        **kwargs: Additional arguments to initialize `user_struct` if `made_struct` is not provided.

    Returns:
        The structure filled with the results of the ioctl call.
    """
    # TODO: ADD if DEBUG env flag here to print this
    # print(f"Debug Info - FD: {fd}, IDIR: {idir}, NR: {nr}, GPU ID: {kwargs.get('gpu_id')}, Size: {kwargs.get('size')}")
    made = made_struct or user_struct(**kwargs)
    if fd < 0 or os.fstat(fd).st_nlink == 0:
        raise ValueError("Invalid or closed file descriptor")
    try:
        ret = fcntl.ioctl(
            fd, (idir << 30) | (ctypes.sizeof(made) << 16) | (ord("K") << 8) | nr, made
        )
    except OSError as e:
        raise RuntimeError(
            f"IOCTL operation failed with system error: {os.strerror(e.errno)}"
        ) from e
    return made


def ioctls_from_header() -> Any:
    """
    Dynamically create ioctl functions from header definitions in kfd.py.

    Returns:
        A dynamically created class instance with ioctl functions as methods.
    """
    pattern = r"# (AMDKFD_IOC_[A-Z0-9_]+) = (_IOWR?)\('K',\s*nr,\s*type\) \(\s*(0x[0-9a-fA-F]+)\s*,\s*struct\s+([A-Za-z0-9_]+)\s*\) # macro"
    matches = re.findall(pattern, pathlib.Path(kfd.__file__).read_text(), re.MULTILINE)
    idirs = {"_IOW": 1, "_IOR": 2, "_IOWR": 3}
    fxns = {
        name.replace("AMDKFD_IOC_", "").lower(): functools.partial(
            kfd_ioctl, idirs[idir], int(nr, 16), getattr(kfd, f"struct_{sname}")
        )
        for name, idir, nr, sname in matches
    }
    return type("KFD_IOCTL", (object,), fxns)()
