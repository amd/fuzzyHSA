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
import errno
from typing import Type, Any

import kfd


def node_sysfs_path(node_id, file):
    return f"/sys/devices/virtual/kfd/kfd/topology/nodes/{node_id}/{file}"


def find_first_gpu_node():
    i = 0
    while True:
        path = pathlib.Path(node_sysfs_path(i, "gpu_id"))
        if not path.exists():
            break
        if int(path.read_text()) != 0:
            return i
        i += 1
    raise RuntimeError("No GPUs found")


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
    made = made_struct or user_struct(**kwargs)
    ret = fcntl.ioctl(
        fd, (idir << 30) | (ctypes.sizeof(made) << 16) | (ord("K") << 8) | nr, made
    )
    if ret != 0:
        raise OSError(errno.errorcode[ret], f"ioctl returned {ret}")
    return made


def ioctls_from_header() -> Any:
    """
    Dynamically create ioctl functions from header definitions in kfd.py.

    Returns:
        A dynamically created class instance with ioctl functions as methods.
    """
    pattern = r"# (AMDKFD_IOC_[A-Z0-9_]+)\s=\s_(IOW?R?).*\((0x[0-9a-fA-F]+),\s+struct\s([A-Za-z0-9_]+)\s+\)"
    matches = re.findall(pattern, pathlib.Path(kfd.__file__).read_text(), re.MULTILINE)
    idirs = {"IOW": 1, "IOR": 2, "IOWR": 3}
    fxns = {
        name.replace("AMDKFD_IOC_", "").lower(): functools.partial(
            kfd_ioctl, idirs[idir], int(nr, 16), getattr(kfd, f"struct_{sname}")
        )
        for name, idir, nr, sname in matches
    }
    return type("KIO", (object,), fxns)()
