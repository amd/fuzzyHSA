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

import ctypes
from unittest.mock import patch
import pytest

from src.fuzzyHSA.kfd.kfd_manager import KFDManager, KFDDevice
import src.fuzzyHSA.kfd.kfd as kfd

@pytest.fixture
def kfd_manager():
    return KFDManager()


@pytest.fixture
def kfd_device(kfd_manager):
    return KFDDevice(node_id=0, manager=kfd_manager)


@patch("fuzzyHSA.kfd.kfd_manager.ctypes.CDLL")
def test_memory_management(mock_cdll, kfd_manager):
    mock_cdll.return_value.mmap.return_value = ctypes.c_void_p(1234)
    mock_cdll.return_value.munmap.return_value = 0

    addr = kfd_manager.mmap(4096, 1, 1, -1)  # PROT_READ, MAP_SHARED, fd=-1 as example
    assert addr.value == 1234
    kfd_manager.munmap(addr, 4096)

    mock_cdll.return_value.mmap.assert_called_once()
    mock_cdll.return_value.munmap.assert_called_once()


@patch("fuzzyHSA.kfd.kfd_manager.fcntl.ioctl")
def test_ioctl(mock_ioctl, kfd_manager):
    mock_ioctl.return_value = 0
    cmd_struct = kfd.struct_kfd_ioctl_create_queue(
        queue_id=0
    )
    kfd_manager.ioctl(
        0, kfd.AMDKFD_IOC_CREATE_QUEUE, cmd_struct
    )
    mock_ioctl.assert_called_once()


@patch("fuzzyHSA.kfd.kfd_manager.os.open")
@patch.object(KFDManager, "ioctl")
def test_create_queue(mock_ioctl, mock_open, kfd_device):
    mock_open.return_value = 3

    kfd_device.create_queue()
    mock_ioctl.assert_called_once()
    kfd_device.close()

    mock_open.assert_called_once()
