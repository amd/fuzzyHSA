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

import ctypes, mmap
from unittest.mock import patch, mock_open, MagicMock
import pytest

from fuzzyHSA.kfd.ops import KFDDevice


# @pytest.fixture
# def kfd_device():
#     with patch("fuzzyHSA.kfd.ops.os.open", return_value=3) as mock_open:
#         device = KFDDevice(node_id=0)
#     return device
#
@pytest.fixture
def kfd_device():
    # Mock os.open to prevent actual file operations
    with patch("fuzzyHSA.kfd.ops.os.open", return_value=3), patch(
        "pathlib.Path.open", mock_open(read_data="1")
    ), patch("fuzzyHSA.kfd.ops.KFDDevice.initialize_class") as mock_init_class:
        device_str = "KFD:0"
        device = KFDDevice(device_str)
    return device


@patch("fuzzyHSA.kfd.ops.KFDDevice.mmap")
@patch("fuzzyHSA.kfd.ops.KFDDevice.munmap")
def test_memory_management(mock_munmap, mock_mmap, kfd_device):
    # Setup mock return values for mmap and munmap
    mock_mmap.return_value = ctypes.c_void_p(1234)  # Simulate successful mmap
    mock_munmap.return_value = 0  # Simulate successful munmap

    # Testing mmap
    addr = kfd_device.mmap(
        4096, mmap.PROT_READ | mmap.PROT_WRITE, mmap.MAP_SHARED, -1, 0
    )
    assert addr.value == 1234, "Memory mapping should return the expected address."
    mock_mmap.assert_called_once_with(
        4096, mmap.PROT_READ | mmap.PROT_WRITE, mmap.MAP_SHARED, -1, 0
    )

    # Testing munmap
    kfd_device.munmap(addr, 4096)
    mock_munmap.assert_called_once_with(addr, 4096)


@patch("fuzzyHSA.kfd.ops.fcntl.ioctl", autospec=True)
def test_ioctl(mock_ioctl, kfd_device):
    mock_ioctl.return_value = 0  # Simulate successful ioctl call

    cmd = 0xC008BF00  # Placeholder for an actual IOCTL command
    arg = ctypes.c_int(0)  # Placeholder argument structure

    kfd_device.ioctl(cmd, arg)
    mock_ioctl.assert_called_once_with(kfd_device.fd, cmd, arg)


# TODO: This fails and I think it's because I'm trying to do a real ioctl with a mock device. Need to create another unit test script that doesn't use mock
@patch("fuzzyHSA.kfd.ops.KFDDevice.ioctl", autospec=True)
def test_create_queue(mock_ioctl, kfd_device):
    mock_ioctl.return_value = MagicMock()

    kfd_device.create_queue()
    assert mock_ioctl.called, "ioctl should be called to create a queue."

    kfd_device.close()
