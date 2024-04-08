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
from unittest.mock import patch, MagicMock
import pytest

from fuzzyHSA.kfd.ops import KFDDevice


@pytest.fixture
def kfd_device():
    with patch("fuzzyHSA.kfd.kfd_device.os.open", return_value=3) as mock_open:
        device = KFDDevice(node_id=0)
    return device


@patch("fuzzyHSA.kfd.kfd_device.ctypes.CDLL")
def test_memory_management(mock_cdll, kfd_device):
    # Setup mock return values for mmap and munmap
    mock_cdll.return_value.mmap.return_value = ctypes.c_void_p(1234)
    mock_cdll.return_value.munmap.return_value = 0

    # Testing mmap
    addr = kfd_device.mmap(
        4096, ctypes.PROT_READ | ctypes.PROT_WRITE, ctypes.MAP_SHARED, -1, 0
    )
    assert addr.value == 1234, "Memory mapping should return the expected address."
    mock_cdll.return_value.mmap.assert_called_once_with(
        None, 4096, ctypes.PROT_READ | ctypes.PROT_WRITE, ctypes.MAP_SHARED, -1, 0
    )

    # Testing munmap
    kfd_device.munmap(addr, 4096)
    mock_cdll.return_value.munmap.assert_called_once_with(ctypes.c_void_p(1234), 4096)


@patch("fuzzyHSA.kfd.kfd_device.fcntl.ioctl", autospec=True)
def test_ioctl(mock_ioctl, kfd_device):
    mock_ioctl.return_value = 0  # Simulate successful ioctl call

    # Example: Simulate an ioctl call to create a queue, using placeholder values
    cmd = 0xC008BF00  # Placeholder for an actual IOCTL command
    arg = ctypes.c_int(0)  # Placeholder argument structure

    kfd_device.ioctl(cmd, arg)
    mock_ioctl.assert_called_once_with(kfd_device.fd, cmd, arg)


# Assuming KFDDevice has a create_queue method using ioctl internally
@patch("fuzzyHSA.kfd.kfd_device.KFDDevice.ioctl", autospec=True)
def test_create_queue(mock_ioctl, kfd_device):
    # Setup the mock for ioctl to simulate a successful queue creation
    mock_ioctl.return_value = MagicMock()

    # Perform the operation
    kfd_device.create_queue()
    # Validate the ioctl was called appropriately within create_queue
    assert mock_ioctl.called, "ioctl should be called to create a queue."

    # Cleanup: Close the device explicitly if not using context management
    kfd_device.close()
