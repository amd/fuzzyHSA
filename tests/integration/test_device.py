# SPDX-License-Identifier: Apache-2.0
"""Integration tests for KFD device operations (requires AMD GPU)."""

import os

import pytest

from fuzzyHSA.kfd import KFDDevice, discover_gpus


@pytest.mark.integration
class TestGPUDiscovery:
    def test_discover_gpus(self):
        gpus = discover_gpus()
        assert len(gpus) > 0, "No AMD GPUs found"

    def test_gpu_info_properties(self):
        gpus = discover_gpus()
        gpu = gpus[0]
        assert gpu.gpu_id > 0
        assert gpu.drm_render_minor >= 128
        assert gpu.arch.startswith("gfx")


@pytest.mark.integration
class TestKFDDevice:
    def test_open_close(self):
        device = KFDDevice(0)
        device.open()
        assert device.kfd_fd >= 0
        assert device.drm_fd >= 0
        device.close()

    def test_context_manager(self):
        with KFDDevice(0) as device:
            assert device.kfd_fd >= 0
            assert device.gpu_id > 0

    def test_properties(self):
        with KFDDevice(0) as device:
            assert device.gpu_id > 0
            assert device.arch.startswith("gfx")

    def test_invalid_device_index(self):
        with pytest.raises(RuntimeError, match="out of range"):
            KFDDevice(999)


@pytest.mark.integration
class TestKFDAvailability:
    def test_kfd_available(self):
        assert os.path.exists("/dev/kfd") and os.access("/dev/kfd", os.R_OK | os.W_OK), "/dev/kfd not accessible"
