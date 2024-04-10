import mmap
import pytest
from fuzzyHSA.kfd.ops import KFDDevice


@pytest.fixture(scope="module")
def kfd_device():
    """
    Fixture to create and return a KFDDevice instance for testing,
    with automatic cleanup to close the device after tests are completed.
    """
    device = None
    try:
        device = KFDDevice("KFD:0")  # TODO: should handle multiple devices
        yield device
    finally:
        if device:
            device.close()


class TestKFDDeviceHardwareIntegration:
    def test_memory_management(self, kfd_device):
        """
        Test memory mapping and unmapping functionality with actual hardware.
        """
        mmap_size = 4096
        prot = mmap.PROT_READ | mmap.PROT_WRITE
        flags = mmap.MAP_SHARED
        fd = kfd_device.drm_fd  # TODO: Probably wrong
        offset = 0

        addr = kfd_device.mmap(mmap_size, prot, flags, fd, offset)
        assert addr is not None, "Failed to mmap memory."

        kfd_device.munmap(addr, mmap_size)

    def test_ioctl_operations(self, kfd_device):
        """
        Test IOCTL operations with actual hardware.
        """
        cmd = 0xC008BF00  # Example IOCTL command
        arg = kfd_device.prepare_ioctl_arg(cmd)

        version_struct = kfd_device.ioctl(cmd, arg)

        assert version_struct.major > 0, "Driver major version should be greater than 0"
        assert version_struct.minor >= 0, "Driver minor version should be non-negative"
        print(f"Driver Version: {version_struct.major}.{version_struct.minor}")

    def test_create_queue(self, kfd_device):
        """
        Test the functionality of creating a queue on the KFD device.
        """
        queue_id = kfd_device.create_queue()

        assert queue_id >= 0, "Queue ID should be a non-negative integer"

        queue_info = kfd_device.query_queue_info(queue_id)
        assert (
            queue_info.state == "active"
        ), "Queue should be in an 'active' state after creation"
        print(f"Queue {queue_id} created successfully with state: {queue_info.state}")


if __name__ == "__main__":
    pytest.main([__file__])
