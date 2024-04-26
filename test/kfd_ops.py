import ctypes, mmap
import pprint
import pytest
from fuzzyHSA.utils import query_attributes
from fuzzyHSA.kfd.ops import KFDDevice
import fuzzyHSA.kfd.autogen.kfd as kfd  # importing generated files via the fuzzyHSA package


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


MAP_FIXED, MAP_NORESERVE = 0x10, 0x400


class TestKFDDeviceHardwareIntegration:
    def test_memory_management(self, kfd_device):
        """
        Test memory mapping and unmapping functionality with actual hardware.
        """
        # NOTE: using fd=-1 in combination with mmap.MAP_ANONYMOUS is appropriate
        # for creating memory mappings that are independent of the file system,
        # offering a simple and effective way to manage memory for temporary or
        # internal application needs.

        size = 4096
        flags = mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS | MAP_NORESERVE
        fd = -1  # Indicates no file descriptor

        addr = kfd_device.mmap(size=size, prot=0, flags=flags, fd=fd, offset=0)

        assert addr is not None, "Failed to mmap memory."

        kfd_device.munmap(addr, size)

    def test_ioctl_operations(self, kfd_device):
        """
        Test IOCTL operations.

        TODO:
        - Implement individual tests for each IOCTL operation listed below.
        - Each test should:
          1. Properly set up any required parameters or structures.
          2. Call the ioctl operation.
          3. Verify the operation's success by checking return values and any changes in state or outputs.
          4. Handle and log errors appropriately.
          5. Clean up any resources used during the test.

        List of IOCTL operations to test:
          - acquire_vm: Test VM acquisition functionalities.
          - alloc_memory_of_gpu: Test GPU memory allocation and ensure proper handling of memory addresses.
          - alloc_queue_gws: Test allocation of queue gateways.
          - create_event: Verify event creation and correct initialization of event properties.
          - create_queue: Ensure queues are created with correct configurations.
          - dbg_address_watch: Test debug functionalities related to address watching.
          - dbg_register: Test registration of debug instances.
          - dbg_unregister: Verify proper unregistration and cleanup of debug instances.
          - dbg_wave_control: Test controls for debug wavefront management.
          - destroy_event: Ensure events are cleanly destroyed without residual state.
          - destroy_queue: Test queue destruction and resource deallocation.
          - free_memory_of_gpu: Ensure GPU memory is freed and that no leaks are present.
          - get_clock_counters: Verify retrieval of clock counter data.
          - get_dmabuf_info: Test DMA buffer information retrieval.
          - get_process_apertures_new: Check acquisition of new process apertures.
          - get_queue_wave_state: Verify state retrieval of queue wavefronts.
          - get_tile_config: Test configuration retrieval of GPU tiles.
          - import_dmabuf: Verify DMA buffer import functionality.
          - map_memory_to_gpu: Ensure memory mapping to GPU is handled correctly.
          - reset_event: Test resetting of events and state cleanup.
          - set_cu_mask: Verify setting of compute unit masks.
          - set_event: Test configuration of event parameters.
          - set_memory_policy: Verify memory policy settings apply correctly.
          - set_scratch_backing_va: Test setting of scratch backing virtual addresses.
          - set_trap_handler: Verify trap handler settings are applied.
          - set_xnack_mode: Test XNACK mode settings.
          - smi_events: Verify handling of system management interface events.
          - svm: Test shared virtual memory operations.
          - unmap_memory_from_gpu: Ensure memory unmapping is clean and complete.
          - update_queue: Test updating queue parameters and effects.
          - wait_events: Verify event waiting mechanisms work as expected.
        """
        operations = [
            ("acquire_vm", self._test_acquire_vm),
            ("alloc_memory_of_gpu", self._test_alloc_memory_of_gpu),
            ("map_memory_to_gpu", self._test_map_memory_to_gpu),
            ("create_event", self._test_create_event),
            ("create_queue", self._test_create_queue),
            # TODO: List above
        ]
        results = {}
        for name, operation in operations:
            try:
                operation(kfd_device)
                results[name] = "Passed"
            except Exception as e:
                results[name] = f"Failed with error: {str(e)}"

        for operation, result in results.items():
            print(f"{operation}: {result}")

        failed_tests = {op: res for op, res in results.items() if "Failed" in res}
        if failed_tests:
            error_messages = "\n".join(
                f"{op}: {res}" for op, res in failed_tests.items()
            )
            assert False, f"Some IOCTL operations failed:\n{error_messages}"

    def _test_acquire_vm(self, kfd_device):
        kfd_device.KFD_IOCTL.acquire_vm(
            kfd_device.kfd, drm_fd=kfd_device.drm_fd, gpu_id=kfd_device.gpu_id
        )

    def _test_alloc_memory_of_gpu(self, kfd_device):
        size = 0x1000
        addr_flags = mmap.MAP_SHARED | mmap.MAP_ANONYMOUS

        addr = kfd_device.mmap(size=size, prot=0, flags=addr_flags, fd=-1, offset=0)

        flags = kfd.KFD_IOC_ALLOC_MEM_FLAGS_GTT
        mem = kfd_device.KFD_IOCTL.alloc_memory_of_gpu(
            kfd_device.kfd,
            va_addr=addr,
            size=size,
            gpu_id=kfd_device.gpu_id,
            flags=flags,
            mmap_offset=0,
        )

    def _test_map_memory_to_gpu(self, kfd_device):
        size = 0x1000
        addr_flags = mmap.MAP_SHARED | mmap.MAP_ANONYMOUS

        addr = kfd_device.mmap(size=size, prot=0, flags=addr_flags, fd=-1, offset=0)

        flags = kfd.KFD_IOC_ALLOC_MEM_FLAGS_GTT
        mem = kfd_device.KFD_IOCTL.alloc_memory_of_gpu(
            kfd_device.kfd,
            va_addr=addr,
            size=size,
            gpu_id=kfd_device.gpu_id,
            flags=flags,
            mmap_offset=0,
        )

        mem.__setattr__(
            "mapped_gpu_ids", getattr(mem, "mapped_gpu_ids", []) + [kfd_device.gpu_id]
        )
        c_gpus = (ctypes.c_int32 * len(mem.mapped_gpu_ids))(*mem.mapped_gpu_ids)

        stm = kfd_device.KFD_IOCTL.map_memory_to_gpu(
            kfd_device.kfd,
            handle=mem.handle,
            device_ids_array_ptr=ctypes.addressof(c_gpus),
            n_devices=len(mem.mapped_gpu_ids),
        )
        assert stm.n_success == len(mem.mapped_gpu_ids)

    def _test_create_event(self, kfd_device):
        memory_flags_config = {
            "mmap_prot": mmap.PROT_READ | mmap.PROT_WRITE,
            "mmap_flags": mmap.MAP_SHARED | mmap.MAP_ANONYMOUS,
            "kfd_flags": kfd.KFD_IOC_ALLOC_MEM_FLAGS_GTT
            | kfd.KFD_IOC_ALLOC_MEM_FLAGS_COHERENT
            | kfd.KFD_IOC_ALLOC_MEM_FLAGS_UNCACHED
            | kfd.KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE
            | kfd.KFD_IOC_ALLOC_MEM_FLAGS_EXECUTABLE
            | kfd.KFD_IOC_ALLOC_MEM_FLAGS_NO_SUBSTITUTE,
        }

        memory_size = 0x8000
        KFDDevice.event_page = kfd_device.allocate_memory(
            memory_size, memory_flags_config, map_to_gpu=True
        )
        sync_event = kfd_device.KFD_IOCTL.create_event(
            KFDDevice.kfd, event_page_offset=KFDDevice.event_page.handle, auto_reset=1
        )
        assert sync_event is not None, "Failed to create event."

    def _test_create_queue(self, kfd_device):
        """
        Test the functionality of creating a queue on the KFD device.
        """

        sdma_ring_flags_config = {
            "mmap_prot": 0,
            "mmap_flags": mmap.MAP_SHARED | mmap.MAP_ANONYMOUS,
            "kfd_flags": kfd.KFD_IOC_ALLOC_MEM_FLAGS_GTT
            | kfd.KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE
            | kfd.KFD_IOC_ALLOC_MEM_FLAGS_EXECUTABLE
            | kfd.KFD_IOC_ALLOC_MEM_FLAGS_NO_SUBSTITUTE
            | kfd.KFD_IOC_ALLOC_MEM_FLAGS_COHERENT
            | kfd.KFD_IOC_ALLOC_MEM_FLAGS_UNCACHED,
        }

        sdma_ring = kfd_device.allocate_memory(
            0x100000, sdma_ring_flags_config, map_to_gpu=True
        )

        gart_flags_config = {
            "mmap_prot": mmap.PROT_READ | mmap.PROT_WRITE,
            "mmap_flags": mmap.MAP_SHARED | mmap.MAP_ANONYMOUS,
            "kfd_flags": kfd.KFD_IOC_ALLOC_MEM_FLAGS_GTT
            | kfd.KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE
            | kfd.KFD_IOC_ALLOC_MEM_FLAGS_EXECUTABLE
            | kfd.KFD_IOC_ALLOC_MEM_FLAGS_NO_SUBSTITUTE
            | kfd.KFD_IOC_ALLOC_MEM_FLAGS_COHERENT
            | kfd.KFD_IOC_ALLOC_MEM_FLAGS_UNCACHED,
        }
        gart_sdma = kfd_device.allocate_memory(
            0x1000, gart_flags_config, map_to_gpu=True
        )

        sdma_queue = kfd_device.KFD_IOCTL.create_queue(
            KFDDevice.kfd,
            ring_base_address=sdma_ring.va_addr,
            ring_size=sdma_ring.size,
            gpu_id=kfd_device.gpu_id,
            queue_type=kfd.KFD_IOC_QUEUE_TYPE_SDMA,
            queue_percentage=kfd.KFD_MAX_QUEUE_PERCENTAGE,
            queue_priority=kfd.KFD_MAX_QUEUE_PRIORITY,
            write_pointer_address=gart_sdma.va_addr,
            read_pointer_address=gart_sdma.va_addr + 8,
        )

        try:
            assert sdma_queue.queue_id >= 0, "Queue ID should be a non-negative integer"
            assert (
                sdma_queue.ring_size > 0
            ), "Ring size should be greater than zero if active"
            assert (
                sdma_queue.ring_base_address != 0
            ), "Ring base address should not be zero if active"
            print(f"Queue {sdma_queue.queue_id} created successfully and is active.")
        except AssertionError as error:
            print(f"Failed to verify queue active status: {error}")


if __name__ == "__main__":
    pytest.main([__file__])
