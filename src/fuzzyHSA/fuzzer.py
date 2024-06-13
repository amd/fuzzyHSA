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

from .utils import check_generated_files
from fuzzyHSA.kfd.ops import KFDDevice

REQUIRED_FILES = ["kfd.py", "hsa.py", "amd_gpu.py"]


def main():
    try:
        check_generated_files(REQUIRED_FILES)
        print("All required files are present. Continuing with main execution.")
        device = KFDDevice("HSA")
    except RuntimeError as e:
        print(f"Startup Error: {e}")
        return


if __name__ == "__main__":
    main()

# Example of API
# # Initialize device
# device = GPUDevice()
#
# # Allocate memory
# mem = GPUMemory(device, size=1024, host_accessible=True)
#
# # Copy data to GPU
# data = memoryview(bytearray(b"some_data"))
# mem.copy_from_host(data)
#
# # Compile and load program
# source_code = """
# __global__ void my_kernel(float *a) {
#     int idx = blockIdx.x * blockDim.x + threadIdx.x;
#     a[idx] = a[idx] * 2.0;
# }
# """
# program = GPUProgram(device, source_code, "my_kernel")
#
# # Create queues
# cp_queue = CommandProcessorQueue(device)
# sdma_queue = SDMAQueue(device)
#
# # Execute program
# cp_queue.execute(program, mem.memory, global_size=(64, 1, 1), local_size=(64, 1, 1))
#
# # Copy data back to host
# result = memoryview(bytearray(1024))
# mem.copy_to_host(result)
#
# # Free memory
# mem.free()
#
# # Synchronize device
# device.synchronize()
#
