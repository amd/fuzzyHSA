// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <assert.h>
#include <hsa/hsa.h>
#include <hsa/hsa_ext_amd.h>
#include <iostream>
#include <pybind11/pybind11.h>
#include <vector>

class HSAFuzzer {
public:
  HSAFuzzer() : queue(nullptr) {
    hsa_status_t status = hsa_init();
    assert(status == HSA_STATUS_SUCCESS &&
           "HSA runtime initialization failed.");

    status = hsa_iterate_agents(find_gpu_device, &gpu_agent);
    assert(status == HSA_STATUS_SUCCESS && "GPU device not found.");

    const uint32_t queue_size = 256;
    status = hsa_queue_create(gpu_agent, queue_size, HSA_QUEUE_TYPE_MULTI, NULL,
                              NULL, UINT32_MAX, UINT32_MAX, &queue);
    assert(status == HSA_STATUS_SUCCESS && "Queue creation failed.");
  }

  ~HSAFuzzer() {
    if (queue) {
      hsa_status_t status = hsa_queue_destroy(queue);
      assert(status == HSA_STATUS_SUCCESS && "Queue destruction failed.");
    }
    hsa_shut_down();
  }

  void allocate_memory(size_t size) {
    hsa_amd_memory_pool_t gpu_memory_pool;
    hsa_status_t status = hsa_amd_agent_iterate_memory_pools(
        gpu_agent, find_gpu_memory_pool, &gpu_memory_pool);
    assert(status == HSA_STATUS_SUCCESS && "GPU memory pool not found.");

    void *buffer = nullptr;
    status = hsa_amd_memory_pool_allocate(gpu_memory_pool, size, 0, &buffer);
    assert(status == HSA_STATUS_SUCCESS && "Memory allocation failed.");

    allocated_buffers.push_back(buffer);
  }

  void execute_kernel(const std::string &kernel_name) {
    std::cout << "Executing kernel: " << kernel_name << std::endl;
    // TODO: Load HSACO, setup kernel args, dispatch kernel, etc.
  }

private:
  static hsa_status_t find_gpu_device(hsa_agent_t agent, void *data) {
    hsa_device_type_t device_type;
    hsa_status_t status =
        hsa_agent_get_info(agent, HSA_AGENT_INFO_DEVICE, &device_type);
    if (HSA_STATUS_SUCCESS == status && HSA_DEVICE_TYPE_GPU == device_type) {
      *(reinterpret_cast<hsa_agent_t *>(data)) = agent;
      return HSA_STATUS_INFO_BREAK;
    }
    return HSA_STATUS_SUCCESS;
  }

  static hsa_status_t find_gpu_memory_pool(hsa_amd_memory_pool_t pool,
                                           void *data) {
    hsa_status_t status;
    hsa_amd_segment_t segment;
    status = hsa_amd_memory_pool_get_info(
        pool, HSA_AMD_MEMORY_POOL_INFO_SEGMENT, &segment);
    if (status == HSA_STATUS_SUCCESS && segment == HSA_AMD_SEGMENT_GLOBAL) {
      *(reinterpret_cast<hsa_amd_memory_pool_t *>(data)) = pool;
      return HSA_STATUS_INFO_BREAK;
    }
    return HSA_STATUS_SUCCESS;
  }

  hsa_agent_t gpu_agent;
  hsa_queue_t *queue;
  std::vector<void *> allocated_buffers;
};

PYBIND11_MODULE(cpp_fuzzer, m) {
  pybind11::class_<HSAFuzzer>(m, "HSAFuzzer")
      .def(pybind11::init<>())
      .def("execute_kernel", &HSAFuzzer::execute_kernel)
      .def("allocate_memory", &HSAFuzzer::allocate_memory);
}
