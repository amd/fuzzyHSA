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

#include <cstdlib>
#include <fcntl.h>
#include <hsa/hsa.h>
#include <hsa/hsa_ext_amd.h>
#include <iostream>
#include <pybind11/pybind11.h>
#include <vector>

#include "kernels.h"

#define CHECK_STATUS(err)                                                      \
  {                                                                            \
    if ((err) != HSA_STATUS_SUCCESS) {                                         \
      const char *error_string = nullptr;                                      \
      hsa_status_string(err, &error_string);                                   \
      std::cerr << "HSA API call failure at line " << __LINE__                 \
                << ", file: " << __FILE__ << ". Error: "                       \
                << (error_string ? error_string : "Unknown error")             \
                << std::endl;                                                  \
      std::abort();                                                            \
    }                                                                          \
  }

bool isDebugEnabled() {
  const char *debugEnv = std::getenv("DEBUG");
  return debugEnv && std::string(debugEnv) == "1";
}

class HSAFuzzer {
public:
  HSAFuzzer(const std::string &hsaco_file) : queue(nullptr) {
    hsa_status_t status = hsa_init();
    CHECK_STATUS(status);

    status = hsa_iterate_agents(find_gpu_device, &gpu_agent);
    CHECK_STATUS(status);

    const uint32_t queue_size = 256;
    status = hsa_queue_create(gpu_agent, queue_size, HSA_QUEUE_TYPE_MULTI, NULL,
                              NULL, UINT32_MAX, UINT32_MAX, &queue);
    CHECK_STATUS(status);

    load_hsaco(hsaco_file);
  }

  ~HSAFuzzer() {
    if (queue) {
      hsa_status_t status = hsa_queue_destroy(queue);
      CHECK_STATUS(status);
    }
    hsa_shut_down();
  }

  void allocate_memory(size_t size) {
    hsa_amd_memory_pool_t gpu_memory_pool;
    hsa_status_t status = hsa_amd_agent_iterate_memory_pools(
        gpu_agent, find_gpu_memory_pool, &gpu_memory_pool);
    CHECK_STATUS(status);

    void *buffer = nullptr;
    status = hsa_amd_memory_pool_allocate(gpu_memory_pool, size, 0, &buffer);
    CHECK_STATUS(status);

    allocated_buffers.push_back(buffer);
  }

  void execute_kernel(const std::string &kernel_name) {
    std::cout << "Executing kernel: " << kernel_name << std::endl;
    // TODO: Load HSACO, setup kernel args, dispatch kernel, etc.
  }

private:
  hsa_status_t status;
  hsa_agent_t gpu_agent = {0};
  hsa_executable_t executable = {0};
  hsa_code_object_reader_t code_obj_rdr = {0};
  hsa_queue_t *queue;
  std::vector<void *> allocated_buffers;

  static hsa_status_t find_gpu_device(hsa_agent_t agent, void *data) {
    hsa_device_type_t device_type;
    hsa_status_t status =
        hsa_agent_get_info(agent, HSA_AGENT_INFO_DEVICE, &device_type);
    if (HSA_STATUS_SUCCESS == status && HSA_DEVICE_TYPE_GPU == device_type) {
      *(reinterpret_cast<hsa_agent_t *>(data)) = agent;

      if (isDebugEnabled()) {
        char agent_name[64] = {0};
        hsa_agent_get_info(agent, HSA_AGENT_INFO_NAME, agent_name);
        std::cout << "Found GPU device: " << agent_name << std::endl;
      }

      return HSA_STATUS_INFO_BREAK;
    }
    return HSA_STATUS_SUCCESS;
  }

  static hsa_status_t find_gpu_memory_pool(hsa_amd_memory_pool_t pool,
                                           void *data) {
    hsa_amd_segment_t segment;
    hsa_status_t status = hsa_amd_memory_pool_get_info(
        pool, HSA_AMD_MEMORY_POOL_INFO_SEGMENT, &segment);
    if (status == HSA_STATUS_SUCCESS && segment == HSA_AMD_SEGMENT_GLOBAL) {
      *(reinterpret_cast<hsa_amd_memory_pool_t *>(data)) = pool;

      if (isDebugEnabled()) {
        size_t pool_size = 0;
        hsa_amd_memory_pool_get_info(pool, HSA_AMD_MEMORY_POOL_INFO_SIZE,
                                     &pool_size);
        std::cout << "Found Global Memory Pool Size: "
                  << pool_size / (1024 * 1024 * 1024) << "GB" << std::endl;
      }

      return HSA_STATUS_INFO_BREAK;
    }
    return HSA_STATUS_SUCCESS;
  }

  void load_hsaco(const std::string &hsaco_file) {
    int file_handle = open(hsaco_file.c_str(), O_RDONLY);
    if (file_handle == -1) {
      char agent_name[64] = {0};
      status = hsa_agent_get_info(gpu_agent, HSA_AGENT_INFO_NAME, agent_name);
      CHECK_STATUS(status);
      std::string fileName = "./" + std::string(agent_name) + "/" + hsaco_file;
      file_handle = open(fileName.c_str(), O_RDONLY); // Corrected reassignment
    }

    if (file_handle == -1) {
      std::cerr << "Failed to open " << hsaco_file
                << ", errno: " << std::strerror(errno) << std::endl;
    }

    status =
        hsa_code_object_reader_create_from_file(file_handle, &code_obj_rdr);
    CHECK_STATUS(status);
    close(file_handle);

    status = hsa_executable_create_alt(HSA_PROFILE_FULL,
                                       HSA_DEFAULT_FLOAT_ROUNDING_MODE_DEFAULT,
                                       NULL, &executable);
    CHECK_STATUS(status);
    status = hsa_executable_load_agent_code_object(executable, gpu_agent,
                                                   code_obj_rdr, NULL, NULL);
    CHECK_STATUS(status);
    status = hsa_executable_freeze(executable, NULL);
    CHECK_STATUS(status);
    status = hsa_code_object_reader_destroy(code_obj_rdr);
    CHECK_STATUS(status);

    hsa_executable_symbol_t kernel_symbol;
    hsa_status_t status = hsa_executable_get_symbol(
        executable, NULL, hsaco_file.c_str(), gpu_agent, 0, &kernel_symbol);
    CHECK_STATUS(status)

    if (isDebugEnabled()) {
      uint64_t kernel_object;
      uint32_t group_segment_size;
      uint32_t private_segment_size;
      uint32_t kernarg_segment_size;
      uint32_t kernarg_segment_alignment;

      status = hsa_executable_symbol_get_info(
          kernel_symbol, HSA_EXECUTABLE_SYMBOL_INFO_KERNEL_OBJECT,
          &kernel_object);
      if (status == HSA_STATUS_SUCCESS) {
        std::cout << "Kernel object handle: " << kernel_object << std::endl;
      }

      status = hsa_executable_symbol_get_info(
          kernel_symbol, HSA_EXECUTABLE_SYMBOL_INFO_KERNEL_GROUP_SEGMENT_SIZE,
          &group_segment_size);
      if (status == HSA_STATUS_SUCCESS) {
        std::cout << "Group segment size: " << group_segment_size << " bytes"
                  << std::endl;
      }

      status = hsa_executable_symbol_get_info(
          kernel_symbol, HSA_EXECUTABLE_SYMBOL_INFO_KERNEL_PRIVATE_SEGMENT_SIZE,
          &private_segment_size);
      if (status == HSA_STATUS_SUCCESS) {
        std::cout << "Private segment size: " << private_segment_size
                  << " bytes" << std::endl;
      }

      status = hsa_executable_symbol_get_info(
          kernel_symbol, HSA_EXECUTABLE_SYMBOL_INFO_KERNEL_KERNARG_SEGMENT_SIZE,
          &kernarg_segment_size);
      if (status == HSA_STATUS_SUCCESS) {
        std::cout << "Kernel argument segment size: " << kernarg_segment_size
                  << " bytes" << std::endl;
      }

      status = hsa_executable_symbol_get_info(
          kernel_symbol,
          HSA_EXECUTABLE_SYMBOL_INFO_KERNEL_KERNARG_SEGMENT_ALIGNMENT,
          &kernarg_segment_alignment);
      if (status == HSA_STATUS_SUCCESS) {
        std::cout << "Kernel argument segment alignment: "
                  << kernarg_segment_alignment << " bytes" << std::endl;
      }
    }
  }
};

PYBIND11_MODULE(fuzzer_backend, m) {
  pybind11::class_<KernelManager>(m, "KernelManager")
      .def(pybind11::init<>())
      .def("compile_kernel_to_hsaco", &KernelManager::compile_kernel_to_hsaco);
  pybind11::class_<HSAFuzzer>(m, "HSAFuzzer")
      .def(pybind11::init<const std::string &>(), pybind11::arg("hsaco_file"))
      .def("execute_kernel", &HSAFuzzer::execute_kernel)
      .def("allocate_memory", &HSAFuzzer::allocate_memory);
}
