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

#pragma once

#include <pybind11/pybind11.h>
#include <fstream>
#include <cstdlib>
#include <unordered_map>
#include <string>
#include <filesystem>

const char* vector_add_kernel_code = R"(
    #include <hip/hip_runtime.h>
    extern "C" __global__ void vector_add(const float* a, const float* b, float* c, int N) {
        int i = hipBlockIdx_x * hipBlockDim_x + hipThreadIdx_x;
        if (i < N) {
            c[i] = a[i] + b[i];
        }
    }
)";

const char* vector_mul_kernel_code = R"(
    #include <hip/hip_runtime.h>
    extern "C" __global__ void vector_mul(const float* a, const float* b, float* c, int N) {
        int i = hipBlockIdx_x * hipBlockDim_x + hipThreadIdx_x;
        if (i < N) {
            c[i] = a[i] * b[i];
        }
    }
)";

class KernelManager {
public:
    void compile_kernel_to_hsaco(const std::string& kernel_name) {
        std::unordered_map<std::string, std::string> kernel_map = {
            {"vector_add", vector_add_kernel_code},
            {"vector_mul", vector_mul_kernel_code}
        };

        if (kernel_map.find(kernel_name) == kernel_map.end()) {
            throw std::runtime_error("Kernel not found");
        }

        std::ofstream tmp_file("tmp_kernel.cpp");
        tmp_file << kernel_map[kernel_name];
        tmp_file.close();

        std::string home_dir = std::getenv("HOME");
        std::filesystem::path cache_dir = std::filesystem::path(home_dir) / ".cache" / "fuzzyHSA";
        std::filesystem::path hsaco_output_path = cache_dir / (kernel_name + ".hsaco");

        std::string command = "hipcc --genco tmp_kernel.cpp -o " + hsaco_output_path.string();
        int result = std::system(command.c_str());
        if (result != 0) {
            throw std::runtime_error("Kernel compilation failed");
        }

        std::remove("tmp_kernel.cpp");
    }
};
