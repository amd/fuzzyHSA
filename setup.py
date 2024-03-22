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

import os
from setuptools import setup, Extension
import pybind11

os.environ["CC"] = "hipcc"

fuzzer_backend = Extension(
    "fuzzer_backend",
    sources=["src/cpp/HSAFuzzer.cpp"],
    include_dirs=[
        pybind11.get_include(),
        "/opt/rocm/include",
    ],
    language="c++",
    extra_compile_args=["-std=c++17"],
    libraries=["hsa-runtime64"],
    library_dirs=["/opt/rocm/lib"],
    extra_link_args=["-Wl,-rpath,/opt/rocm/lib"],
)

setup(
    name="fuzzyHSA",
    version="0.1.0",
    author="Zachary Streeter",
    description="A Python HSA Fuzzer",
    ext_modules=[fuzzer_backend],
    setup_requires=["pybind11>=2.5.0"],
)
