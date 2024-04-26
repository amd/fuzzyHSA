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
        # TODO: continue main execution here
    except RuntimeError as e:
        print(f"Startup Error: {e}")
        return


if __name__ == "__main__":
    main()
