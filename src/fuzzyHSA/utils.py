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

from pathlib import Path
import importlib.util

def check_generated_files():
    package_path = Path(importlib.util.find_spec('fuzzyHSA').origin).parent
    kfd_file_path = package_path / 'kfd' / 'kfd.py'
    if not kfd_file_path.exists():
        raise RuntimeError("kfd.py not found. Please run autogen_stub.sh to generate it.")

def create_cache_directory():
    cache_dir = Path.home() / '.cache' / 'fuzzyHSA'
    cache_dir.mkdir(parents=True, exist_ok=True)
