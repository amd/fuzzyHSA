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
from typing import Dict, Any, List
import inspect
import importlib.util


# TODO: need to have this check for general "filename"
def check_generated_files(filenames: List[str]) -> None:
    """
    Checks if the specified autogenerated files exist in the specified package directory.

    Args:
    filenames (List[str]): List of filenames to check under the 'autogen' subdirectory.

    Raises:
    RuntimeError: If any specified file does not exist.
    """
    package_path = Path(importlib.util.find_spec("fuzzyHSA").origin).parent
    autogen_path = package_path / "kfd" / "autogen"

    for filename in filenames:
        file_path = autogen_path / filename
        if not file_path.exists():
            raise RuntimeError(
                f"{filename} not found. Please run autogen_stub.sh to generate it."
            )


def create_cache_directory():
    cache_dir = Path.home() / ".cache" / "fuzzyHSA"
    cache_dir.mkdir(parents=True, exist_ok=True)


def query_attributes(obj: Any) -> Dict[str, Any]:
    """
    Retrieves all attributes of an object with their current values.

    Args:
    obj (Any): The object to inspect.

    Returns:
    Dict[str, Any]: A dictionary containing attribute names and their values.
    """
    members_dict = {
        name: value for name, value in inspect.getmembers(obj) if not callable(value)
    }
    return members_dict

def read_file(path: Path) -> int:
    """
    Helper method to read a single value from a file and convert it to an integer.
    """
    with open(path, "r") as file:
        return int(file.read().strip())

def read_properties(path: Path) -> dict:
    """
    Helper method to read properties from a file and convert them into a dictionary.
    Each line in the file is expected to have a key and a value separated by whitespace.
    """
    with open(path, "r") as file:
        return {line.split()[0]: int(line.split()[1]) for line in file}
