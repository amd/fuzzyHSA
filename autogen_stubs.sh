#!/usr/bin/env bash

set -euo pipefail
trap "echo 'Error: Script failed.'" ERR

find_package_path() {
    python3 -c "import importlib.util; from pathlib import Path; spec = importlib.util.find_spec('$1'); print(Path(spec.origin).parent if spec and spec.origin else exit(1))"
}

PACKAGE_NAME="fuzzyHSA"
BASE=$(find_package_path $PACKAGE_NAME)/kfd

if [[ ! -z "$BASE" && -d "$BASE" ]]; then
	echo "Found package path: $BASE"
else
	echo "Package path not found. Ensure the package is correctly installed."
	exit 1
fi

# setup instructions for clang2py
if [[ ! $(clang2py -V) ]]; then
	pushd .
	cd /tmp
	sudo apt-get install -y --no-install-recommends clang
	pip install --upgrade pip setuptools
	pip install clang==14.0.6
	git clone https://github.com/geohot/ctypeslib.git
	cd ctypeslib
	pip install --user .
	clang2py -V
	popd
fi

fixup() {
	sed -i '1s/^/# mypy: ignore-errors\n/' $1
	sed -i 's/ *$//' $1
	grep FIXME_STUB $1 || true
}

generate_kfd() {
	clang2py \
		"/usr/include/linux/kfd_ioctl.h" \
		-o $BASE/kfd.py \
		-k cdefstum
	fixup $BASE/kfd.py
	sed -i "s\import ctypes\import ctypes, os\g" $BASE/kfd.py
}

clean_up() {
    echo "Cleaning up generated files..."
    rm -f "$BASE/kfd.py"
    echo "Cleanup complete."
}

[ "$1" == "kfd" ] && generate_kfd
[ "$1" == "clean" ] && clean_up
