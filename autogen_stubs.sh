#!/usr/bin/env bash

set -euo pipefail
trap "echo 'Error: Script failed.'" ERR

find_package_path() {
	python3 -c "import importlib.util; from pathlib import Path; spec = importlib.util.find_spec('$1'); print(Path(spec.origin).parent if spec and spec.origin else exit(1))"
}

PACKAGE_NAME="fuzzyHSA"
BASE=$(find_package_path $PACKAGE_NAME)/kfd/autogen

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
	sed -i '1s/^/# mypy: ignore-errors\n/' "$1"
	sed -i 's/ *$//' "$1"
	grep FIXME_STUB "$1" || true
}

function check_generated_file_existence() {
	local filename=$1
	local full_path="$BASE/$filename"
	if [[ -f "$full_path" ]]; then
		return 0
	else
		return 1
	fi
}

function generate_amd_gpu() {
	local filename="amd_gpu.py"
	if check_generated_file_existence "$filename"; then
		echo "$filename already exists. Skipping generation."
	else
		local rocm_path="/opt/rocm"
		local include_path="$rocm_path/include"

		wget https://raw.githubusercontent.com/ROCm/ROCR-Runtime/201228c4fbd343cebdb6457ded7cb4d55637d60d/src/core/inc/sdma_registers.h -O $BASE/sdma_registers.h
		clang2py $BASE/sdma_registers.h --clang-args="-I$include_path -x c++" -o "$BASE/amd_gpu.py" -l /opt/rocm/lib/libhsa-runtime64.so

		NVD_HEADER=$(find /usr/src -name nvd.h | grep 'amdgpu')
		[ -f "NVD_HEADER" ] && echo "Couldn't find nvd.h on the system" && exit 1

		sed 's/^\(.*\)\(\s*\/\*\)\(.*\)$/\1 #\2\3/; s/^\(\s*\*\)\(.*\)$/#\1\2/' $NVD_HEADER >>$BASE/amd_gpu.py # comments
		sed -i 's/#\s*define\s*\([^ \t]*\)(\([^)]*\))\s*\(.*\)/def \1(\2): return \3/' $BASE/amd_gpu.py        # #define name(x) (smth) -> def name(x): return (smth)
		sed -i '/#\s*define\s\+\([^ \t]\+\)\s\+\([^ ]\+\)/s//\1 = \2/' $BASE/amd_gpu.py                        # #define name val -> name = val

		fixup "$BASE/amd_gpu.py"

		echo "Installed $filename at $BASE"
	fi
}

function generate_hsa() {
	local filename="hsa.py"
	if check_generated_file_existence "$filename"; then
		echo "$filename already exists. Skipping generation."
	else
		local include_path="/opt/rocm/include"
		local lib_path="/opt/rocm/lib"

		clang2py \
			$include_path/hsa/hsa.h \
			$include_path/hsa/hsa_ext_amd.h \
			$include_path/hsa/amd_hsa_signal.h \
			$include_path/hsa/amd_hsa_queue.h \
			$include_path/hsa/amd_hsa_kernel_code.h \
			$include_path/hsa/hsa_ext_finalize.h \
			$include_path/hsa/hsa_ext_image.h \
			$include_path/hsa/hsa_ven_amd_aqlprofile.h \
			--clang-args=-I"$include_path" -o "$BASE/$filename" -l "$lib_path"/libhsa-runtime64.so

		sed -i "s\import ctypes\import ctypes, os\g" $BASE/$filename
		sed -i "s\'/opt/rocm/\os.getenv('ROCM_PATH', '/opt/rocm/')+'/\g" $BASE/$filename

		fixup "$BASE/$filename"

		echo "Installed $filename at $BASE"
	fi
}

function generate_kfd() {
	local filename="kfd.py"
	if check_generated_file_existence "$filename"; then
		echo "$filename already exists. Skipping generation."
	else
		clang2py \
			"/usr/include/linux/kfd_ioctl.h" \
			-o "$BASE"/"$filename" \
			-k cdefstum

		sed -i "s\import ctypes\import ctypes, os\g" "$BASE"/"$filename"

		fixup "$BASE"/"$filename"

		echo "Installed $filename at $BASE"
	fi
}

function generate() {
	generate_amd_gpu
	generate_hsa
	generate_kfd
}

function delete_generated_file() {
	local filename="$1"
	if check_generated_file_existence "$filename"; then
		echo "Cleaning up: removing $filename"
		rm "$BASE"/"$filename"
	else
		echo "No cleanup needed. $filename does not exist."
	fi
}

function clean() {
	delete_generated_file "kfd.py"
	delete_generated_file "hsa.py"
	delete_generated_file "amd_gpu.py"
	delete_generated_file "sdma_registers.h"
}

case "$1" in
generate)
	generate
	;;
clean)
	clean
	;;
*)
	echo "Usage: $0 [generate|clean]"
	echo "generate: Prepares and creates bindings for kfd and HSA, converting system headers into usable Python modules."
	echo "clean: Removes any previously generated files to ensure a clean state for re-generation."
	exit 1
	;;
esac
