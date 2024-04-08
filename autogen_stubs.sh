#!/usr/bin/env bash

set -euo pipefail
trap "echo 'Error: Script failed.'" ERR

find_package_path() {
	python3 -c "import importlib.util; from pathlib import Path; spec = importlib.util.find_spec('$1'); print(Path(spec.origin).parent if spec and spec.origin else exit(1))"
}

PACKAGE_NAME="fuzzyHSA"
BASE=$(find_package_path $PACKAGE_NAME)/kfd

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

function generate() {
    local filename="$1.py"
    if check_generated_file_existence "$filename"; then
        echo "$filename already exists. Skipping generation."
    else
      clang2py \
        "/usr/include/linux/kfd_ioctl.h" \
        -o "$BASE"/"$filename" \
        -k cdefstum #TODO: need to have this more general so it uses in "$filename"
      fixup "$BASE"/"$filename"
      sed -i "s\import ctypes\import ctypes, os\g" "$BASE"/"$filename"
      echo "Installed $filename at '$BASE'"
    fi
}

function clean() {
    local filename="$1.py"
    if check_generated_file_existence "$filename"; then
          echo "Cleaning up: removing $filename"
          rm "$BASE"/"$filename"
      else
          echo "No cleanup needed. $filename does not exist."
      fi
}

function parse_arg() {
    IFS='=' read -ra ADDR <<< "$1"  # Split argument by '='
    local command="${ADDR[0]}"
    local value="${ADDR[1]}"

    case $command in
        generate)
            generate "$value"
            ;;
        clean)
            clean "$value"
            ;;
        *)
            echo "Unknown command: $command"
            exit 1
            ;;
    esac
}

parse_arg "$1"
