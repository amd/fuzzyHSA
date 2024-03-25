#!/usr/bin/env bash

set -euo pipefail
trap "echo 'Error: Script failed.'" ERR

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

BASE=./

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

[ "$1" == "kfd" ] && generate_kfd
