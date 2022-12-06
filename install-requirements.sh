#!/bin/bash

# This script compiles and installs all requirements for this repo
COLOR_GREEN='\033[0;32m'
COLOR_RED='\033[0;31m'
COLOR_OFF='\033[0m' # No Color

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

function print_system_info {
  echo -e "${COLOR_GREEN}***********************SYSTEM INFO*************************************"
  echo -e "kernel version:" $(uname -r)
  echo -e "linux release info:" $(lsb_release -d | awk '{print $2, $3}')
  echo -e "${COLOR_OFF}"
}

function error_message {
  set +x
  echo
  echo -e "${COLOR_RED}Error during installation${COLOR_OFF}"
  print_system_info
  exit 1
}

function success_message {
  set +x
  echo
  echo -e "${COLOR_GREEN}Installation completed successfully${COLOR_OFF}"
  exit 0
}

get_llvm() {
  pushd .
  cd "$DEPSDIR"
  echo -e "${COLOR_GREEN}[INFO] Download LLVM 13 binaries ${COLOR_OFF}"
  if [ ! -d clang+llvm13 ]; then
      mkdir clang+llvm13
      wget https://github.com/llvm/llvm-project/releases/download/llvmorg-13.0.0/clang+llvm-13.0.0-x86_64-linux-gnu-ubuntu-20.04.tar.xz
      tar xf clang+llvm-13.0.0-x86_64-linux-gnu-ubuntu-20.04.tar.xz -C clang+llvm13 --strip-components 1
      rm clang+llvm-13.0.0-x86_64-linux-gnu-ubuntu-20.04.tar.xz
  fi

  echo -e "${COLOR_GREEN}[INFO] LLVM is installed ${COLOR_OFF}"
  popd
}

get_install_bcc() {
  BCC_DIR=$DEPSDIR/bcc
  BCC_BUILD_DIR=$DEPSDIR/bcc/build/

  if [ -f "$DEPSDIR/bcc_installed" ]; then
      return
  fi
  
  rm -rf "$BCC_DIR"
  pushd .
  cd "$DEPSDIR"
  echo -e "${COLOR_GREEN}[INFO] Cloning BCC repo ${COLOR_OFF}"
  git clone --depth 1 --recursive --branch v0.22.0 https://github.com/iovisor/bcc.git 
  cd "$BCC_DIR"
  git submodule update --init
  git apply ${DIR}/bcc-patch.patch
  mkdir -p "$BCC_BUILD_DIR"
  cd "$BCC_BUILD_DIR"
  cmake -DLLVM_DIR="${DEPSDIR}"/clang+llvm13/lib/cmake/llvm -DPYTHON_CMD=python3 \
  -DENABLE_EXAMPLES=OFF -DENABLE_MAN=OFF -DENABLE_TESTS=OFF -DRUN_LUA_TESTS=OFF ..
  make -j $(getconf _NPROCESSORS_ONLN)
  $SUDO make install

  echo -e "${COLOR_GREEN}[INFO] BCC is installed ${COLOR_OFF}"
  popd
  touch "$DEPSDIR/bcc_installed"
}

compile_hashlib() {
  HASHLIB_DIR=${DIR}/src/hash_lib

  pushd .
  cd "${HASHLIB_DIR}"
  make
  
  popd
}

trap error_message ERR

function show_help() {
usage="$(basename "$0")
Install all the requirements for this repo"
echo "$usage"
echo
}

while getopts h option; do
 case "${option}" in
 h|\?)
  show_help
  exit 0
 esac
done

echo -e "${COLOR_GREEN}This script and all the instructions in this repo had been tested on Ubuntu 20.04 LTS.${COLOR_OFF}"
echo ""
print_system_info

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

[ -z ${SUDO+x} ] && SUDO='sudo'
[ -z ${DEPSDIR+x} ] && DEPSDIR=$DIR/deps

if [ ! -d "$DEPSDIR" ]; then
  mkdir -p $DEPSDIR
fi

# print bash commands and their arguments as they are executed
#set -x
# exit immediately if a command exits with a non-zero status
set -e

echo -e "${COLOR_GREEN}[INFO] Install system requirements ${COLOR_OFF}"
$SUDO apt update
# $SUDO add-apt-repository ppa:deadsnakes/ppa -y || true
# $SUDO apt update
PACKAGES=""
PACKAGES+=" git wget gnupg2 software-properties-common" # needed to clone dependencies
PACKAGES+=" build-essential cmake" # provides compiler and other compilation tools
PACKAGES+=" bison autopoint gettext texinfo help2man flex" # bcc dependencies
PACKAGES+=" arping bison clang-format cmake dh-python \
  dpkg-dev pkg-kde-tools ethtool flex inetutils-ping iperf \
  libedit-dev libelf-dev \
  libfl-dev libzip-dev linux-libc-dev libluajit-5.1-dev \
  luajit python3-netaddr python3-pyroute2 python3-distutils python3 python3-pip"
PACKAGES+=" libssl-dev" # needed for certificate based security
PACKAGES+=" sudo"
PACKAGES+=" libpcap-dev" # needed for packetcapture filter

$SUDO bash -c "DEBIAN_FRONTEND=noninteractive apt install -yq $PACKAGES"

get_llvm
get_install_bcc
compile_hashlib

echo -e "${COLOR_GREEN}[INFO] Install Python3 requirements ${COLOR_OFF}"
sudo python3 -m pip install -r ${DIR}/requirements.txt --user

success_message
