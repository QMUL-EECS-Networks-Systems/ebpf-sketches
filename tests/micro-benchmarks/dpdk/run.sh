#!/bin/bash

set -x

sudo ./build/$1 -l 1 -n 4 -- -p 0x3 --config="(0,0,1),(1,0,1)"
