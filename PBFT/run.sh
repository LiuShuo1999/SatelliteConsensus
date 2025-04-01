#!/bin/bash
make clean
make
./pbft 9100 1 0 50 12 524288
# 