#!/bin/bash

make clean && make

./main -iface ens3 -drop 192.168.33.99
