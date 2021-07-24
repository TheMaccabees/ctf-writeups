#!/bin/bash
# Disassemble file as aarch64
objdump -D -bbinary -maarch64 $1
