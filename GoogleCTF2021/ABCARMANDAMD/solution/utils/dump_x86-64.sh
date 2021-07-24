#!/bin/bash
# Disassemble file as x86_64
objdump -D -bbinary -mi386:x86-64 -Mintel $1
