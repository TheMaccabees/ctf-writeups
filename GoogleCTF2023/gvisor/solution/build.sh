#!/bin/bash
clang -Os main.c stub.S -Iinc/ -o main.elf -lpthread

