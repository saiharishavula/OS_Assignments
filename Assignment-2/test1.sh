#!/bin/sh
# Deleting files will be moved off to .stb folder without encryption
set -x
cp large_file test1
cd mnt/stbfs/
unlink test1