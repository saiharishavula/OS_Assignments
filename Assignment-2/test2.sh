#!/bin/sh
# Deleting files will be moved off to .stb folder with encryption
set -x
cp large_file test2
cd mnt/stbfs/
unlink test2