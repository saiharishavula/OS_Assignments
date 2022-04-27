#!/bin/sh
# truncate a file in .stb folder
set -x
cd mnt/stbfs/.stb/
truncate file-name # should fail