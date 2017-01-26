#!/usr/bin/env bash

source setenv.sh

# listen only to localhost, enable debug
#python _runService_Development.py

# listen on all interfaces, no debug
python _runService_Production.py

# listen on all interfaces, no debug, multi-process
# doesn't work ATM with SDOS for various reasons
#./_runService_Production.sh
