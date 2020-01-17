#!/bin/bash
#	Project MCM
#
#	Copyright (C) <2015-2017> Tim Waizenegger, <University of Stuttgart>
#
#	This software may be modified and distributed under the terms
#	of the MIT license.  See the LICENSE file for details.

cd /sdos-core
git pull
export PYTHONPATH=$PYTHONPATH:/sdos-core:/sdos-core/mcm


# run as a flask multithread app
#python _runService_Production.py

# run in a gunicorn (multiprocessed) server
./_runService_Gunicorn.sh