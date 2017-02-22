#!/bin/bash
#	Project MCM
#
#	Copyright (C) <2015-2017> Tim Waizenegger, <University of Stuttgart>
#
#	This software may be modified and distributed under the terms
#	of the MIT license.  See the LICENSE file for details.


# gunicorn runs multi-process; this currently does not work with the Key Cascade due to the need for locking
# which we can only do in a multi-thread, but no multi-process scenario
gunicorn --config=config_gunicorn.py mcm.sdos.service:app