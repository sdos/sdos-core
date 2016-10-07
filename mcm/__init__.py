#!/usr/bin/python
# coding=utf-8

"""
	Project MCM - Micro Content Management
	SDOS - Secure Delete Object Store


	Copyright (C) <2016> Tim Waizenegger, <University of Stuttgart>

	This software may be modified and distributed under the terms
	of the MIT license.  See the LICENSE file for details.
"""

import logging
from mcm.sdos import configuration
logging.basicConfig(level=configuration.log_level, format=configuration.log_format)