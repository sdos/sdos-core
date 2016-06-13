#!/usr/bin/python
# coding=utf-8

"""
	Project MCM - Micro Content Management
	SDOS - Secure Delete Object Store


	Copyright (C) <2016> Tim Waizenegger, <University of Stuttgart>

	This software may be modified and distributed under the terms
	of the MIT license.  See the LICENSE file for details.





	This is the configuration file for the SDOS core and service components
"""

import logging, math, os


###############################################################################
"""
	Log level setting
"""
# log_level = logging.CRITICAL
# log_level = logging.ERROR
log_level = logging.WARNING
# log_level = logging.INFO
# log_level = logging.DEBUG
log_format = '%(asctime)s - %(module)s - %(levelname)s ##\t  %(message)s'

###############################################################################
"""
	API / service settings
"""
swift_auth_url = "http://192.168.209.204:8080/auth/v1.0"
swift_storage_url = "http://192.168.209.204:8080/v1/AUTH_{}"
proxy_storage_url = "http://localhost:3000/v1/AUTH_{}"
netPortDev = os.getenv("VCAP_APP_PORT", "3000")
netHostDev = os.getenv("VCAP_APP_HOST", "127.0.0.1")

###############################################################################
"""
	Key Cascade geometry / parameters
"""
PARTITION_BITS =								8 #8 # 256 slots for 8 bit, 4 slots for 2 bit
TREE_HEIGHT =									2 # height doesn't include the root
CASCADE_FILE_PATH =								'/tmp/sdos'
BYTES_FOR_NAME_LENGTH =							2 # allows names to be 65536 characters long

###############################################################################
"""
	Derived properties
	DO NOT CHANGE

"""
PARTITION_SIZE =								2 ** PARTITION_BITS # 256 slots for 8 bit
NUMBER_OF_OBJECT_KEY_PARTITIONS =				PARTITION_SIZE ** TREE_HEIGHT
NUMBER_OF_SLOTS_IN_OBJECT_KEY_PARTITIONS =		PARTITION_SIZE ** (TREE_HEIGHT +1)
NUMBER_OF_PARTITION_KEY_PARTITIONS =			math.floor(((PARTITION_SIZE ** TREE_HEIGHT) -1) / (PARTITION_SIZE - 1))
TOTAL_NUMER_OF_PARTITIONS =						NUMBER_OF_OBJECT_KEY_PARTITIONS + NUMBER_OF_PARTITION_KEY_PARTITIONS
BYTES_FOR_PARTITION_IDs =						math.ceil(int.bit_length(TOTAL_NUMER_OF_PARTITIONS) / 8)
FIRST_OBJECT_KEY_SLOT =							TOTAL_NUMER_OF_PARTITIONS
LAST_OBJCT_KEY_SLOT =							FIRST_OBJECT_KEY_SLOT + NUMBER_OF_SLOTS_IN_OBJECT_KEY_PARTITIONS -1
BYTES_FOR_SLOT_IDS = 							math.ceil(int.bit_length(LAST_OBJCT_KEY_SLOT) / 8)
MAX_NAME_LENGTH =								2 ** (BYTES_FOR_NAME_LENGTH * 8)