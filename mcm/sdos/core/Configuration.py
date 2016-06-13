#!/usr/bin/python
# coding=utf-8

"""
	Project MCM - Micro Content Management
	SDOS - Secure Delete Object Store


	Copyright (C) <2016> Tim Waizenegger, <University of Stuttgart>

	This software may be modified and distributed under the terms
	of the MIT license.  See the LICENSE file for details.
"""

import math

PARTITION_BITS =								8 #8 # 256 slots for 8 bit, 4 slots for 2 bit
TREE_HEIGHT =									2 # height doesn't include the root
CASCADE_FILE_PATH =								'/tmp/sdos'
BYTES_FOR_NAME_LENGTH =							2 # allows names to be 65536 characters long

###############################################################################
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

if __name__ == '__main__':
	pass
