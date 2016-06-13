#!/usr/bin/python
# coding=utf-8

"""
	Project MCM - Micro Content Management
	SDOS - Secure Delete Object Store


	Copyright (C) <2016> Tim Waizenegger, <University of Stuttgart>

	This software may be modified and distributed under the terms
	of the MIT license.  See the LICENSE file for details.
"""

import json
import logging

from tim.sdos.core import Configuration

log = logging.getLogger()


class TreeGeometry(object):
	"""
	classdocs
	"""

	def __init__(self):
		"""
		Constructor
		"""


def getGeometry(cascade):
	g = {
		"levels": Configuration.TREE_HEIGHT + 1,
		"partitionSize": Configuration.PARTITION_SIZE,
		# "usedSlots": cascade.keySlotMapper.usedList,
		"usedPartitions": cascade.getListOfUsedPartitions(),
		"objectMapping": cascade.getFullReverseMapping()
	}
	return json.dumps(g)
