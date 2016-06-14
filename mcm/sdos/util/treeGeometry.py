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
import collections

from mcm.sdos import configuration

log = logging.getLogger()


class TreeGeometry(object):
	"""
	classdocs
	"""

	def __init__(self):
		"""
		Constructor
		"""


def get_geometry_json(cascade):
	g = {
		"levels": configuration.TREE_HEIGHT + 1,
		"partitionSize": configuration.PARTITION_SIZE,
		# "usedSlots": cascade.keySlotMapper.usedList,
		"usedPartitions": cascade.get_used_partitions(),
		"objectMapping": cascade.get_reverse_object_key_partition_mapping()
	}
	return json.dumps(g)


def get_slot_mapping_stats_json(cascade):
	mapper = cascade.keySlotMapper
	m = mapper.getMappingDict()
	return json.dumps({"numObjects": len(m),
	                   "numSlots": configuration.NUMBER_OF_SLOTS_IN_OBJECT_KEY_PARTITIONS,
	                   "freeSlots": configuration.NUMBER_OF_SLOTS_IN_OBJECT_KEY_PARTITIONS - len(m),
	                   "utilization": round(100/configuration.NUMBER_OF_SLOTS_IN_OBJECT_KEY_PARTITIONS * len(m), 2)})


def get_slot_mapping(cascade):
	mapper = cascade.keySlotMapper
	m = mapper.getMappingDict()
	reverse = dict((v, k) for k, v in m.items())
	return insert_empty_slots(reverse)


def insert_empty_slots(mapping):
	mapping_new = collections.OrderedDict()
	next_expected_index = 0
	for slot in sorted(mapping.items()):
		slot_local = slot[0] - configuration.FIRST_OBJECT_KEY_SLOT
		empties = slot_local - next_expected_index
		if (empties):
			mapping_new[next_expected_index] = "########## {} empties (including this) follow ##########".format(empties)
		else:
			mapping_new[slot_local] = slot[1]
		next_expected_index = slot_local + 1
	mapping_new[next_expected_index] = "########## {} empties (including this) until end of space ##########".format(
		configuration.LAST_OBJCT_KEY_SLOT - configuration.FIRST_OBJECT_KEY_SLOT - next_expected_index)
	return mapping_new


def get_slot_mapping_json(cascade):
	return json.dumps(get_slot_mapping(cascade=cascade))


def print_slot_mapping(cascade):
	m = get_slot_mapping(cascade=cascade)
	for item in m.items():
		print(item)
