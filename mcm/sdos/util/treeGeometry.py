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
import math

from mcm.sdos import configuration

log = logging.getLogger()


###############################################################################
###############################################################################

def get_used_partitions_json(cascade):
	return json.dumps(cascade.get_used_partitions())

def get_partition_mapping_json(cascade):
	return json.dumps(cascade.get_reverse_object_key_partition_mapping())


def get_cascade_stats_json(cascade):
	mapper = cascade.keySlotMapper
	m = mapper.getMappingDict()
	return json.dumps({"numObjects": len(m),
	                   "numSlots": configuration.NUMBER_OF_SLOTS_IN_OBJECT_KEY_PARTITIONS,
	                   "freeSlots": configuration.NUMBER_OF_SLOTS_IN_OBJECT_KEY_PARTITIONS - len(m),
	                   "utilization": str(round(100/configuration.NUMBER_OF_SLOTS_IN_OBJECT_KEY_PARTITIONS * len(m), 2)) + "%",
	                   "levels": configuration.TREE_HEIGHT + 1,
	                   "partitionSize": configuration.PARTITION_SIZE
	                   })



###############################################################################
###############################################################################

def reverse_slot_mapping(cascade):
	"""
	reverse the obj->slot mapping to slot->obj
	:param cascade:
	:return:
	"""
	mapper = cascade.keySlotMapper
	m = mapper.getMappingDict()
	return dict((v, k) for k, v in m.items())

def insert_empty_slots(mapping):
	"""
	use the mapping slot->obj and fill the gaps (missing slot IDs) with some info text
	:param mapping:
	:return:
	"""
	mapping_new = collections.OrderedDict()
	next_expected_index = 0
	for slot in sorted(mapping.items()):
		slot_local = slot[0] - configuration.FIRST_OBJECT_KEY_SLOT
		empties = slot_local - next_expected_index
		#print(slot, slot_local, next_expected_index, empties)
		if (empties):
			mapping_new[next_expected_index] = "########## {} empties (including this) follow ##########".format(empties)
		mapping_new[slot_local] = slot[1]
		next_expected_index = slot_local + 1
	mapping_new[next_expected_index] = "########## {} empties (including this) until end of space ##########".format(
		configuration.LAST_OBJCT_KEY_SLOT - configuration.FIRST_OBJECT_KEY_SLOT - next_expected_index)
	return mapping_new

def get_reverse_slot_mapping(cascade):
	"""
	call the above two functions to produce the slot->obj mapping
	:param cascade:
	:return:
	"""
	return insert_empty_slots(reverse_slot_mapping(cascade))

def get_reverse_slot_mapping_json(cascade):
	return json.dumps(get_reverse_slot_mapping(cascade=cascade))

def print_reverse_slot_mapping(cascade):
	m = get_reverse_slot_mapping(cascade=cascade)
	for item in m.items():
		print(item)

###############################################################################
###############################################################################




def get_slot_utilization(cascade, NUMFIELDS=10000):
	"""
	<p>Each number represents a block of "groupSize" key slots.
                Numbers 0 through 9 indicate how many slots are used in that block; with 0 all slots are empty and with
                9 all are utilized.
                Note that these <q>blocks</q> are only used here for visualizing allocation. They don't align with key
                partitions or anything.</p>
	:param cascade:
	:return:
	"""
	reverse = reverse_slot_mapping(cascade)
	s = ""
	MAXVAL = 9
	groupSize = math.floor((configuration.LAST_OBJCT_KEY_SLOT - configuration.FIRST_OBJECT_KEY_SLOT + 1) / NUMFIELDS)
	remainder = (configuration.LAST_OBJCT_KEY_SLOT - configuration.FIRST_OBJECT_KEY_SLOT + 1) - groupSize * NUMFIELDS
	currentPos = 0
	foundInGroup = 0
	for slot in range(configuration.FIRST_OBJECT_KEY_SLOT, configuration.LAST_OBJCT_KEY_SLOT):
		if currentPos == groupSize:
			s += str(math.ceil(MAXVAL/groupSize * foundInGroup))
			currentPos = 0
			foundInGroup = 0
		if slot in reverse:
			foundInGroup += 1
		currentPos += 1
	if remainder:
		s += str(math.ceil(MAXVAL/remainder * foundInGroup))
	return json.dumps({"groupSize": groupSize, "blocks": NUMFIELDS, "alloc": s})




















