#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
Created on Jun 9, 2016

@author: tim
'''

import logging
from tim.sdos.core import Frontend, Configuration
import json

log = logging.getLogger()



class TreeGeometry(object):
	'''
	classdocs
	'''


	def __init__(self):
		'''
		Constructor
		'''
		
		
	def getGeometry(self, cascade):
		g = {
			"levels": Configuration.TREE_HEIGHT +1,
			"partitionSize": Configuration.PARTITION_SIZE,
			#"usedSlots": cascade.keySlotMapper.usedList,
			"usedPartitions": list(cascade.getListOfUsedPartitions()),
			"objectMapping": cascade.getFullReverseMapping()
			}
		return json.dumps(g)