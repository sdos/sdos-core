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
import sys

from mcm.sdos.core import Frontend
from mcm.sdos.util import treeGeometry
from mcm.sdos import configuration

logging.basicConfig(level=configuration.log_level, format=configuration.log_format)
log = logging.getLogger()

###############################################################################
###############################################################################

if __name__ == '__main__':
	log.debug('geomtest start')
	log.debug(sys.version)
	log.debug(sys.flags)
	# frontend = Frontend.DirectFrontend(containerName='sdosTest1')
	# frontend = Frontend.CryptoFrontend(containerName='sdosTest1')
	frontend = Frontend.SdosFrontend(containerName='sdosTest1', swiftUser = 'test:tester', swiftKey = 'testing')
	cascade = frontend.cascade

	log.warning(treeGeometry.get_geometry_json(cascade=cascade))
	log.warning(treeGeometry.get_slot_mapping_json(cascade=cascade))
	log.warning(treeGeometry.get_cascade_stats_json(cascade=cascade))
	treeGeometry.print_slot_mapping(cascade=cascade)
	print(treeGeometry.get_slot_utilization(cascade=cascade))










