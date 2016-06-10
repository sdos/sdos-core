#!/usr/bin/python
# -*- coding: utf-8 -*-
'''

@author: tim
'''

import logging
import sys
import io
import time
import statistics
from tim.sdos.core import Frontend
from tim.sdos.util import treeGeometry


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(module)s - %(levelname)s ##\t  %(message)s')
#logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(module)s - %(levelname)s ##\t  %(message)s')
log = logging.getLogger()


###############################################################################
###############################################################################

if __name__ == '__main__':
	
	
	log.debug('geomtest start')
	log.debug(sys.version)
	log.debug(sys.flags)
	#frontend = Frontend.DirectFrontend(containerName='sdosTest1')
	#frontend = Frontend.CryptoFrontend(containerName='sdosTest1')
	frontend = Frontend.SdosFrontend(containerName='sdosTest1')
	cascade = frontend.cascade
	
	g = treeGeometry.TreeGeometry()
	log.info(g.getGeometry(cascade=cascade))
	