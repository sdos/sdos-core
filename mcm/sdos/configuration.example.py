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
#log_level = logging.DEBUG
log_format = '%(asctime)s - %(module)s - %(levelname)s ##\t  %(message)s'

"""
################################################################################
Server / runtime config
################################################################################
"""

"""
this is the socket that the "dev" runner will listen on.
VCAP_APP_* variables are used in cloudfoundry environments; the second parameter is the fallback which will be used normally
note that with this config, the DEV runner is only locally visible. Only the PROD runner listening on 0.0.0.0 will be accessible form th eoutside
"""
# My proxy endpoints
netPortDev = os.getenv("VCAP_APP_PORT", "3000")
netHostDev = os.getenv("VCAP_APP_HOST", "127.0.0.1")

netPortProd = os.getenv("VCAP_APP_PORT", "3000")
netHostProd = os.getenv("VCAP_APP_HOST", "0.0.0.0")

proxy_store_url = "http://localhost:3000/v1/AUTH_{}"


# swift endpoint
swift_auth_url = "http://129.69.209.131:5000/v2.0/tokens"
swift_store_url = "http://129.69.209.131:8080/v1/AUTH_{}"


###############################################################################
"""
	Key Cascade geometry / parameters
"""
CASCADE_FILE_PATH = '/tmp/sdos'
