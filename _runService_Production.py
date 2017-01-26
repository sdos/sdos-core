#!/usr/bin/python
# coding=utf-8

"""
	Project MCM - Micro Content Management
	SDOS - Secure Delete Object Store


	Copyright (C) <2016> Tim Waizenegger, <University of Stuttgart>

	This software may be modified and distributed under the terms
	of the MIT license.  See the LICENSE file for details.
"""

from mcm.sdos.service import app
from mcm.sdos import configuration


"""
	Without threading, the server is too slow to serve clients. Requests are missed...
"""

app.run(
			host=configuration.netHostProd,
			port=int(configuration.netPortProd),
			debug=False,
			threaded=True
)