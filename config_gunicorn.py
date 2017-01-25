# -*- coding: utf-8 -*-

"""
	Project SDOS

	Copyright (C) <2016> <University of Stuttgart>

	This software may be modified and distributed under the terms
	of the MIT license.  See the LICENSE file for details.
"""

from mcm.sdos import configuration
import multiprocessing


bind = "{}:{}".format(configuration.netHostProd, configuration.netPortProd)
workers = multiprocessing.cpu_count() * 2 + 1
#workers = workers * 1
workers = 1
timeout = 600
graceful_timeout = 800
worker_class = "gevent"
#worker_class = "eventlet"
#worker_class = "geventwebsocket.gunicorn.workers.GeventWebSocketWorker"