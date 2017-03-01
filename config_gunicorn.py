# -*- coding: utf-8 -*-

"""
	Project SDOS

	Copyright (C) <2016> <University of Stuttgart>

	This software may be modified and distributed under the terms
	of the MIT license.  See the LICENSE file for details.
"""

from mcm.sdos import configuration
import multiprocessing

bind = "{}:{}".format(configuration.my_bind_host, configuration.my_endpoint_port)
# workers = multiprocessing.cpu_count() * 2 + 1
# workers = workers * 1
# gunicorn runs multi-process; this currently does not work with the Key Cascade due to the need for locking
# which we can only do in a multi-thread, but no multi-process scenario
workers = 1
timeout = 600
graceful_timeout = 800
# worker_class = "gevent"
# worker_class = "eventlet"
# worker_class = "geventwebsocket.gunicorn.workers.GeventWebSocketWorker"
worker_class = "egg:meinheld#gunicorn_worker"