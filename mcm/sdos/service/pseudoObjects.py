#!/usr/bin/python
# coding=utf-8

"""
	Project MCM - Micro Content Management
	SDOS - Secure Delete Object Store


	Copyright (C) <2016> Tim Waizenegger, <University of Stuttgart>

	This software may be modified and distributed under the terms
	of the MIT license.  See the LICENSE file for details.



	Handle pseudo objects that allow accessing SDOS/MCM internal data over regular swift object requests

"""

import logging
import json
from flask import Response

from mcm.sdos.service.Exceptions import HttpError
from mcm.sdos.util import treeGeometry

PSEUDO_OBJECT_PREFIX = "__mcm__/"
PASSPHRASEFIELD = 'x-object-meta-passphrase'


def extract_passphrase(msg):
    """

    :param msg:
    :return:
    """
    try:
        return msg[PASSPHRASEFIELD]
    except:
        return None


def dispatch_get_head(frontend, thisObject):
    logging.debug("GET/HEAD request for MCM pseudo object: {}".format(thisObject))
    is_operation = lambda name: (thisObject[len(PSEUDO_OBJECT_PREFIX):] == name)
    ###############################################################################
    # statistics, visualization
    ###############################################################################
    if is_operation("crypto_key_stats"):
        return Response(response=json.dumps(frontend.key_source.get_status_json()), status=200,
                        mimetype="application/json")
    elif is_operation("sdos_used_partitions"):
        return Response(response=treeGeometry.sdos_used_partitions(cascade=frontend.cascade), status=200,
                        mimetype="application/json")
    elif is_operation("sdos_partition_mapping"):
        return Response(response=treeGeometry.sdos_partition_mapping(cascade=frontend.cascade), status=200,
                        mimetype="application/json")
    elif is_operation("sdos_batch_delete_log"):
        return Response(response=treeGeometry.sdos_batch_delete_log(sdos_frontend=frontend), status=200,
                        mimetype="application/json")
    elif is_operation("sdos_cascade_stats"):
        return Response(response=treeGeometry.sdos_cascade_stats(sdos_frontend=frontend), status=200,
                        mimetype="application/json")
    elif is_operation("sdos_slot_utilization10"):
        return Response(response=treeGeometry.sdos_slot_utilization(cascade=frontend.cascade, NUMFIELDS=10), status=200,
                        mimetype="application/json")
    elif is_operation("sdos_slot_utilization100"):
        return Response(response=treeGeometry.sdos_slot_utilization(cascade=frontend.cascade, NUMFIELDS=100),
                        status=200,
                        mimetype="application/json")
    elif is_operation("sdos_slot_utilization1000"):
        return Response(response=treeGeometry.sdos_slot_utilization(cascade=frontend.cascade, NUMFIELDS=1000),
                        status=200,
                        mimetype="application/json")
    elif is_operation("sdos_slot_utilization10000"):
        return Response(response=treeGeometry.sdos_slot_utilization(cascade=frontend.cascade, NUMFIELDS=10000),
                        status=200,
                        mimetype="application/json")
    ###############################################################################
    # unknown
    ###############################################################################
    else:
        raise HttpError("unknown pseudo object: {}".format(thisObject))


def dispatch_put_post(frontend, thisObject, data):
    logging.debug("PUT/POST request for MCM pseudo object: {}, data: {}".format(thisObject, data))
    is_operation = lambda name: (thisObject[len(PSEUDO_OBJECT_PREFIX):] == name)
    p = extract_passphrase(data)

    try:
        frontend.cascade  # sdos frontend
        key_source = frontend.cascade.masterKeySource
    except AttributeError:
        pass
    try:
        frontend.key_source  # sdos frontend
        key_source = frontend.key_source
    except AttributeError:
        pass


    ###############################################################################
    # key management actions
    ###############################################################################
    if is_operation("sdos_next_deletable"):
        return Response(response=key_source.provide_next_deletable(passphrase=p), status=200,
                        mimetype="application/json")
    elif is_operation("sdos_clear_next_deletable"):
        return Response(response=key_source.clear_next_deletable(), status=200,
                        mimetype="application/json")
    elif is_operation("sdos_masterkey_unlock"):
        return Response(response=key_source.unlock_key(passphrase=p), status=200,
                        mimetype="application/json")
    elif is_operation("sdos_masterkey_lock"):
        return Response(response=key_source.lock_key(), status=200,
                        mimetype="application/json")
    elif is_operation("sdos_batch_delete_start"):
        return Response(response=frontend.batch_delete_start(), status=200,
                        mimetype="application/json")
    ###############################################################################
    # unknown
    ###############################################################################
    else:
        raise HttpError("unknown pseudo object: {}".format(thisObject))
