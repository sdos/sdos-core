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


def dispatch_get_head(sdos_frontend, thisObject):
    logging.debug("GET/HEAD request for MCM pseudo object: {}".format(thisObject))
    is_operation = lambda name: (thisObject[len(PSEUDO_OBJECT_PREFIX):] == name)
    try:
        cascade = sdos_frontend.cascade
        ###############################################################################
        # statistics, visualization
        ###############################################################################
        if is_operation("sdos_used_partitions"):
            return Response(response=treeGeometry.sdos_used_partitions(cascade=cascade), status=200,
                            mimetype="application/json")
        elif is_operation("sdos_partition_mapping"):
            return Response(response=treeGeometry.sdos_partition_mapping(cascade=cascade), status=200,
                            mimetype="application/json")
        elif is_operation("sdos_batch_delete_log"):
            return Response(response=treeGeometry.sdos_batch_delete_log(sdos_frontend=sdos_frontend), status=200,
                            mimetype="application/json")
        elif is_operation("sdos_cascade_stats"):
            return Response(response=treeGeometry.sdos_cascade_stats(sdos_frontend=sdos_frontend), status=200,
                            mimetype="application/json")
        elif is_operation("sdos_slot_utilization10"):
            return Response(response=treeGeometry.sdos_slot_utilization(cascade=cascade, NUMFIELDS=10), status=200,
                            mimetype="application/json")
        elif is_operation("sdos_slot_utilization100"):
            return Response(response=treeGeometry.sdos_slot_utilization(cascade=cascade, NUMFIELDS=100), status=200,
                            mimetype="application/json")
        elif is_operation("sdos_slot_utilization1000"):
            return Response(response=treeGeometry.sdos_slot_utilization(cascade=cascade, NUMFIELDS=1000), status=200,
                            mimetype="application/json")
        elif is_operation("sdos_slot_utilization10000"):
            return Response(response=treeGeometry.sdos_slot_utilization(cascade=cascade, NUMFIELDS=10000), status=200,
                            mimetype="application/json")
        ###############################################################################
        # unknown
        ###############################################################################
        else:
            raise HttpError("unknown pseudo object: {}".format(thisObject))
    except Exception as e:
        logging.exception("pseudo object API received exception")
        return "{}".format(e), 500


def dispatch_put_post(sdos_frontend, thisObject, data):
    logging.debug("PUT/POST request for MCM pseudo object: {}, data: {}".format(thisObject, data))
    is_operation = lambda name: (thisObject[len(PSEUDO_OBJECT_PREFIX):] == name)
    try:
        cascade = sdos_frontend.cascade
        p = extract_passphrase(data)
        ###############################################################################
        # key management actions
        ###############################################################################
        if is_operation("sdos_next_deletable"):
            return Response(response=cascade.masterKeySource.provide_next_deletable(passphrase=p), status=200,
                            mimetype="application/json")
        elif is_operation("sdos_clear_next_deletable"):
            return Response(response=cascade.masterKeySource.clear_next_deletable(), status=200,
                            mimetype="application/json")
        elif is_operation("sdos_masterkey_unlock"):
            return Response(response=cascade.masterKeySource.unlock_key(passphrase=p), status=200,
                            mimetype="application/json")
        elif is_operation("sdos_masterkey_lock"):
            return Response(response=cascade.masterKeySource.lock_key(), status=200,
                            mimetype="application/json")
        elif is_operation("sdos_batch_delete_start"):
            return Response(response=sdos_frontend.batch_delete_start(), status=200,
                            mimetype="application/json")
        ###############################################################################
        # unknown
        ###############################################################################
        else:
            raise HttpError("unknown pseudo object: {}".format(thisObject))
    except Exception as e:
        logging.exception("pseudo object API received exception")
        return "{}".format(e), 500
