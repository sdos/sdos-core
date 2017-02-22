#!/usr/bin/python
# coding=utf-8

"""
	Project MCM - Micro Content Management
	SDOS - Secure Delete Object Store


	Copyright (C) <2017> Tim Waizenegger, <University of Stuttgart>

	This software may be modified and distributed under the terms
	of the MIT license.  See the LICENSE file for details.



	Handle a pseudo container that allow accessing SDOS/MCM internal data over regular swift requests
	This pseudo container is used for requests that don't correlate to a specific container
	unfortunately, we currently don't have authentication for this API

"""

import logging
from flask import Response

from mcm.sdos.service.Exceptions import HttpError

try:
    from mcm.sdos.util.tpmLib import TpmLib
except ImportError:
    logging.exception("unable to import TPM lib, TPM functions will not be available")
    TpmLib = None

PSEUDO_CONTAINER_NAME = "__mcm-pseudo-container__"
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


def __handle_no_tpm():
    """

    :return:
    """
    t = "TPM lib not installed, no TPM support available."
    return Response(t, status=200, mimetype="text/plain")

def dispatch(thisObject, data=None):
    logging.debug("request for MCM pseudo container: {}, data: {}".format(thisObject, data))
    is_operation = lambda name: (thisObject == name)
    try:
        ###############################################################################
        # TPM integration
        ###############################################################################
        if is_operation("tpm_status"):
            if not TpmLib:
                return __handle_no_tpm()
            return Response(response=TpmLib().get_status(), status=200,
                            mimetype="text/plain")
        elif is_operation("tpm_unlock"):
            if not TpmLib:
                return __handle_no_tpm()
            return Response(response=TpmLib().unlock(extract_passphrase(data)), status=200,
                            mimetype="text/plain")
        elif is_operation("tpm_lock"):
            if not TpmLib:
                return __handle_no_tpm()
            return Response(response=TpmLib().lock(), status=200,
                            mimetype="text/plain")
        ###############################################################################
        # unknown
        ###############################################################################
        else:
            raise HttpError("unknown pseudo container: {}".format(thisObject))
    except Exception as e:
        logging.exception("pseudo container API received exception")
        return "{}".format(e), 500
