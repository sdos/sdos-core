#!/usr/bin/python
# coding=utf-8

"""
	Project MCM - Micro Content Management
	SDOS - Secure Delete Object Store


	Copyright (C) <2016> Tim Waizenegger, <University of Stuttgart>

	This software may be modified and distributed under the terms
	of the MIT license.  See the LICENSE file for details.



		WSGI application for the proxy server.
	This service receives requests over a REST API that effectively behaves like a swift server
	 requests are directly forwarded (using a http lib) to swift in order to retrieve objects, containers etc.
	 a swift client lib is then used to issue further (new) requests to swift in order to retrieve the key cascade objects
	 the first response form swift (containing the data object) is then modified (en/decryption) and passed to the client

"""

import logging
import json
from functools import wraps
from flask import request, Response
from swiftclient.exceptions import ClientException

from mcm.sdos import configuration
from mcm.sdos.service.Exceptions import HttpError
from mcm.sdos.service import httpBackend, app, pseudoObjects, pseudoContainer
from mcm.sdos.crypto import DataCrypt
from mcm.sdos.parallelExecution.Pool import SwiftPool, FEPool
from mcm.sdos.swift.SwiftBackend import SwiftBackend

log = logging.getLogger()


##############################################################################
# decorators
##############################################################################
def log_requests(f):
    @wraps(f)
    def logging_wrapper(*args, **kwargs):
        log.info(
            "<<<{}>>> handles request: {} {} -- HEADERS: {} -- ARGS: {}".format(f.__name__, request.method,
                                                                                request.url,
                                                                                request.headers,
                                                                                request.args))
        # log.debug("Request DATA: {}".format(request.data))
        return f(*args, **kwargs)

    return logging_wrapper


@app.after_request
def add_mcm_id(response):
    response.headers["MCM-Service-Type"] = "SDOS"
    return response


##############################################################################
# helpers
##############################################################################
def replaceStorageUrl(swiftResponse):
    swiftUrl = swiftResponse['X-Storage-Url']
    if not swiftUrl.startswith(configuration.swift_store_url.format("")):
        raise HttpError("swift returned wrong storage URL")
    swiftAuthName = swiftUrl[len(configuration.swift_store_url.format("")):]
    swiftResponse['X-Storage-Url'] = configuration.my_endpoint_store_url.format(swiftAuthName)


def replaceStorageUrl_authv2(auth_response):
    """
    here we parse the response from the auth provider and replace the provided swift store URL
    the response contains a token and some metadata which we leave intact. there is also an array of all
    available services. we replace this whole dict with only our SDOS endpoint
    :param auth_response:
    :return:
    """
    ar = json.loads(auth_response.decode("utf-8"))
    tenant_id = ar["access"]["token"]["tenant"]["id"]
    my_endpoint = [{'adminURL': 'http://129.69.209.131:8080',
                    'region': 'RegionOne',
                    'publicURL': configuration.my_endpoint_store_url.format(tenant_id),
                    'id': '1dc55ed5c82f4cd9a98d9f059729422f',
                    'internalURL': 'http://129.69.209.131:8080/v1/AUTH_ea012720129645d9b32b23b4af5c154f'
                    }]
    log.debug("Whole auth data: {}".format(ar))
    catalog = ar["access"]["serviceCatalog"]
    log.debug("All catalog: {}".format(catalog))

    for service in catalog:
        if (service["type"] == "object-store" and service["name"] == "swift"):
            log.debug("This swift service: {}".format(service))
            log.debug("replacing the endpoint for this swift service...")
            service["endpoints"] = my_endpoint

    return ar


def strip_etag(h):
    try:
        h.pop("Etag")
    except:
        pass
    return h


def add_sdos_flag(h):
    i = dict(h)
    i["X-Object-Meta-MCM-Content"] = DataCrypt.HEADER
    return i


def get_token(request):
    return request.headers["X-Auth-Token"]


def get_proxy_request_url(thisAuth, thisContainer=None, thisObject=None):
    """
    create the url under which this API proxy will reach its swift back end. basically this is the request url with a different hostname
    :param thisAuth:
    :param thisContainer:
    :param thisObject:
    :return:
    """
    u = configuration.swift_store_url.format(thisAuth)
    if thisContainer:
        u += "/" + thisContainer
        if thisObject:
            u += "/" + thisObject
    return u


##############################################################################
# Frontend Pool
##############################################################################

def get_sdos_frontend(containerName, swiftTenant, swiftToken):
    """
    TODO: we really need a cascade-pool here and maybe locking in the cascade...
    :param containerName:
    :param swiftTenant:
    :param swiftToken:
    :return:
    """

    sp = SwiftPool()
    sb = sp.getConn(swiftTenant, swiftToken)

    fp = FEPool()

    if sb.is_sdos_container(containerName):
        return fp.getFE(containerName, swiftTenant, swiftToken)
    else:
        return False


##############################################################################
# error handler
##############################################################################
@app.errorhandler(Exception)
def handle_invalid_usage(e):
    log.exception("unhandled exception reached API handler")
    if (ClientException == type(e)):
        if (401 == e.http_status):
            return "not authenticated", 401
        return e.__str__(), e.http_status
    if (HttpError == type(e)):
        return e.to_string(), e.status_code
    return "{}".format(e), 500


@app.route("/auth/v1.0", methods=["GET"])
@log_requests
def handle_auth():
    """
    Forward the auth request to swift
    replace the given storage url with our own:
    'X-Storage-Url': 'http://192.168.209.204:8080/v1/AUTH_test'
    becomes
    'X-Storage-Url': 'http://localhost:4000/v1/AUTH_test'

    this is the first request any client makes; we passed on an auth-token from swift
    which is used in further requests
    :return:
    """
    clientHeaders = request.headers
    swiftStatus, swiftHeaders, swiftBody = httpBackend.doAuthGetToken(reqHead=clientHeaders, method="GET")
    log.debug("swift response: {}".format(swiftHeaders))
    replaceStorageUrl(swiftResponse=swiftHeaders)
    log.debug("proxy response: {}".format(swiftHeaders))
    r = Response(response="", status=swiftStatus)
    r.headers = swiftHeaders
    return r


@app.route("/v2.0/tokens", methods=["POST"])
@log_requests
def handle_auth_v2():
    """
    Forward the auth request to swift
    replace the given storage url with our own:
    'X-Storage-Url': 'http://192.168.209.204:8080/v1/AUTH_test'
    becomes
    'X-Storage-Url': 'http://localhost:4000/v1/AUTH_test'

    this is the first request any client makes; we passed on an auth-token from swift
    which is used in further requests

    in this V2 auth type, the credentials are in the body
    :return:
    """
    clientHeaders = request.headers
    clientBody = request.data
    swiftStatus, swiftHeaders, swiftBody = httpBackend.doAuthGetToken(reqHead=clientHeaders, method="POST",
                                                                      data=clientBody)
    log.debug("swift response: {} --BODY-- {}".format(swiftHeaders, swiftBody))
    proxyResponse = replaceStorageUrl_authv2(swiftBody)
    log.debug("proxy response body: {}".format(proxyResponse))
    r = Response(response=json.dumps(proxyResponse), status=swiftStatus)
    return r


##############################################################################
# API functions
##############################################################################

"""
	Account functions
	--> direct passthrough to swift
"""


@app.route("/v1/AUTH_<thisAuth>", methods=["HEAD", "POST", "GET", "PUT", "DELETE"])
@log_requests
def handle_account(thisAuth):
    myUrl = get_proxy_request_url(thisAuth)
    s, h, b = httpBackend.doGenericRequest(method=request.method, reqUrl=myUrl, reqHead=request.headers,
                                           reqArgs=request.args, reqData=request.data)
    return Response(response=b, status=s, headers=h)


"""
	Container functions
	--> direct passthrough to swift
"""


@app.route("/v1/AUTH_<thisAuth>/<thisContainer>", methods=["POST", "GET", "PUT", "DELETE", "HEAD"])
@log_requests
def handle_container(thisAuth, thisContainer):
    if thisContainer == pseudoContainer.PSEUDO_CONTAINER_NAME:
        return "", 200

    myUrl = get_proxy_request_url(thisAuth, thisContainer)
    s, h, b = httpBackend.doGenericRequest(method=request.method, reqUrl=myUrl, reqHead=request.headers,
                                           reqArgs=request.args, reqData=request.data)
    return Response(response=b, status=s, headers=h)


"""
	Object functions
	--> handled by SDOS if needed
"""


@app.route("/v1/AUTH_<thisAuth>/<thisContainer>/<path:thisObject>", methods=["GET", "HEAD"])
@log_requests
def handle_object_get(thisAuth, thisContainer, thisObject):

    if thisContainer == pseudoContainer.PSEUDO_CONTAINER_NAME:
        return pseudoContainer.dispatch(thisObject=thisObject)

    sdos_frontend = get_sdos_frontend(containerName=thisContainer, swiftTenant=thisAuth, swiftToken=get_token(request))

    if sdos_frontend and thisObject.startswith(pseudoObjects.PSEUDO_OBJECT_PREFIX):
        return pseudoObjects.dispatch_get_head(sdos_frontend, thisObject)

    myUrl = get_proxy_request_url(thisAuth, thisContainer, thisObject)
    s, h, b = httpBackend.doGenericRequest(method=request.method, reqUrl=myUrl, reqHead=request.headers,
                                           reqArgs=request.args, reqData=request.data)
    if (s == 200 and len(b) and sdos_frontend):
        try:
            decrypted_b = sdos_frontend.decrypt_bytes_object(b, thisObject)
        except:
            raise HttpError("Decryption failed", 412)
        # don't overwrite headers since the content length from the original response is incorrect; it accounts for padding...
        # the Response object will determine the actual, correct size
        return Response(response=decrypted_b, status=s, headers=strip_etag(h))
    else:
        r = Response(response=b, status=s)
        # this covers the unencrypted case (1) and also HEAD requests (2). We overwrite ALL the headers to retain
        # the content size in the HEAD case
        r.headers = h
        return r


@app.route("/v1/AUTH_<thisAuth>/<thisContainer>/<path:thisObject>", methods=["DELETE"])
@log_requests
def handle_object_delete(thisAuth, thisContainer, thisObject):
    myUrl = get_proxy_request_url(thisAuth, thisContainer, thisObject)
    s, h, b = httpBackend.doGenericRequest(method=request.method, reqUrl=myUrl, reqHead=request.headers,
                                           reqArgs=request.args, reqData=request.data)

    sdos_frontend = get_sdos_frontend(containerName=thisContainer, swiftTenant=thisAuth, swiftToken=get_token(request))
    if (s == 204 and sdos_frontend):
        sdos_frontend.deleteObject(thisObject)
    return Response(response=b, status=s, headers=h)


@app.route("/v1/AUTH_<thisAuth>/<thisContainer>/<path:thisObject>", methods=["PUT", "POST"])
@log_requests
def handle_object_put(thisAuth, thisContainer, thisObject):
    """
    upload/update object; C/U (from CRUD) operations
    we explicitly check the validity of the request
        SwiftBackend(tenant=thisAuth, token=thisToken).assert_valid_auth()
    for pseudo object/pseudo container requests because this otherwise doesn't happen,
    or happens too late; i.e. after KeyCascade objects were modified. In case of uploads we verify AFTER
    K.C. operations because the client can just upload the same object again and the "wrongly" assigned key/slot will be re-used
    :param thisAuth:
    :param thisContainer:
    :param thisObject:
    :return:
    """
    thisToken = get_token(request)
    if thisContainer == pseudoContainer.PSEUDO_CONTAINER_NAME:
        SwiftBackend(tenant=thisAuth, token=thisToken).assert_valid_auth()
        return pseudoContainer.dispatch(thisObject=thisObject, data=request.headers)

    myUrl = get_proxy_request_url(thisAuth, thisContainer, thisObject)
    sdos_frontend = get_sdos_frontend(containerName=thisContainer, swiftTenant=thisAuth, swiftToken=thisToken)

    if sdos_frontend and thisObject.startswith(pseudoObjects.PSEUDO_OBJECT_PREFIX):
        SwiftBackend(tenant=thisAuth, token=thisToken).assert_valid_auth()
        return pseudoObjects.dispatch_put_post(sdos_frontend, thisObject, request.headers)

    if (sdos_frontend and len(request.data)):
        try:
            data = sdos_frontend.encrypt_bytes_object(o=request.data, name=thisObject)
            headers = add_sdos_flag(request.headers)
        except:
            raise HttpError("Encryption failed", 412)
    else:
        data = request.data
        headers = request.headers

    s, h, b = httpBackend.doGenericRequest(method=request.method, reqUrl=myUrl, reqHead=headers,
                                           reqArgs=request.args, reqData=data)
    return Response(response=b, status=s, headers=strip_etag(h))
