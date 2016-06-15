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
from functools import wraps
from flask import request, Response

from mcm.sdos import configuration
from mcm.sdos.service.Exceptions import HttpError
from mcm.sdos.service import httpBackend, app
from mcm.sdos.core import Frontend

"""
	WSGI application for the proxy server.
	This service receives requests over a REST API that effectively behaves like a swift server
	 requests are directly forwarded (using a http lib) to swift in order to retrieve objects, containers etc.
	 a swift client lib is then used to issue further (new) requests to swift in order to retrieve the key cascade objects
	 the first response form swift (containing the data object) is then modified (decryption) and passed to the client

"""

log = logging.getLogger()


##############################################################################
# decorators
##############################################################################
def log_requests(f):
	@wraps(f)
	def logging_wrapper(*args, **kwargs):
		log.debug(
			"<<<{}>>> handles request: {} {} -- HEADERS: {} -- ARGS: {} -- DATA: {}".format(f.__name__, request.method,
			                                                                                request.url,
			                                                                                request.headers,
			                                                                                request.args, request.data))
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
	if not swiftUrl.startswith(configuration.swift_storage_url.format("")):
		raise HttpError("swift returned wrong storage URL")
	swiftAuthName = swiftUrl[len(configuration.swift_storage_url.format("")):]
	swiftResponse['X-Storage-Url'] = configuration.proxy_storage_url.format(swiftAuthName)


def strip_etag(h):
	h.pop("Etag")
	return h

def get_token(request):
	return request.headers["X-Auth-Token"]


##############################################################################
# error handler
##############################################################################
@app.errorhandler(Exception)
def handle_invalid_usage(e):
	if (HttpError == type(e)):
		return e.to_string(), e.status_code
	log.exception("internal error")
	return "Exception in the SDOS service; check logs", 400


"""
	Forward the auth request to swift
	replace the given storage url with our own:
	'X-Storage-Url': 'http://192.168.209.204:8080/v1/AUTH_test'
	becomes
	'X-Storage-Url': 'http://localhost:4000/v1/AUTH_test'
	
	this is the first request any client makes; we passed on a auth.token from swift
	which is used in further requests
"""


@app.route("/auth/v1.0", methods=["GET"])
@log_requests
def handle_auth():
	clientHeaders = request.headers
	swiftStatus, swiftHeaders = httpBackend.doAuthGetToken(reqHead=clientHeaders)
	log.debug("swift response: {}".format(swiftHeaders))
	replaceStorageUrl(swiftResponse=swiftHeaders)
	log.debug("proxy response: {}".format(swiftHeaders))
	return Response(response="", status=swiftStatus, headers=swiftHeaders)


##############################################################################
# API functions
##############################################################################

"""
	Account functions
"""


@app.route("/v1/AUTH_<thisAuth>", methods=["HEAD", "POST", "GET", "PUT", "DELETE"])
@log_requests
def handle_account(thisAuth):
	myUrl = configuration.swift_storage_url.format(thisAuth)
	s, h, b = httpBackend.doGenericRequest(method=request.method, reqUrl=myUrl, reqHead=request.headers,
	                                       reqArgs=request.args, reqData=request.data)
	return Response(response=b, status=s, headers=h)


"""
	Container functions
"""


@app.route("/v1/AUTH_<thisAuth>/<thisContainer>", methods=["POST", "GET", "PUT", "DELETE"])
@log_requests
def handle_container(thisAuth, thisContainer):
	myUrl = configuration.swift_storage_url.format(thisAuth)
	myUrl += "/" + thisContainer
	s, h, b = httpBackend.doGenericRequest(method=request.method, reqUrl=myUrl, reqHead=request.headers,
	                                       reqArgs=request.args, reqData=request.data)
	return Response(response=b, status=s, headers=h)


"""
	Object functions
"""


@app.route("/v1/AUTH_<thisAuth>/<thisContainer>/<path:thisObject>", methods=["GET"])
@log_requests
def handle_object_get(thisAuth, thisContainer, thisObject):
	myUrl = configuration.swift_storage_url.format(thisAuth)
	myUrl += "/" + thisContainer + "/" + thisObject
	s, h, b = httpBackend.doGenericRequest(method=request.method, reqUrl=myUrl, reqHead=request.headers,
	                                       reqArgs=request.args, reqData=request.data)
	if (s == 200 and len(b)):
		frontend = Frontend.SdosFrontend(containerName=thisContainer, swiftTenant=thisAuth, swiftToken=get_token(request))
		decrypted_b = frontend.decrypt_bytes_object(b, thisObject)
		return Response(response=decrypted_b, status=s, headers=strip_etag(h))
	raise HttpError("decrypting failed; received no data from swift")


@app.route("/v1/AUTH_<thisAuth>/<thisContainer>/<path:thisObject>", methods=["POST", "PUT", "DELETE"])
@log_requests
def handle_object(thisAuth, thisContainer, thisObject):
	myUrl = configuration.swift_storage_url.format(thisAuth)
	myUrl += "/" + thisContainer + "/" + thisObject
	s, h, b = httpBackend.doGenericRequest(method=request.method, reqUrl=myUrl, reqHead=request.headers,
	                                       reqArgs=request.args, reqData=request.data)
	return Response(response=b, status=s, headers=h)
