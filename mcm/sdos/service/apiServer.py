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
from mcm.retentionManager import app, httpBackend, appConfig, retentionFilter
from mcm.retentionManager.Exceptions import HttpError

"""WSGI application for the proxy server."""

log = logging.getLogger()


##############################################################################
# decorators
##############################################################################
def log_requests(f):
	@wraps(f)
	def logging_wrapper(*args, **kwargs):
		log.debug("<<<{}>>> handles request: {} {}".format(f.__name__, request.method, request.url))
		return f(*args, **kwargs)

	return logging_wrapper


##############################################################################
# helpers
##############################################################################
def replaceStorageUrl(swiftResponse):
	swiftUrl = swiftResponse['X-Storage-Url']
	if not swiftUrl.startswith(appConfig.swift_storage_url.format("")):
		raise HttpError("swift returned wrong storage URL")
	swiftAuthName = swiftUrl[len(appConfig.swift_storage_url.format("")):]
	swiftResponse['X-Storage-Url'] = appConfig.proxy_storage_url.format(swiftAuthName)


##############################################################################
# error handler
##############################################################################
@app.errorhandler(Exception)
def handle_invalid_usage(e):
	if (HttpError == type(e)):
		return e.to_string(), e.status_code
	log.exception("internal error")
	return "Internal Server Error", 500


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


"""
	Account functions
"""


@app.route("/v1/AUTH_<thisAuth>", methods=["HEAD", "POST", "GET", "PUT", "DELETE"])
@log_requests
def handle_account(thisAuth):
	myUrl = appConfig.swift_storage_url.format(thisAuth)
	log.debug(
		"client request {}, header: {}, args: {} -- content: {}".format(request.method, request.headers, request.args,
		                                                                request.data))
	s, h, b = httpBackend.doGenericRequest(method=request.method, reqUrl=myUrl, reqHead=request.headers,
	                                       reqArgs=request.args, reqData=request.data)
	return Response(response=b, status=s, headers=h)


"""
	Container functions
"""


@app.route("/v1/AUTH_<thisAuth>/<thisContainer>", methods=["POST", "GET", "PUT", "DELETE"])
@log_requests
def handle_container(thisAuth, thisContainer):
	myUrl = appConfig.swift_storage_url.format(thisAuth)
	myUrl += "/" + thisContainer
	log.debug(
		"client request {}, header: {}, args: {} -- content: {}".format(request.method, request.headers, request.args,
		                                                                request.data))
	s, h, b = httpBackend.doGenericRequest(method=request.method, reqUrl=myUrl, reqHead=request.headers,
	                                       reqArgs=request.args, reqData=request.data)
	return Response(response=b, status=s, headers=h)


"""
	Object functions
"""


@app.route("/v1/AUTH_<thisAuth>/<thisContainer>/<path:thisObject>", methods=["POST", "GET", "PUT", "DELETE"])
@log_requests
@retentionFilter.checkRetentionDate
def handle_object(thisAuth, thisContainer, thisObject):
	myUrl = appConfig.swift_storage_url.format(thisAuth)
	myUrl += "/" + thisContainer + "/" + thisObject
	log.debug(
		"client request {}, header: {}, args: {} -- content: {}".format(request.method, request.headers, request.args,
		                                                                request.data))
	s, h, b = httpBackend.doGenericRequest(method=request.method, reqUrl=myUrl, reqHead=request.headers,
	                                       reqArgs=request.args, reqData=request.data)
	return Response(response=b, status=s, headers=h)
