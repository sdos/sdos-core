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
import requests
from mcm.retentionManager import appConfig

log = logging.getLogger(__name__)


def stripHeaders(headers):
	headers = dict(headers)
	headers.pop('Host')
	headers.pop('User-Agent')
	headers.pop('Content-Length')
	headers.pop('Content-Type')
	return headers


def doAuthGetToken(reqHead):
	reqHead = stripHeaders(headers=reqHead)
	log.debug("doAuthGetToken {}".format(reqHead))
	r = requests.get(url=appConfig.swift_auth_url, headers=reqHead)
	b = r.content
	h = dict(r.headers)
	s = r.status_code
	log.debug("got: {}, {}, {}".format(b, h, s))
	return (s, h)


def doGenericRequest(method, reqUrl, reqHead, reqArgs, reqData):
	reqHead = stripHeaders(headers=reqHead)
	r = requests.request(method=method, url=reqUrl, headers=reqHead, params=reqArgs, data=reqData)
	log.debug("doGeneric {}, url: {}, head: {}, args: {}, data: {}".format(method, reqUrl, reqHead, reqArgs, reqData))
	b = r.content
	h = dict(r.headers)
	s = r.status_code
	log.debug("doGeneric {} swift response: {}, {}, {}".format(method, s, h, b))
	return (s, h, b)
