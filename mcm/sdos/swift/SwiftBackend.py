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
import swiftclient
import io
from mcm.sdos import configuration


class SwiftBackend(object):
    """
    classdocs
    """

    def __init__(self, tenant=None, token=None, user=None, key=None):
        """
        we take either an existing authentication, or create a new one.
        in SDOS-service mode, tenant/token are used since AUTH is already handled by the client.
        user/key are only used for tests
        """
        self.log = logging.getLogger(__name__)
        self.log.debug('initializing...')
        self.swiftC = None

        if tenant and token:
            self.set_existing_authentication(tenant=tenant, token=token)
        elif user and key:
            self.authenticate(user=user, key=key)
        self._assertConnection()

    ###############################################################################
    ###############################################################################

    def set_existing_authentication(self, tenant, token):
        self.swiftC = swiftclient.client.Connection(preauthtoken=token,
                                                    preauthurl=configuration.swift_store_url.format(tenant),
                                                    retries=5,
                                                    timeout=10,
                                                    insecure='true')

    def authenticate(self, user, key):
        self.log.debug('establishing NEW connection')
        self.swiftC = swiftclient.client.Connection(authurl=configuration.swift_auth_url,
                                                    user=user,
                                                    key=key,
                                                    retries=5,
                                                    timeout=10,
                                                    insecure='true')

    def _assertConnection(self):
        if not self.swiftC: raise AttributeError(
            'no swift connection object present. Maybe the swift backend was not properly initialized.')

    ###############################################################################
    ###############################################################################

    def printStatus(self):
        self.log.info('status: ')

    def assert_valid_auth(self):
        self._assertConnection()
        self.swiftC.head_account()

    def putObject(self, container, name, dataObject, headers={}):
        self.log.debug('putting file to swift: {}'.format(name))
        self._assertConnection()
        rsp = dict()
        self.swiftC.put_object(container=container, obj=name, contents=dataObject, response_dict=rsp, headers=headers)

    def getObject(self, container, name):
        self.log.debug('getting file from swift: {}'.format(name))
        self._assertConnection()
        rsp = dict()
        t = self.swiftC.get_object(container=container, obj=name, resp_chunk_size=None, query_string=None,
                                   response_dict=rsp, headers=None)
        o = io.BytesIO(t[1])
        return o

    def deleteObject(self, container, name):
        self.log.debug('deleting file from swift: {}'.format(name))
        self._assertConnection()
        rsp = dict()
        self.swiftC.delete_object(container=container, obj=name, query_string=None, response_dict=rsp)

    def create_container_if_not_exists(self, container):
        self.log.debug('create_container_if_not_exists: {}'.format(container))
        self._assertConnection()
        try:
            self.swiftC.post_container(container=container, headers={})
        except swiftclient.exceptions.ClientException:
            self.swiftC.put_container(container=container, headers={})

    def is_sdos_container(self, containerName):
        self.log.debug('checking for SDOS flag presence on container: {}'.format(containerName))
        self._assertConnection()
        t = self.swiftC.head_container(containerName)
        return t.get("x-container-meta-sdos", False) == "True"

    def get_sdos_properties(self, containerName):
        """
        we read the tree height and partition-bits from the container in order to init the Key Cascade
        :param containerName:
        :return: (is_sdos, height, part_bits)
        """
        self.log.debug('checking for SDOS properties on container: {}'.format(containerName))
        self._assertConnection()
        t = self.swiftC.head_container(containerName)
        r = (
            t.get("x-container-meta-sdos", False) == "True",
            int(t.get("x-container-meta-sdospartitionbits", 0)),
            int(t.get("x-container-meta-sdosheight", 0)),
            t.get("x-container-meta-sdosmasterkey", 0),
            t.get("x-container-meta-sdosbatchdelete", False) == "True"
        )
        return r
