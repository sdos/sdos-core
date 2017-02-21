#!/usr/bin/python
# coding=utf-8

"""
	Project MCM - Micro Content Management
	SDOS - Secure Delete Object Store


	Copyright (C) <2016> Tim Waizenegger, <University of Stuttgart>

	This software may be modified and distributed under the terms
	of the MIT license.  See the LICENSE file for details.


	@author: tim

"""
import logging
from threading import Lock

from sdos.parallelExecution import Borg
from sdos.swift import SwiftBackend
from sdos.core import Frontend


class SwiftPool(Borg):
    """
        A singleton that manages a pool of swift connections per tenant/user
        only one instance of this class exists at any time -> only one swift connection per user
    """

    def __init__(self):
        Borg.__init__(self)

        try:
            self.__pool
        except:
            self.__pool = dict()

    def addConn(self, swiftTenant, swiftToken, conn):
        self.__pool[(swiftTenant, swiftToken)] = conn

    def getConn(self, swiftTenant, swiftToken):
        try:
            return self.__pool[(swiftTenant, swiftToken)]
        except KeyError:
            sb = SwiftBackend.SwiftBackend(tenant=swiftTenant, token=swiftToken)
            self.addConn(swiftTenant, swiftToken, sb)
            return sb


class FEPool(Borg):
    """
        A singleton that manages a pool of Frontends; i.e. key cascades with attached swift backends
        only one cascade exists per container/user combination
    """

    def __init__(self):
        Borg.__init__(self)

        try:
            self.__lock
        except:
            self.__lock = Lock()

        try:
            self.__pool
        except:
            self.__pool = dict()

    def addFE(self, container, swiftTenant, swiftToken, fe):
        # self.__pool[(container, swiftTenant, swiftToken)] = fe
        # TODO: multi-backend in the Key Cascade is necessary.
        # currently, we would re-use the first users token for all requests...
        self.__pool[(container, swiftTenant)] = fe

    def getFE(self, container, swiftTenant, swiftToken):
        logging.info(
            "looking for Frontend for: container {}, swiftTenant {}, swiftToken {}".format(container, swiftTenant,
                                                                                           swiftToken))
        logging.debug("Lock \/ acquiring")
        self.__lock.acquire()
        logging.debug("Lock || locked")
        try:
            sp = SwiftPool()
            swift_backend_current = sp.getConn(swiftTenant, swiftToken)
            sdos_frontend = self.__pool[(container, swiftTenant)]
            sdos_frontend.refresh_swift_backend(swift_backend_new=swift_backend_current)
            return sdos_frontend
        except KeyError:
            logging.info(
                "Frontend not found in pool, creating new for: container {}, swiftTenant {}, swiftToken {}".format(
                    container, swiftTenant,
                    swiftToken))

            fe = Frontend.frontendFactory(swift_backend_current, container)

            self.addFE(container, swiftTenant, swiftToken, fe)
            return fe
        finally:
            self.__lock.release()
            logging.debug("Lock /\ release CREATED NEW FE (probably...)")
