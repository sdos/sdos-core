#!/usr/bin/python
# coding=utf-8

"""
	Project MCM - Micro Content Management
	SDOS - Secure Delete Object Store


	Copyright (C) <2017> Tim Waizenegger, <University of Stuttgart>

	This software may be modified and distributed under the terms
	of the MIT license.  See the LICENSE file for details.
"""

import io
import logging
import threading



class KeyPartitionCache(object):
    """
    Caching and loading of nodes
    This class may be used as a wrapper for the regular CascadePersistance class
    """

    def __init__(self, partitionStore):
        """
        Constructor
        """
        self.partitionStore = partitionStore
        self.partitionCache = dict()
        self.__dirty_partitions = set()
        self.__watch_and_store_partitions()

    def writePartition(self, partitionId, by):
        logging.debug("writing partition to cache: {}".format(partitionId))
        self.partitionCache[partitionId] = by.getbuffer()
        self.__dirty_partitions.add(partitionId)


    def readPartition(self, partitionId):
        logging.debug("reading partition from cache: {}".format(partitionId))

        if partitionId in self.partitionCache:
            logging.debug("partition found in cache: {}".format(partitionId))
        else:
            logging.warning("partition NOT found in cache: {}".format(partitionId))
            by = self.partitionStore.readPartition(partitionId)
            if not by:
                return None
            self.partitionCache[partitionId] = by.getbuffer()
        return io.BytesIO(self.partitionCache[partitionId])


    def __watch_and_store_partitions(self):
        logging.debug("checking for dirty partitions in cache: {} found".format(len(self.__dirty_partitions)))
        while self.__dirty_partitions:
            pid = self.__dirty_partitions.pop()
            logging.info("flushing modified partition from cache: {}".format(pid))
            try:
                self.partitionStore.writePartition(pid, io.BytesIO(self.partitionCache[pid]))
            except Exception:
                self.__dirty_partitions.add(pid)
                logging.exception("storing changed partition failed!")
        threading.Timer(10, self.__watch_and_store_partitions).start()


