#!/usr/bin/python
# coding=utf-8

"""
	Project MCM - Micro Content Management
	SDOS - Secure Delete Object Store


	Copyright (C) <2017> Tim Waizenegger, <University of Stuttgart>

	This software may be modified and distributed under the terms
	of the MIT license.  See the LICENSE file for details.
"""
import math
import logging


class CascadeProperties(object):
    def __init__(self, partition_bits=8, tree_height=2):
        """
        	Key Cascade geometry / parameters
        	PARTITION_BITS8 # 256 slots for 8 bit, 4 slots for 2 bit
        	TREE_HEIGHT # height doesn't include the root
        	BYTES_FOR_NAME_LENGTH = 2  # allows names to be 65536 characters long
        """
        b = int(partition_bits)
        h = int(tree_height)
        self.__validate_properties(b, h)

        self.PARTITION_BITS = b
        self.TREE_HEIGHT = h
        self.BYTES_FOR_NAME_LENGTH = 2

        ###############################################################################
        """
        	Derived properties
        """
        self.PARTITION_SIZE = 2 ** self.PARTITION_BITS  # 256 slots for 8 bit
        self.NUMBER_OF_OBJECT_KEY_PARTITIONS = self.PARTITION_SIZE ** self.TREE_HEIGHT
        self.NUMBER_OF_SLOTS_IN_OBJECT_KEY_PARTITIONS = self.PARTITION_SIZE ** (self.TREE_HEIGHT + 1)
        self.NUMBER_OF_PARTITION_KEY_PARTITIONS = math.floor(
            ((self.PARTITION_SIZE ** self.TREE_HEIGHT) - 1) / (self.PARTITION_SIZE - 1))
        self.TOTAL_NUMER_OF_PARTITIONS = self.NUMBER_OF_OBJECT_KEY_PARTITIONS + self.NUMBER_OF_PARTITION_KEY_PARTITIONS
        self.BYTES_FOR_PARTITION_IDs = math.ceil(int.bit_length(self.TOTAL_NUMER_OF_PARTITIONS) / 8)
        self.FIRST_OBJECT_KEY_SLOT = self.TOTAL_NUMER_OF_PARTITIONS
        self.LAST_OBJCT_KEY_SLOT = self.FIRST_OBJECT_KEY_SLOT + self.NUMBER_OF_SLOTS_IN_OBJECT_KEY_PARTITIONS - 1
        self.BYTES_FOR_SLOT_IDS = math.ceil(int.bit_length(self.LAST_OBJCT_KEY_SLOT) / 8)
        self.MAX_NAME_LENGTH = 2 ** (self.BYTES_FOR_NAME_LENGTH * 8)

        logging.info('Initializing new Cascade properties...')
        logging.info('partition bits: {}'.format(self.PARTITION_BITS))
        logging.info('partitions have {} slots'.format(self.PARTITION_SIZE))
        logging.info('cascade height without root: {}'.format(self.TREE_HEIGHT))
        logging.info(
            'total number of partitions: {}, number of internal partitions {}'.format(self.TOTAL_NUMER_OF_PARTITIONS,
                                                                                      self.NUMBER_OF_PARTITION_KEY_PARTITIONS))
        logging.info('number of object key partitions (leaves) is {}, they have a total of {} key slots'.format(
            self.NUMBER_OF_OBJECT_KEY_PARTITIONS, self.NUMBER_OF_SLOTS_IN_OBJECT_KEY_PARTITIONS))
        logging.info(
            'object key IDs are in the range {}..{}'.format(self.FIRST_OBJECT_KEY_SLOT, self.LAST_OBJCT_KEY_SLOT))

    def __validate_properties(self, partition_bits, tree_height):
        if not (partition_bits > 0 and partition_bits < 32 and tree_height > 0 and tree_height < 64):
            raise ValueError(
                "Cascade properties invalid: partition_bits {} -- tree_height {}".format(partition_bits, tree_height))
