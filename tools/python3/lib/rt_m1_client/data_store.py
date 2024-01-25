#!/usr/bin/python3
#==============================================================================
# 5G-MAG Reference Tools: M1 Session Persistent Data Store
#==============================================================================
#
# File: rt_m1_client/data_store.py
# License: 5G-MAG Public License (v1.0)
# Author: David Waring
# Copyright: (C) 2022 British Broadcasting Corporation
#
# For full license terms please see the LICENSE file distributed with this
# program. If this file is missing then the license can be retrieved from
# https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
#
#==============================================================================
#
# M1 Session DataStore classes
# ============================
#
# This module contains classes to implement a persistent data store for use by
# the M1Session class.
#
# There are 2 classes DataStore is the base class and JSONFileDataStore is an
# implementation which stores the persistent data objects as JSON objects.
#
'''5G-MAG Reference Tools: M1 Session DataStore classes
====================================================

The DataStore class provides a base class for storing persistent data using
a key string. This data can then be retrieved later so that the application can carry on where it left off.

The JSONFileDataStore class is an implementation that stores the data being
represented in JSON notation as a set of files.
'''
import aiofiles
import aiofiles.os
import json
import logging
import os
import os.path
from typing import Any

class DataStore:
    '''DataStore base class
    '''
    def __await__(self):
        '''Implement ``await`` on object creation

        This allows derived `DataStore` objects to perform asynchronous tasks on object instantiation.

        For example::
          data_store = await DataStore()

        This will await the `asyncInit()` method of this object.
        '''
        return self.asyncInit().__await__()

    async def asyncInit(self):
        '''Asynchronous DataStore initialisation

        Implementations should override this method to perform any object initialisation requiring asynchronous operations.

        This must always return *self*.

        :return: self
        '''
        return self

    async def get(self, key: str, default: Any = None) -> Any:
        '''Get a persisted value by key name

        :param str key: The key name to retrieve the `DataStore` value for.
        :param default: The default value to return if the key does not exist in the `DataStore`.

        :return: The value of the retrieved key or the *default* value.
        '''
        raise NotImplementedError('DataStore implementation should override this method')

    async def set(self, key: str, value: Any) -> bool:
        '''Store a persisted value using the key name

        :param str key: The key name to set a value for.
        :param value: The value to set.

        :return: ``True`` if the value was set in the `DataStore` or ``False`` if there was a failure.
        '''
        raise NotImplementedError('DataStore implementation should override this method')

class JSONFileDataStore(DataStore):
    '''JSONFileDataStore class

    This class implements a DataStore as a set of files containing JSON.
    '''
    def __init__(self, data_store_dir: str):
        '''Constructor

        :param str data_store_dir: The directory path to use for the JSON file data store.

        Please note that this object should be instantiated using ``await JSONFileDataStore(data_store_dir)`` as it has
        asynchronous initialisation to perform.
        '''
        self.__dir = data_store_dir

    async def asyncInit(self):
        '''Asynchronous JSONFileDataStore initialisation

        This will ensure that the data store directory for JSON files exists during instantiation.

        :return: self
        :raise RuntimeError: if the data store path already exists but is not a directory.
        '''
        if not await aiofiles.os.path.exists(self.__dir):
            old_umask = os.umask(0)
            try:
                await aiofiles.os.makedirs(self.__dir, mode=0o700)
            finally:
                os.umask(old_umask)
        if not await aiofiles.os.path.isdir(self.__dir):
            raise RuntimeError(f'{self.__dir} is not a directory')
        return self

    async def get(self, key: str, default: Any = None) -> Any:
        '''Get a persisted value by key name

        :param str key: The key name to retrieve the `DataStore` value for.
        :param default: The default value to return if the *key* does not exist in the `DataStore`.

        :return: The value of the retrieved key or the *default* value.
        '''
        json_file = os.path.join(self.__dir, f'{key}.json')
        if not await aiofiles.os.path.exists(json_file) or not await aiofiles.os.path.isfile(json_file):
            return default
        async with aiofiles.open(json_file, mode='r') as json_in:
            val = json.loads(await json_in.read())
        return val

    async def set(self, key: str, value: Any) -> bool:
        '''Store a persisted value using the key name

        :param str key: The key name to set a value for.
        :param value: The value to set.

        :return: ``True`` if the value was set in the `DataStore` or ``False`` if there was a failure.
        '''
        json_file = os.path.join(self.__dir, f'{key}.json')
        async with aiofiles.open(json_file, mode='w') as json_out:
            await json_out.write(json.dumps(value))
        return True
