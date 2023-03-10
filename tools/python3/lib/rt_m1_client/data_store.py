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
import json
import logging
import os
import os.path
from typing import Any

class DataStore:
    '''DataStore base class
    '''
    async def get(self, key: str, default: Any = None) -> Any:
        '''Get a persisted value by key name
        '''
        raise NotImplementedError('DataStore implementation should override this method')

    async def set(self, key: str, value: Any) -> bool:
        '''Store a persisted value using the key name
        '''
        raise NotImplementedError('DataStore implementation should override this method')

class JSONFileDataStore(DataStore):
    '''JSONFileDataStore class

    This class implements a DataStore as a set of files containing JSON.
    '''
    def __init__(self, data_store_dir: str):
        self.__dir = data_store_dir
        if not os.path.exists(self.__dir):
            os.makedirs(self.__dir)
        if not os.path.isdir(self.__dir):
            raise RuntimeError(f'{self.__dir} is not a directory')

    def __await__(self):
        return self.__self().__await__()

    async def __self(self):
        return self

    async def get(self, key: str, default: Any = None) -> Any:
        '''Get a persisted value by key name
        '''
        json_file = os.path.join(self.__dir, f'{key}.json')
        if not os.path.exists(json_file) or not os.path.isfile(json_file):
            return default
        with open(json_file, 'r') as json_in:
            val = json.load(json_in)
        return val

    async def set(self, key: str, value: Any) -> bool:
        '''Store a persisted value using the key name
        '''
        json_file = os.path.join(self.__dir, f'{key}.json')
        async with aiofiles.open(json_file, mode='w') as json_out:
            await json_out.write(json.dumps(value))
        return True
