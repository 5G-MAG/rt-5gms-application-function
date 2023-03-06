#!/usr/bin/python3
#==============================================================================
# 5G-MAG Reference Tools: M1 Session
#==============================================================================
#
# File: rt_m1_client/session.py
# License: 5G-MAG Public License (v1.0)
# Author: David Waring
# Copyright: (C) 2023 British Broadcasting Corporation
#
# For full license terms please see the LICENSE file distributed with this
# program. If this file is missing then the license can be retrieved from
# https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
#
#==============================================================================
#
# M1 Session class
# ===============
#
# This module contains an M1 Session management class written in Python 3 using
# asyncio. This class uses an M1Client object to communicate with the 5GMS
# Application Function via the interface at reference point M1.
#
# The module will maintain a persistent list of provisioning sessions and assist
# in managing the resources for those provisioning sessions.
#
'''5G-MAG Reference Tools: M1 Session class
========================================

This class provides an interface for managing provisioning sessions on a 5GMS
Application Function.

This class uses the M1Client class to communicate with the 5GMS Application
Function via the interface at reference point M1.
'''
import logging
from typing import Optional, Union, Tuple, Dict, Any, TypedDict

from .exceptions import (M1ClientError, M1ServerError, M1Error)
from .types import (ApplicationId, ContentHostingConfiguration, ContentProtocols,
                    ProvisioningSessionType, ProvisioningSession, ResourceId)
from .client import (M1Client, ProvisioningSessionResponse, ContentHostingConfigurationResponse, ServerCertificateResponse, ServerCertificateSigningRequestResponse, ContentProtocolsResponse)
from .data_store import DataStore

class M1Session:
    '''M1 Session management class
    ===========================

    This class is used as the top level class to manage a communication session
    with the 5GMS Application Function.
    '''
    async def __init__(self, host_address: Tuple[str,int], persistent_data_store: Optional[DataStore] = None):
        self.__m1_host = host_address
        self.__data_store_dir = persistent_data_store
        self.__m1_client = None
        self.__provisioning_sessions = {}
        await self.__reloadFromDataStore()

    # Provisioning Session Management

    async def provisioningSessionIds(self):
        '''Get the list of current known provisioning session ids
        '''
        return self.__provisioning_sessions.keys()

    async def provisioningSessionProtocols(self, provisioning_session_id: ResourceId) -> Optional[ContentProtocols]:
        '''Get the ContentProtocols for the existing provisioning session
        '''
        if provisioning_session_id not in self.__provisioning_sessions:
            return None
        await self.__cacheProtocols(provisioning_session_id)
        return self.__provisioning_sessions[provisioning_session_id]['protocols']['ContentProtocols']

    async def provisioningSessionCertificateIds(self, provisioning_session_id: ResourceId) -> Optional[List[ResourceId]]:
        if provisioning_session_id not in self.__provisioning_sessions:
            return None
        await self.__cacheProvisioningSession(provisioning_session_id)
        ps = self.__provisioning_sessions[provisioning_session_id]['ProvisioningSession']
        if 'certificates' not in ps:
            return []
        return ps['certificates']

    async def provisioningSessionContentHostingConfiguration(self, provisioning_session_id: ResourceId) -> Optional[ContentHostingConfiguration]:
        if provisioning_session_id not in self.__provisioning_sessions:
            return None
        await self.__cacheContentHostingConfiguration(provisioning_session_id)
        ps = self.__provisioning_sessions[provisioning_session_id]
        chc_resp = ps['content-hosting-configuration']
        if chc_resp is None:
            return None
        chc = chc_resp['ContentHostingConfiguration']
        return chc

    async def provisioningSessionDestroy(self, provisioning_session_id: ResourceId) -> Optional[bool]:
        if provisioning_session_id not in self.__provisioning_sessions:
            return None
        await self.__connect()
        return await self.__m1_client.destroyProvisioningSession(prov_sess)

    # Certificates management

    async def certificateIds(self, provisioning_session_id: ResourceId) -> Optional[List[ResourceId]]:
        if provisioning_session_id not in self.__provisioning_sessions:
            return None
        await self.__cacheProvisioningSession(provisioning_session_id)
        ps = self.__provisioning_sessions[provisioning_session_id]['ProvisioningSession']
        if 'certificates' not in ps:
            return []
        return ps['certificates']

    async def newCertificate(self, provisioning_session_id: ResourceId) -> Optional[ResourceId]:


    async def newCertificateSigningRequest(self, provisioning_session_id: ResourceId) -> Optional[str]:

    # Private methods

    async def __reloadFromDataStore(self):
        if self.__data_store_dir is None:
            return

        sessions = self.__data_store_dir.get('provisioning_sessions');

        # Check the provisioning session still exist with the AF
        await self.__connect()
        to_remove = []
        for prov_sess in sessions:
            if await self.__m1_client.getProvisioningSessionById(prov_sess) is None:
                to_remove += [prov_sess]
        for prov_sess in to_remove:
            sessions.remove(prov_sess)

        # Populate provisioning session resource keys
        self.__provisioning_sessions = {}
        for prov_sess in sessions:
            self.__provisioning_sessions[prov_sess] = None
        
    async def __cacheResources(self):
        if len(self.__provisioning_sessions) == 0:
            return
        for prov_sess in self.__provisioning_sessions.keys():
            self.__cacheProvisioningSession(prov_sess)

    async def __cacheProvisioningSession(self, prov_sess: ResourceId):
        ps = self.__provisioning_sessions[prov_sess]
        now = datetime.datetime.now(datetime.timezone.utc)
        if ps is None or ps['cache-until'] is None or ps['cache-until'] < now:
            await self.__connect()
            result = await self.__m1_client.getProvisioningSessionById(prov_sess)
            if result is not None:
                ps.update(result)
                ps.update({
                    'protocols': None,
                    'content-hosting-configuration': None,
                    })

    async def __cacheProtocols(self, provisioning_session_id: ResourceId):
        await self.__cacheProvisioningSession(provisioning_session_id)
        ps = self.__provisioning_sessions[provisioning_session_id]
        now = datetime.datetime.now(datetime.timezone.utc)
        if ps['protocols'] is None or ps['protocols']['cache-until'] is None or ps['protocols']['cache-until'] < now:
            await self.__connect()
            result = await self.__m1_client.getContentProtocols(provisioning_session_id)
            if result is not None:
                ps['protocols'].update(result)

    async def __cacheContentHostingConfiguration(self, provisioning_session_id: ResourceId):
        await self.__cacheProvisioningSession(provisioning_session_id)
        ps = self.__provisioning_sessions[provisioning_session_id]
        now = datetime.datetime.now(datetime.timezone.utc)
        chc = ps['content-hosting-configuration']
        if chc is None or chc['cache-until'] is None or chc['cache-until'] < now:
            await self.__connect()
            result = await self.__m1_client.retrieveContentHostingConfiguration(provisioning_session_id)
            if result is not None:
                chc.update(result)
            else:
                ps['content-hosting-configuration'] = None

    async def __connect(self):
        if self.__m1_client is None:
            self.__m1_client = M1Client(self.__m1_host)

__all__ = [
        # Classes
        'M1Session',
        ]
