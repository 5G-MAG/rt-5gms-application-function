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
import datetime
import logging
from typing import Optional, Union, Tuple, Dict, Any, TypedDict, List

from .exceptions import (M1ClientError, M1ServerError, M1Error)
from .types import (ApplicationId, ContentHostingConfiguration, ContentProtocols, ProvisioningSessionType, ProvisioningSession,
                    ResourceId, PROVISIONING_SESSION_TYPE_DOWNLINK)
from .client import (M1Client, ProvisioningSessionResponse, ContentHostingConfigurationResponse, ServerCertificateResponse,
                     ServerCertificateSigningRequestResponse, ContentProtocolsResponse)
from .data_store import DataStore

class M1Session:
    '''M1 Session management class
    ===========================

    This class is used as the top level class to manage a communication session
    with the 5GMS Application Function.
    '''
    def __init__(self, host_address: Tuple[str,int], persistent_data_store: Optional[DataStore] = None):
        self.__m1_host = host_address
        self.__data_store_dir = persistent_data_store
        self.__m1_client = None
        self.__provisioning_sessions = {}
        self.__log = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def __await__(self):
        return self.__asyncInit().__await__()

    async def __asyncInit(self):
        await self.__reloadFromDataStore()
        return self

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
        return self.__provisioning_sessions[provisioning_session_id]['protocols']['contentprotocols']

    async def provisioningSessionCertificateIds(self, provisioning_session_id: ResourceId) -> Optional[List[ResourceId]]:
        '''Get the list of certificate Ids for a provisioning session
        '''
        if provisioning_session_id not in self.__provisioning_sessions:
            return None
        await self.__cacheProvisioningSession(provisioning_session_id)
        ps = self.__provisioning_sessions[provisioning_session_id]['provisioningsession']
        if 'certificates' not in ps:
            return []
        return ps['certificates']

    async def provisioningSessionContentHostingConfiguration(self, provisioning_session_id: ResourceId) -> Optional[ContentHostingConfiguration]:
        '''Get the ContentHostingConfiguration associated with the provisioning session

        Returns None if the provisioning session does not exist or if there is no ContentHostingConfiguration associated with the
                provisioning session.
        '''
        if provisioning_session_id not in self.__provisioning_sessions:
            return None
        await self.__cacheContentHostingConfiguration(provisioning_session_id)
        ps = self.__provisioning_sessions[provisioning_session_id]
        chc_resp = ps['content-hosting-configuration']
        if chc_resp is None:
            # Nothing got cached from the AF, probably an error, but no CHC found
            return None
        chc = chc_resp['ContentHostingConfiguration']
        return chc

    async def provisioningSessionDestroy(self, provisioning_session_id: ResourceId) -> Optional[bool]:
        if provisioning_session_id not in self.__provisioning_sessions:
            return None
        await self.__connect()
        result = await self.__m1_client.destroyProvisioningSession(prov_sess)
        if result:
            del self.__provisioning_sessions[provisioning_session_id]
            if self.__data_store_dir:
                await self.__data_store_dir.set('provisioning_sessions', list(self.__provisioning_sessions.keys()))

    async def provisioningSessionCreate(self, prov_type: ProvisioningSessionType, app_id: ApplicationId, asp_id: ApplicationId):
        await self.__connect()
        prov_sess_resp: ProvisioningSessionResponse = await self.__m1_client.createProvisioningSession(prov_type, app_id, asp_id)
        if prov_sess_resp is None:
            self.__log.debug("provisioningSessionCreate: no response")
            return None
        ps_id = prov_sess_resp['ProvisioningSessionId']
        self.__provisioning_sessions[ps_id] = None
        if self.__data_store_dir:
            await self.__data_store_dir.set('provisioning_sessions', list(self.__provisioning_sessions.keys()))
        return ps_id

    # Certificates management

    async def certificateIds(self, provisioning_session_id: ResourceId) -> Optional[List[ResourceId]]:
        if provisioning_session_id not in self.__provisioning_sessions:
            return None
        await self.__cacheProvisioningSession(provisioning_session_id)
        ps = self.__provisioning_sessions[provisioning_session_id]['provisioningsession']
        if 'serverCertificateIds' not in ps:
            return []
        return ps['serverCertificateIds']

    async def certificateCreate(self, provisioning_session_id: ResourceId) -> Optional[ResourceId]:
        if provisioning_session_id not in self.__provisioning_sessions:
            return None
        await self.__connect()
        cert_resp: ServerCertificateResponse = await self.__m1_client.createServerCertificate(provisioning_session_id)
        if cert_resp is None:
            return None
        cert_id = cert_resp['ServerCertificateId']
        ps = await self.__getProvisioningSessionCache(provisioning_session_id)
        if ps is not None:
            if 'certificates' not in ps or ps['certificates'] is None:
                ps['certificates'] = [cert_id]
            elif cert_id not in ps['certificates']:
                ps['certificates'] += [cert_id]
        return cert_id

    async def certificateNewSigningRequest(self, provisioning_session_id: ResourceId) -> Optional[Tuple[ResourceId,str]]:
        if provisioning_session_id not in self.__provisioning_sessions:
            return None
        await self.__connect()
        cert_resp: ServerCertificateSigningRequestResponse = await self.__m1_client.reserveServerCertificate(
                provisioning_session_id)
        if cert_resp is None:
            return None
        cert_id = cert_resp['ServerCertificateId']
        ps = await self.__getProvisioningSessionCache(provisioning_session_id)
        if ps is not None:
            if 'certificates' not in ps or ps['certificates'] is None:
                ps['certificates'] = [cert_id]
            elif cert_id not in ps['certificates']:
                ps['certificates'] += [cert_id]
        return (cert_id,cert_resp['CertificateSigningRequestPEM'])

    # ContentHostingConfiguration methods

    async def contentHostingConfigurationCreate(self, provisioning_session: ResourceId, chc: ContentHostingConfiguration) -> bool:
        if provisioning_session not in self.__provisioning_sessions:
            return False
        await self.__connect()
        chc_resp: Union[bool,ContentHostingConfigurationResponse] = await self.__m1_client.createContentHostingConfiguration(
                provisioning_session, chc)
        if isinstance(chc_resp,bool):
            return chc_resp
        ps = await self.__getProvisioningSessionCache(provisioning_session)
        if ps is not None:
            ps['content-hosting-configuration'] = {k.lower(): v for k,v in chc_resp.items()}
        return True

    async def contentHostingConfigurationGet(self, provisioning_session: ResourceId) -> Optional[ContentHostingConfiguration]:
        if provisioning_session not in self.__provisioning_sessions:
            return None
        await self.__cacheContentHostingConfiguration(provisioning_session)
        ps = await self.__getProvisioningSessionCache(provisioning_session)
        if ps is None:
            return None
        return ContentHostingConfiguration(ps['content-hosting-configuration']['contenthostingconfiguration'])

    # Convenience methods

    async def createNewDownlinkPullStream(self, ingesturl, entrypoint, app_id, name=None, asp_id=None, ssl=False, insecure=True):
        # Create a new provisioning session
        provisioning_session: ResourceId = await self.provisioningSessionCreate(PROVISIONING_SESSION_TYPE_DOWNLINK, app_id, asp_id)
        if provisioning_session is None:
            raise RuntimeError('Failed to create a provisioning session')
        # Create an SSL certificate if requested
        if ssl:
            cert: Optional[ResourceId] = await self.certificateCreate(provisioning_session)
            if cert is None:
                if insecure:
                    self.__log.warn('Failed to create hosting with HTTPS, continuing with just HTTP')
                else:
                    raise RuntimeError('Failed to create hosting, unable to create SSL certificate')
        # If no name given, generate one
        if name is None:
            name = self.__next_auto_stream_name()
        # Build and send the ContentHostingConfiguration
        chc: ContentHostingConfiguration = {
                'name': name,
                'ingestConfiguration': {
                    'pull': True,
                    'protocol': 'urn:3gpp:5gms:content-protocol:http-pull-ingest',
                    'baseURL': ingesturl,
                    },
                'distributionConfigurations': []
                }
        if ssl and cert is not None:
            chc['distributionConfigurations'] += [{'certificateId': cert}]
        if insecure:
            chc['distributionConfigurations'] += [{}]
        if entrypoint is not None:
            chc['entryPointPath'] = entrypoint
        if not await self.contentHostingConfigurationCreate(provisioning_session, chc):
            raise RuntimeError('Failed to create the content hosting configuration')
        return True

    # Private methods

    async def __reloadFromDataStore(self):
        if self.__data_store_dir is None:
            return

        sessions = await self.__data_store_dir.get('provisioning_sessions');
        if sessions is None:
            return

        # Check the provisioning session still exist with the AF
        await self.__connect()
        to_remove = []
        for prov_sess in sessions:
            if await self.__m1_client.getProvisioningSessionById(prov_sess) is None:
                to_remove += [prov_sess]
        if len(to_remove) > 0:
            for prov_sess in to_remove:
                sessions.remove(prov_sess)
            if self.__data_store_dir:
                await self.__data_store_dir.set('provisioning_sessions', sessions)

        # Populate provisioning session resource keys
        self.__provisioning_sessions = {}
        for prov_sess in sessions:
            self.__provisioning_sessions[prov_sess] = None
        
    async def __getProvisioningSessionCache(self, provisioning_session_id: ResourceId) -> Optional[dict]:
        if provisioning_session_id not in self.__provisioning_sessions:
            return None
        await self.__cacheProvisioningSession(provisioning_session_id)
        return self.__provisioning_sessions[provisioning_session_id]

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
                if ps is None:
                    ps = {}
                    self.__provisioning_sessions[prov_sess] = ps
                ps.update({k.lower(): v for k,v in result.items()})
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
                ps['protocols'].update({k.lower(): v for k,v in result.items()})

    async def __cacheContentHostingConfiguration(self, provisioning_session_id: ResourceId):
        await self.__cacheProvisioningSession(provisioning_session_id)
        ps = self.__provisioning_sessions[provisioning_session_id]
        now = datetime.datetime.now(datetime.timezone.utc)
        chc = ps['content-hosting-configuration']
        if chc is None or chc['cache-until'] is None or chc['cache-until'] < now:
            await self.__connect()
            result = await self.__m1_client.retrieveContentHostingConfiguration(provisioning_session_id)
            if result is not None:
                if chc is None:
                    chc = {}
                    ps['content-hosting-configuration'] = chc
                chc.update({k.lower(): v for k,v in result.items()})
            else:
                ps['content-hosting-configuration'] = None

    async def __connect(self):
        if self.__m1_client is None:
            self.__m1_client = M1Client(self.__m1_host)
            
    def _dump_state(self):
        self.__log.debug(repr(self.__provisioning_sessions))

__all__ = [
        # Classes
        'M1Session',
        ]
