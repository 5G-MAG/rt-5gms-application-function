#!/usr/bin/python3
#==============================================================================
# 5G-MAG Reference Tools: M1 Session
#==============================================================================
#
# File: rt_m1_client/session.py
# License: 5G-MAG Public License (v1.0)
# Author: David Waring
# Copyright: (C) 2022-2023 British Broadcasting Corporation
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
import importlib
import inspect
import logging
import re
from typing import Optional, Union, Tuple, Dict, Any, TypedDict, List, Iterable

import OpenSSL

from .exceptions import (M1ClientError, M1ServerError, M1Error)
from .types import (ApplicationId, ContentHostingConfiguration, ContentProtocols, ProvisioningSessionType, ProvisioningSession,
                    ConsumptionReportingConfiguration, ResourceId, PolicyTemplate, PROVISIONING_SESSION_TYPE_DOWNLINK)
from .client import (M1Client, ProvisioningSessionResponse, ContentHostingConfigurationResponse, ServerCertificateResponse,
                     ServerCertificateSigningRequestResponse, ContentProtocolsResponse, ConsumptionReportingConfigurationResponse,
                     PolicyTemplateResponse)
from .data_store import DataStore
from .certificates import CertificateSigner, DefaultCertificateSigner

class M1Session:
    '''M1 Session management class
    ===========================

    This class is used as the top level class to manage a communication session with the 5GMS Application Function. It will
    communicate using the `M1Client` class with the M1 Server (5GMS Application Function) and cache the results to improve
    efficiency. It can also use a `DataStore` to provide persistence of information across different sessions, and can use a
    `CertificateSigner` to perform signing of certificates when ``domainNameAlias`` is used.
    '''

    def __init__(self, host_address: Tuple[str,int], persistent_data_store: Optional[DataStore] = None, certificate_signer: Optional[Union[CertificateSigner,type,str]] = None):
        '''Constructor

        :param host_address: A tuple containing the M1 server (5GMS Application Function) hostname/ip-address and TCP port number
                             to contact it at.
        :param persistent_data_store: A `DataStore` object to use to provide persistent storage.
        :param certificate_signer: A `CertificateSigner` to use when signing certificates with extra domain names. This can be either a `str` containing the full Python class name, a `CertificateSigner` class to instantiate if needed, or an instance of a `CertificateSigner` to use. If not given then ``rt_m1_client.certificates.DefaultCertificateSigner`` is used.
        '''
        self.__m1_host = host_address
        self.__data_store_dir = persistent_data_store
        self.__cert_signer = certificate_signer
        self.__m1_client = None
        self.__provisioning_sessions = {}
        self.__ca_key = None
        self.__ca = None
        self.__log = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def __await__(self):
        '''``await`` provider for asynchronous instansiation.
        '''
        return self.__asyncInit().__await__()

    async def __asyncInit(self):
        '''Asynchronous object instantiation

        Loads previous state from the DataStore.

        :meta private:
        :return: self
        '''
        await self.__reloadFromDataStore()
        return self

    # Provisioning Session Management

    async def provisioningSessionIds(self) -> Iterable:
        '''Get the list of current known provisioning session ids

        :return: an iterable for the provisioning session ids.
        '''
        return self.__provisioning_sessions.keys()

    async def provisioningSessionProtocols(self, provisioning_session_id: ResourceId) -> Optional[ContentProtocols]:
        '''Get the ContentProtocols for the existing provisioning session

        :param ResourceId provisioning_session_id: The provisioning session to get `ContentProtocols` for.
        :return: a `ContentProtocols` for the provisioning session or ``None`` if the `ContentProtocols` could not be found.
        '''
        if provisioning_session_id not in self.__provisioning_sessions:
            return None
        await self.__cacheProtocols(provisioning_session_id)
        return self.__provisioning_sessions[provisioning_session_id]['protocols']['contentprotocols']

    async def provisioningSessionCertificateIds(self, provisioning_session_id: ResourceId) -> Optional[List[ResourceId]]:
        '''Get the list of certificate Ids for a provisioning session

        :param ResourceId provisioning_session_id: The provisioning session id to get the certificate ids for.
        :return: a list of certificate ids associated with the *provisioning_session_id* or ``None`` if they could not be found.
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

        :param ResourceId provisioning_session_id: The provisioning session id to get the `ContentHostingConfiguration` for.
        :return: ``None`` if the provisioning session does not exist or if there is no `ContentHostingConfiguration` associated
                 with the provisioning session, otherwise return the `ContentHostingConfiguration`.
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
        '''Destroy a provisioning session

        :param provisioning_session_id: The provisioning session id of the session to destroy.
        :return: ``True`` if the provisioning session was destroyed, ``False`` if it could not be destroyed or ``None`` if the
                 provisioning session does not exist.
        '''
        if provisioning_session_id not in self.__provisioning_sessions:
            return None
        await self.__connect()
        result = await self.__m1_client.destroyProvisioningSession(provisioning_session_id)
        if result:
            del self.__provisioning_sessions[provisioning_session_id]
            if self.__data_store_dir:
                await self.__data_store_dir.set('provisioning_sessions', list(self.__provisioning_sessions.keys()))
            return True
        return False

    async def provisioningSessionCreate(self, prov_type: ProvisioningSessionType, app_id: ApplicationId, asp_id: Optional[ApplicationId] = None) -> Optional[ResourceId]:
        '''Create a provisioning session

        The *prov_type* should be `rt_m1_client.types.PROVISIONING_SESSION_TYPE_DOWNLINK` or
        `rt_m1_client.types.PROVISIONING_SESSION_TYPE_UPLINK`. The *app_id* is the mandatory external application id, and the
        *asp_id* is the optional ASP identfier.

        :param prov_type: The provisioning session type, either `PROVISIONING_SESSION_TYPE_DOWNLINK` or
                          `PROVISIONING_SESSION_TYPE_UPLINK`.
        :param app_id: This is the External Application Id.
        :param asp_id: This is the optional Application Service Provider Id.

        :return: the provisioning session id for the new provisioning session or ``None`` if the `ProvisioningSession` could not
                 be created.
        '''
        await self.__connect()
        prov_sess_resp: Optional[ProvisioningSessionResponse] = await self.__m1_client.createProvisioningSession(prov_type, app_id, asp_id)
        if prov_sess_resp is None:
            self.__log.debug("provisioningSessionCreate: no response")
            return None
        ps_id = prov_sess_resp['ProvisioningSessionId']
        # Register the provisioning session id
        self.__provisioning_sessions[ps_id] = None
        # Store in the `DataStore` if available
        if self.__data_store_dir:
            await self.__data_store_dir.set('provisioning_sessions', list(self.__provisioning_sessions.keys()))
        return ps_id

    async def provisioningSessionIdByIngestUrl(self, ingesturl: str, entrypoint: Optional[str] = None) -> Optional[ResourceId]:
        ret = None
        for ps_id in self.__provisioning_sessions.keys():
            await self.__cacheContentHostingConfiguration(ps_id)
            ps = await self.__getProvisioningSessionCache(ps_id)
            if ps is None or ps['content-hosting-configuration'] is None:
                continue
            if ps['content-hosting-configuration']['contenthostingconfiguration']['ingestConfiguration']['baseURL'] == ingesturl:
                entry_points = [dc['entryPoint'] for dc in ps['content-hosting-configuration']['contenthostingconfiguration']['distributionConfigurations'] if 'entryPoint' in dc]
                entry_point_paths = [e['relativePath'] for e in entry_points]
                if (entrypoint is None and len(entry_point_paths) == 0) or (entrypoint is not None and entrypoint in entry_point_paths):
                    ret = ps_id
                    break
        return ret

    # Certificates management

    async def certificateIds(self, provisioning_session_id: ResourceId) -> Optional[List[ResourceId]]:
        '''Get a list of certificate Ids

        :param provisioning_session_id: The provisioning session id to retrieve certificate ids for.
        :return: a list of certificate ids or ``None`` if the provisioning session doesn't exist or cannot be retrieved.
        '''
        if provisioning_session_id not in self.__provisioning_sessions:
            return None
        await self.__cacheProvisioningSession(provisioning_session_id)
        ps = self.__provisioning_sessions[provisioning_session_id]['provisioningsession']
        if 'serverCertificateIds' not in ps:
            return []
        return ps['serverCertificateIds']

    async def certificateCreate(self, provisioning_session_id: ResourceId) -> Optional[ResourceId]:
        '''Create a new certificate

        This creates a new M1 Server signed certificate in the provisioning session and returns the new certificate id.

        :param provisioning_session_id: The provisioning session to create the new certificate in.

        :return: the certificate id of the new certificate or ``None`` if the provisioning session does not exist or if there was
                 no response from the M1 Server.
        '''
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
                # create certificates cache
                ps['certificates'] = {cert_id: {k.lower(): v for k,v in cert_resp.items()}}
            elif cert_id not in ps['certificates'] or ps['certificates'][cert_id] is None:
                # Store new certificate info
                ps['certificates'][cert_id] = {k.lower(): v for k,v in cert_resp.items()}
            else:
                # Update the certificate info
                if cert_resp['ServerCertificate'] is None:
                    cert_resp['ServerCertificate'] = ps['certificates'][cert_id]['servercertificate']
                ps['certificates'][cert_id] = {k.lower(): v for k,v in cert_resp.items()}

        return cert_id

    async def certificateGet(self, provisioning_session_id: ResourceId, certificate_id: ResourceId) -> Optional[str]:
        '''Retrieve a public certificate

        :param provisioning_session_id: The provisioning session id to use to look up the certificate.
        :param certificate_id: The certificate id for the certificate in the provisioning session.

        :return: The PEM string for the public certificate or ``None`` if the certificate could not be found.
        '''
        ret_err = None
        if provisioning_session_id not in self.__provisioning_sessions:
            return None
        try:
            await self.__cacheCertificates(provisioning_session_id)
        except M1Error as err:
            # This error may happen for a different certificate, so just remember it for now
            ret_err = err
        ps = self.__provisioning_sessions[provisioning_session_id]
        # If the certificate does not exist return None
        if 'certificates' not in ps or ps['certificates'] is None or certificate_id not in ps['certificates']:
            return None
        # If there was an error caching certificates and this certificate failed to cache then forward the exception
        if ret_err is not None and ps['certificates'][certificate_id]['servercertificate'] is None:
            raise ret_err
        # Return the cached certificate
        return ps['certificates'][certificate_id]['servercertificate']

    async def certificateNewSigningRequest(self, provisioning_session_id: ResourceId, extra_domain_names: Optional[List[str]] = None) -> Optional[Tuple[ResourceId,str]]:
        '''Create a new CSR for a provisioning session

        This reserves a new certificate in the provisioning session and returns the new certificate id and CSR PEM string.
        It is the responsibility of the caller to generate a signed public certificate from the CSR and post it back to the M1
        Server using the `certificateSet` method.

        :param provisioning_session_id: The provisioning session to reserve the new certificate in.
        :param extra_domain_names: An optional list of extra domain names to add as SubjectAltName entries in a CSR.

        :return: a tuple of certificate id and CSR PEM string for the new certificate or ``None`` if the provisioning session does
                 not exist or if there was no response from the M1 Server.
        '''
        if provisioning_session_id not in self.__provisioning_sessions:
            return None
        await self.__connect()
        cert_resp: ServerCertificateSigningRequestResponse = await self.__m1_client.reserveServerCertificate(
                provisioning_session_id, extra_domain_names=extra_domain_names)
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

    async def certificateSet(self, provisioning_session_id: ResourceId, certificate_id: ResourceId, pem: str) -> Optional[bool]:
        '''Set the public certificate for a reserved certificate in a provisioning session

        This is used to provide a signed public certificate to the M1 Server after reserving the certificate with
        `certificateNewSigningRequest`. This can only be done once per certificate reservation, once the public certificate is set
        then further updates to it are not allowed.

        :param provisioning_session_id: The provisioning session id of the provisioning session to upload the certificate to.
        :param certificate_id: The certificate id in the provisioning session to upload the certificate to.
        :param pem: The public certificate as a PEM string to be uploaded.

        :return: ``True`` if the certificate was set, ``False`` if it has already been set and ``None`` if the provisioning
                 session or certificate id was not found.
        '''
        if provisioning_session_id not in self.__provisioning_sessions:
            return None
        await self.__connect()
        return await self.__m1_client.uploadServerCertificate(provisioning_session_id, certificate_id, pem)

    # ContentHostingConfiguration methods

    async def contentHostingConfigurationCreate(self, provisioning_session: ResourceId, chc: ContentHostingConfiguration) -> bool:
        '''Store a new `ContentHostingConfiguration` for a provisioning session

        :param provisioning_session: The provisioning session id of the provisioning session to set the
                                     `ContentHostingConfiguration` in.
        :param chc: The `ContentHostingConfiguration` to set in the provisioning session.
        :return: ``True`` if the new `ContentHostingConfiguration` was successfully set in the provisioning session or ``False`` if
                 the operation failed (e.g. because there was already a `ContentHostingConfiguration` set).
        '''
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
        '''Retrieve the `ContentHostingConfiguration` set on a provisioning session

        :param provisioning_session: The provisioning session id to retrieve the `ContentHostingConfiguration` for.

        :return: a `ContentHostingConfiguration` for the provisioning session or ``None`` if the provisioning session does not
                 exist or if it has no `ContentHostingConfiguration` set.
        '''
        if provisioning_session not in self.__provisioning_sessions:
            return None
        await self.__cacheContentHostingConfiguration(provisioning_session)
        ps = await self.__getProvisioningSessionCache(provisioning_session)
        if ps is None or ps['content-hosting-configuration'] is None:
            return None
        return ContentHostingConfiguration(ps['content-hosting-configuration']['contenthostingconfiguration'])

    async def contentHostingConfigurationUpdate(self, provisioning_session: ResourceId, chc: ContentHostingConfiguration) -> bool:
        '''Update the `ContentHostingConfiguration` for a provisioning session

        :param provisioning_session: The provisioning session id of the provisioning session to set the
                                     `ContentHostingConfiguration` in.
        :param chc: The `ContentHostingConfiguration` to set in the provisioning session.
        :return: ``True`` if the new `ContentHostingConfiguration` was successfully set in the provisioning session or ``False`` if
                 the operation failed (e.g. because there was no `ContentHostingConfiguration` set).
        '''
        if provisioning_session not in self.__provisioning_sessions:
            return False
        await self.__connect()
        return await self.__m1_client.updateContentHostingConfiguration(provisioning_session, chc)

    # ConsumptionReportingConfiguration methods

    async def consumptionReportingConfigurationCreate(self, provisioning_session: ResourceId, crc: ConsumptionReportingConfiguration) -> bool:
        '''Store a new `ConsumptionReportingConfiguration` for a provisioning session

        :param provisioning_session: The provisioning session id of the provisioning session to set the
                                     `ConsumptionReportingConfiguration` in.
        :param crc: The `ConsumptionReportingConfiguration` to set in the provisioning session.
        :return: ``True`` if the new `ConsumptionReportingConfiguration` was successfully set in the provisioning session or
                 ``False`` if the operation failed (e.g. because there was already a `ConsumptionReportingConfiguration` set).
        '''
        if provisioning_session not in self.__provisioning_sessions:
            return False
        await self.__connect()
        crc_resp: Union[bool,ConsumptionReportingConfigurationResponse,None] = \
                await self.__m1_client.activateConsumptionReportingConfiguration(provisioning_session, crc)
        if isinstance(crc_resp,bool):
            return crc_resp
        ps = await self.__getProvisioningSessionCache(provisioning_session)
        if ps is not None:
            ps['consumption-reporting-configuration'] = {k.lower(): v for k,v in crc_resp.items()}
        return True

    async def consumptionReportingConfigurationGet(self, provisioning_session: ResourceId) -> Optional[ConsumptionReportingConfiguration]:
        '''Retrieve the `ConsumptionReportingConfiguration` set on a provisioning session

        :param provisioning_session: The provisioning session id to retrieve the `ConsumptionReportingConfiguration` for.

        :return: a `ConsumptionReportingConfiguration` for the provisioning session or ``None`` if the provisioning session does not
                 exist or if it has no `ConsumptionReportingConfiguration` set.
        '''
        if provisioning_session not in self.__provisioning_sessions:
            return None
        await self.__cacheConsumptionReportingConfiguration(provisioning_session)
        ps = await self.__getProvisioningSessionCache(provisioning_session)
        if ps is None or ps['consumption-reporting-configuration'] is None:
            return None
        return ConsumptionReportingConfiguration(ps['consumption-reporting-configuration']['consumptionreportingconfiguration'])

    async def consumptionReportingConfigurationUpdate(self, provisioning_session: ResourceId, crc: ConsumptionReportingConfiguration) -> bool:
        '''Update the `ConsumptionReportingConfiguration` for a provisioning session

        :param provisioning_session: The provisioning session id of the provisioning session to set the
                                     `ConsumptionReportingConfiguration` in.
        :param chc: The `ConsumptionReportingConfiguration` to set in the provisioning session.
        :return: ``True`` if the new `ConsumptionReportingConfiguration` was successfully set in the provisioning session or
                 ``False`` if the operation failed (e.g. because there was no `ConsumptionReportingConfiguration` set).
        '''
        if provisioning_session not in self.__provisioning_sessions:
            return False
        await self.__connect()
        return await self.__m1_client.updateConsumptionReportingConfiguration(provisioning_session, crc)

    async def consumptionReportingConfigurationDelete(self, provisioning_session: ResourceId) -> bool:
        '''Remove the `ConsumptionReportingConfiguration` for a provisioning session

        :param provisioning_session: The provisioning session id of the provisioning session to remove the
                                     `ConsumptionReportingConfiguration` in.

        :return: ``True`` if the `ConsumptionReportingConfiguration` was successfully removed or ``False`` if the operation failed.
        '''
        if provisioning_session not in self.__provisioning_sessions:
            return False
        await self.__connect()
        return await self.__m1_client.destroyConsumptionReportingConfiguration(provisioning_session)

    # PolicyTemplate methods

    async def policyTemplateIds(self, provisioning_session_id: ResourceId) -> Optional[List[ResourceId]]:
        '''Get a list of policy template Ids

        :param provisioning_session_id: The provisioning session id to retrieve policy template ids for.
        :return: a list of policy template ids or ``None`` if the provisioning session doesn't exist or cannot be retrieved.
        '''
        if provisioning_session_id not in self.__provisioning_sessions:
            return None
        await self.__cacheProvisioningSession(provisioning_session_id)
        ps = self.__provisioning_sessions[provisioning_session_id]['provisioningsession']
        if 'policyTemplateIds' not in ps:
            return []
        return ps['policyTemplateIds']

    async def policyTemplateCreate(self, provisioning_session_id: ResourceId, policy_template: PolicyTemplate) -> Optional[ResourceId]:
        '''Create a new policy template

        This creates a new policy template in the provisioning session and returns the new policy template id.

        :param provisioning_session_id: The provisioning session to create the new policy template in.
        :param policy_template: The policy template to create.

        :return: the policy template id of the new policy template or ``None`` if the provisioning session does not exist or if
                 there was no response from the M1 Server.
        '''
        if provisioning_session_id not in self.__provisioning_sessions:
            return None
        await self.__connect()
        pol_resp: Optional[PolicyTemplateResponse] = await self.__m1_client.createPolicyTemplate(provisioning_session_id, policy_template)
        if pol_resp is None:
            return None
        pol_id = pol_resp['PolicyTemplate']['policyTemplateId']
        ps = await self.__getProvisioningSessionCache(provisioning_session_id)
        if ps is not None:
            if 'policyTemplates' not in ps or ps['policyTemplates'] is None:
                # create policy template cache
                ps['policyTemplates'] = {pol_id: {k.lower(): v for k,v in pol_resp.items()}}
            elif pol_id not in ps['policyTemplates'] or ps['policyTemplates'][pol_id] is None:
                # Store new policy template info
                ps['policyTemplates'][pol_id] = {k.lower(): v for k,v in pol_resp.items()}
            else:
                # Update the policy template info
                if pol_resp['PolicyTemplate'] is None:
                    pol_resp['PolicyTemplate'] = ps['policyTemplates'][pol_id]['policytemplate']
                ps['policyTemplates'][pol_id] = {k.lower(): v for k,v in pol_resp.items()}

        return pol_id

    async def policyTemplateGet(self, provisioning_session_id: ResourceId, policy_template_id: ResourceId) -> Optional[PolicyTemplate]:
        '''Retrieve a policy template

        '''
        if provisioning_session_id not in self.__provisioning_sessions:
            return None
        await self.__cachePolicyTemplates(provisioning_session_id)
        ps = self.__provisioning_sessions[provisioning_session_id]
        if ps is None or 'policyTemplates' not in ps or ps['policyTemplates'] is None or policy_template_id not in ps['policyTemplates']:
            return None
        return PolicyTemplate(ps['policyTemplates'][policy_template_id]['policytemplate'])

    async def policyTemplateUpdate(self, provisioning_session_id: ResourceId, policy_template_id: ResourceId, policy_template: PolicyTemplate) -> Optional[bool]:
        '''Update a policy template

        '''
        if provisioning_session_id not in self.__provisioning_sessions:
            return False
        await self.__connect()
        return await self.__m1_client.updatePolicyTemplate(provisioning_session_id, policy_template_id, policy_template)

    async def policyTemplateDelete(self, provisioning_session_id: ResourceId, policy_template_id: ResourceId) -> bool:
        '''Delete a policy template

        '''
        if provisioning_session_id not in self.__provisioning_sessions:
            return False
        await self.__connect()
        return await self.__m1_client.destroyPolicyTemplate(provisioning_session_id, policy_template_id)

    # Convenience methods

    async def createDownlinkPullProvisioningSession(self, app_id: ApplicationId, asp_id: Optional[ApplicationId] = None) -> Optional[ResourceId]:
        '''Create a downlink provisioning session

        :param app_id: The mandatory external application id for the provisioning session.
        :param asp_id: The optional ASP id for the provisioning session.
        :return: the new provisioning session id or ``None`` if creation failed.
        '''
        return await self.provisioningSessionCreate(PROVISIONING_SESSION_TYPE_DOWNLINK, app_id, asp_id)

    async def createNewCertificate(self, provisioning_session: ResourceId, extra_domain_names: Optional[List[str]] = None) -> Optional[ResourceId]:
        '''Create a new certificate

        This will create a new certificate for the provisioning session. If *domain_name_alias* is not given this will leave
        creation of the certificate up to the M1 server (5GMS Application Function). If *extra_domain_names* is given, is not
        ``None`` and contains at least one entry then this will reserve a certificate for the provisioning session, sign the CSR
        using the local `CertificateSigner` object and set the signed public certificate for the provisioning session.

        :param provisioning_session: The provisioning session id of the provisioning session to create the certificate in.
        :param extra_domain_names: An optional list of domain names to add as extra SubjectAltName entries.
        :return: The certificate id of the newly created certificate or ``None`` if the certificate could not be created.
        '''
        # simple case just create the certificate
        if extra_domain_names is not None and isinstance(extra_domain_names, bytes):
            extra_domain_names = extra_domain_names.decode('utf-8')
        if extra_domain_names is not None and isinstance(extra_domain_names, str):
            if len(extra_domain_names) > 0:
                extra_domain_names = [extra_domain_names]
            else:
                extra_domain_names = None
        if extra_domain_names is not None and len(extra_domain_names) == 0:
            extra_domain_names = None
        if extra_domain_names is None:
            return await self.certificateCreate(provisioning_session)
        # When domainNameAlias is used we need to use a CSR
        csr: Optional[Tuple[ResourceId,str]] = await self.certificateNewSigningRequest(provisioning_session,extra_domain_names=extra_domain_names)
        if csr is None:
            return None
        cert_id = csr[0]
        csr_pem = csr[1]
        cert_signer = await self.__getCertificateSigner()
        cert: Optional[str] = await cert_signer.signCertificate(csr_pem)
        if cert is None:
            self.__log.error('Failed to generate certificate with domainNameAlias')
            return None
        # Send new cert to the AF
        if not await self.certificateSet(provisioning_session, cert_id, cert):
            self.__log.error('Failed to upload certificate with domainNameAlias')
            return None
        return cert_id

    async def createNewDownlinkPullStream(self, ingesturl: str, app_id: ApplicationId, entrypoints: Optional[List[str]] = None, name: Optional[str] = None, asp_id: Optional[ApplicationId] = None, ssl: bool = False, insecure: bool = True, domain_name_alias: Optional[str] = None) -> ResourceId:
        '''Create a new downlink pull stream

        This will create a new provisioning session, reserve any necessary certificates (if *ssl* is requested) and set the
        `ContentHostingConfiguration`.

        The provisioning session is created with the *app_id* and *asp_id* provided.

        If *ssl* is ``True`` then a certificate will be created in the new provisioning session. This certificate will use the
        *domain_name_alias* if set.

        The `ContentHostingConfiguration` set in the new provisioning session is created from the *ingesturl*, *entrypoint* and
        *name* and will contain a ``distributionConfiguration`` for an HTTP distribution if *insecure* is ``True`` (the default)
        and an HTTPS distribution, using the new certificate, if *ssl* is ``True`` (default is no HTTPS).

        :param ingesturl: The ingest URL for the `ContentHostingConfiguration` to create.
        :param app_id: The external application id for creatation of the provisioning session.
        :param entrypoints: Optional list of ``distributionConfiguration.entryPoint.relativePath`` for the
                            `ContentHostingConfiguration`.
        :param name: Optional ``name`` for the `ContentHostingConfiguration`.
        :param asp_id: Optional Application Service Provider Id for creating the provisioning session.
        :param ssl: If ``True`` include an HTTPS ``distributionConfiguration`` in the `ContentHostingConfiguration`.
        :param insecure: If ``True`` include an HTTP ``distributionConfiguration`` in the `ContentHostingConfiguration`.
        :param domain_name_alias: Optional ``domainNameAlias`` to include in the ``distributionConfiguration`` in the
                                  `ContentHostingConfiguration`.

        :return: The provisioning session id
        :raise RuntimeError: if the creation of provisioning session, certificate or content hosting configuration fails.
        '''
        self.__log.debug(f'createNewDownlinkPullStream(ingesturl={ingesturl!r}, app_id={app_id!r}, entrypoints={entrypoints!r}, name={name!r}, asp_id={asp_id!r}, ssl={ssl!r}, insecure={insecure!r}, domain_name_alias={domain_name_alias!r})')
        # Abort if bad parameters
        if not ssl and not insecure:
            raise RuntimeError('Cannot create a stream without HTTP and HTTPS distributions.')
        # Create a new provisioning session
        provisioning_session: ResourceId = await self.provisioningSessionCreate(PROVISIONING_SESSION_TYPE_DOWNLINK, app_id, asp_id)
        if provisioning_session is None:
            raise RuntimeError('Failed to create a provisioning session')
        # Create an SSL certificate if requested
        if ssl:
            cert: Optional[ResourceId] = await self.createNewCertificate(provisioning_session, extra_domaqin_names=[domain_name_alias])
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
        if entrypoints is None or len(entrypoints) == 0:
            entrypoints = [None]
        for ep in entrypoints:
            if ssl and cert is not None:
                dc = {'certificateId': cert}
                if domain_name_alias is not None:
                    dc['domainNameAlias'] = domain_name_alias
                if ep is not None:
                    dc['entryPoint'] = {'relativePath': ep, 'contentType': await self.__pathToContentType(ep)}
                chc['distributionConfigurations'] += [dc]
            if insecure:
                dc = {}
                if domain_name_alias is not None:
                    dc['domainNameAlias'] = domain_name_alias
                if ep is not None:
                    dc['entryPoint'] = {'relativePath': ep, 'contentType': await self.__pathToContentType(ep)}
                chc['distributionConfigurations'] += [dc]
        if not await self.contentHostingConfigurationCreate(provisioning_session, chc):
            raise RuntimeError('Failed to create the content hosting configuration')
        return provisioning_session

    async def setOrUpdateConsumptionReporting(self, provisioning_session: ResourceId, crc: ConsumptionReportingConfiguration) -> bool:
        '''Set or update the consumption reporting parameters for a provisioning session

        :param ResourceId provisioning_session: The provisioning session to set the consumption report on.
        :param ConsumptionReportingConfiguration crc: The ConsumptionReportingConfiguration to set.

        :return: ``True`` if the configuration was set or ``False`` if the setting failed.
        '''
        if provisioning_session not in self.__provisioning_sessions:
            return False
        await self.__cacheConsumptionReportingConfiguration(provisioning_session)
        ps = await self.__getProvisioningSessionCache(provisioning_session)
        if ps is None or ps['consumption-reporting-configuration'] is None:
            return await self.consumptionReportingConfigurationCreate(provisioning_session, crc)
        return await self.consumptionReportingConfigurationUpdate(provisioning_session, crc)

    # Private data

    __file_suffix_to_mime = {
            'mpd': 'application/dash+xml',
            'm3u8': 'application/vnd.apple.mpegurl',
            }

    __regex_to_mime = [
            (re.compile(r'mpd'), 'application/dash+xml'),
            (re.compile(r'm3u8'), 'application/vnd.apple.mpegurl'),
            (re.compile(r'dash', re.IGNORECASE), 'application/dash+xml'),
            (re.compile(r'hls', re.IGNORECASE), 'application/vnd.apple.mpegurl'),
            ]

    # Private methods

    async def __pathToContentType(self, path: str) -> str:
        self.__log.debug(f'__pathToContentType({path!r})')
        type_map = {
                'mpd': 'application/dash+xml',
                'm3u8': 'application/vnd.apple.mpegurl',
                }
        suffix = path.rsplit('.',1)[-1]
        if suffix in self.__file_suffix_to_mime:
            return self.__file_suffix_to_mime[suffix]
        for regexp, ctype in self.__regex_to_mime:
            if regexp.search(path) is not None:
                return ctype
        return 'application/octet-stream'

    async def __reloadFromDataStore(self) -> None:
        '''Reload persistent information from the DataStore

        Checks the provisioning session ids retrieved from the DataStore against the M1 server and will delete any that are no
        longer available.

        :meta private:
        :return: None
        '''
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
        '''Find a provisioning session cache

        :meta private:
        :param provisioning_session_id: The provisioning session id to get the cache for.
        :return: The cache `dict` or ``None`` if the cache doesn't exist.
        '''
        if provisioning_session_id not in self.__provisioning_sessions:
            return None
        await self.__cacheProvisioningSession(provisioning_session_id)
        return self.__provisioning_sessions[provisioning_session_id]

    async def __cacheResources(self) -> None:
        '''Cache the provisioning session resources lists

        Caches the provisioning session information for each known provisioning session
        '''
        if len(self.__provisioning_sessions) == 0:
            return
        for prov_sess in self.__provisioning_sessions.keys():
            self.__cacheProvisioningSession(prov_sess)

    async def __cacheProvisioningSession(self, prov_sess: ResourceId) -> None:
        '''Cache the provisioning session resource lists for a provisioning session

        Will only cache if the old cache didn't exist or has expired.

        :meta private:
        :param prov_sess: The id of provisioning session to cache.
        '''
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
                    'consumption-reporting-configuration': None,
                    'certificates': None,
                    'policyTemplates': None,
                    })
                # initialise ServerCertificates cache with the available IDs
                if 'serverCertificateIds' in ps['provisioningsession']:
                    ps['certificates'] = {k: None for k in ps['provisioningsession']['serverCertificateIds']}
                # initialise PolicyTemplate cache with the available IDs
                if 'policyTemplateIds' in ps['provisioningsession']:
                    ps['policyTemplates'] = {k: None for k in ps['provisioningsession']['policyTemplateIds']}

    async def __cacheProtocols(self, provisioning_session_id: ResourceId):
        '''Cache the ContentProtocols for a provisioning session

        Will only cache if the old cache didn't exist or has expired.

        :meta private:
        :param provisioning_session_id: The id of provisioning session to cache the `ContentProtocols` for.
        '''
        await self.__cacheProvisioningSession(provisioning_session_id)
        ps = self.__provisioning_sessions[provisioning_session_id]
        now = datetime.datetime.now(datetime.timezone.utc)
        if ps['protocols'] is None or ps['protocols']['cache-until'] is None or ps['protocols']['cache-until'] < now:
            await self.__connect()
            result = await self.__m1_client.retrieveContentProtocols(provisioning_session_id)
            if result is not None:
                if ps['protocols'] is None:
                    ps['protocols'] = {}
                ps['protocols'].update({k.lower(): v for k,v in result.items()})

    async def __cacheCertificates(self, provisioning_session_id: ResourceId):
        '''Cache all public certificates for the provisioning session

        Will only cache if the old cache didn't exist or has expired.

        :meta private:
        :param provisioning_session_id: The id of provisioning session to cache the public certificates for.
        '''
        await self.__cacheProvisioningSession(provisioning_session_id)
        ps = self.__provisioning_sessions[provisioning_session_id]
        now = datetime.datetime.now(datetime.timezone.utc)
        if ps['certificates'] is None:
            return
        ret_err = None
        for cert_id,cert in list(ps['certificates'].items()):
            if cert is None:
                cert = {'etag': None, 'last-modified': None, 'cache-until': None, 'servercertificateid': cert_id,
                        'servercertificate': None}
                ps['certificates'][cert_id] = cert
            if cert['cache-until'] is None or cert['cache-until'] < now:
                await self.__connect()
                try:
                    result = await self.__m1_client.retrieveServerCertificate(provisioning_session_id, cert_id)
                    if result is not None:
                        cert.update({k.lower(): v for k,v in result.items()})
                except M1Error as err:
                    if ret_err is None:
                        ret_err = err
        if ret_err is not None:
            raise ret_err

    async def __cacheContentHostingConfiguration(self, provisioning_session_id: ResourceId) -> None:
        '''Cache the `ContentHostingConfiguration` for a provisioning session

        Will only cache if the old cache didn't exist or has expired.

        :meta private:
        :param provisioning_session_id: The id of provisioning session to cache the `ContentHostingConfiguration` for.
        '''
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

    async def __cacheConsumptionReportingConfiguration(self, provisioning_session_id: ResourceId) -> None:
        '''Cache the `ConsumptionReportingConfiguration` for a provisioning session

        Will only cache if the old cache didn't exist or has expired.

        :meta private:
        :param provisioning_session_id: The id of provisioning session to cache the `ConsumptionReportingConfiguration` for.
        '''
        await self.__cacheProvisioningSession(provisioning_session_id)
        ps = self.__provisioning_sessions[provisioning_session_id]
        now = datetime.datetime.now(datetime.timezone.utc)
        crc = ps['consumption-reporting-configuration']
        if crc is None or crc['cache-until'] is None or crc['cache-until'] < now:
            await self.__connect()
            result: Optional[ConsumptionReportingConfigurationResponse] = \
                    await self.__m1_client.retrieveConsumptionReportingConfiguration(provisioning_session_id)
            if result is not None:
                if crc is None:
                    crc = {}
                    ps['consumption-reporting-configuration'] = crc
                crc.update({k.lower(): v for k,v in result.items()})
            else:
                ps['consumption-reporting-configuration'] = None

    async def __cachePolicyTemplates(self, provisioning_session_id: ResourceId):
        '''Cache all policy templates for the provisioning session

        Will only cache if the old cache didn't exist or has expired.

        :meta private:
        :param provisioning_session_id: The id of provisioning session to cache the policy templates for.
        '''
        await self.__cacheProvisioningSession(provisioning_session_id)
        ps = self.__provisioning_sessions[provisioning_session_id]
        now = datetime.datetime.now(datetime.timezone.utc)
        if ps is None or 'policyTemplates' not in ps or ps['policyTemplates'] is None:
            return
        ret_err = None
        for pol_id,pol in list(ps['policyTemplates'].items()):
            if pol is None:
                pol = {'etag': None, 'last-modified': None, 'cache-until': None, 'policytemplate': None}
                ps['policyTemplates'][pol_id] = pol
            if pol['cache-until'] is None or pol['cache-until'] < now:
                await self.__connect()
                try:
                    result = await self.__m1_client.retrievePolicyTemplate(provisioning_session_id, pol_id)
                    if result is not None:
                        pol.update({k.lower(): v for k,v in result.items()})
                except M1Error as err:
                    if ret_err is None:
                        ret_err = err
        if ret_err is not None:
            raise ret_err

    async def __getCertificateSigner(self) -> CertificateSigner:
        '''Get the `CertificateSigner`

        Creates the CertificateSigner object if we don't already have one.

        :meta private:
        :return: a `CertificateSigner`
        :raise RuntimeError: if the certificate signer requested is not derived from `CertificateSigner`.
        '''
        signer_args = {}
        if self.__cert_signer is None:
            self.__cert_signer = 'rt_m1_client.certificates.DefaultCertificateSigner'
        if isinstance(self.__cert_signer, str):
            if '(' in self.__cert_signer:
                self.__cert_signer, args_str = self.__cert_signer.split('(',1)
                args_str = args_str[:-1]
                signer_args = dict([tuple([p.strip() for p in kv.split('=')]) for kv in args_str.split(',')])
            cert_sign_cls_mod, cert_sign_cls_name = self.__cert_signer.rsplit('.', 1)
            cert_sign_cls_mod = importlib.import_module(cert_sign_cls_mod)
            self.__cert_signer = getattr(cert_sign_cls_mod, cert_sign_cls_name)
        try:
            if inspect.isclass(self.__cert_signer) and issubclass(self.__cert_signer, CertificateSigner):
                self.__cert_signer = await self.__cert_signer(data_store=self.__data_store_dir, **signer_args)
        except TypeError:
            pass
        if inspect.iscoroutinefunction(self.__cert_signer):
            self.__cert_signer = await self.__cert_signer(data_store=self.__data_store_dir, **signer_args)
        if not isinstance(self.__cert_signer, CertificateSigner):
            raise RuntimeError('The certificate signer class given is not derived from CertificateSigner')
        return self.__cert_signer

    async def __connect(self) -> None:
        '''Connect to the M1Client

        :meta private:
        '''
        if self.__m1_client is None:
            self.__m1_client = M1Client(self.__m1_host)

    def _dump_state(self) -> None:
        '''Dump the current provisioning session cache to the log
        '''
        self.__log.debug(repr(self.__provisioning_sessions))

__all__ = [
        # Classes
        'M1Session',
        ]
