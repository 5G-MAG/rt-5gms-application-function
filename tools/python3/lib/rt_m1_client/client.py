#!/usr/bin/python3
#==============================================================================
# 5G-MAG Reference Tools: M1 Client
#==============================================================================
#
# File: m1_client/client.py
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
# M1 Client class
# ===============
#
# This module contains an M1 Client written as a Python 3 class using asyncio.
#
'''5G-MAG Reference Tools: M1 Client class
=======================================

This class provides a simple interface for maintaining a connection to an M1
server, converting Python types to the various M1 requests, parsing the
responses and conversion back to Python types or Exceptions when errors have
occurred. This class will ensure that the out going request headers are
formatted according to 3GPP TS 26.512. Message bodies are passed through as
is and therefore it is the responsibility of the application using this class
to format the body correctly.

This class is not intended to maintain client state for an M1 session, that
should be performed outside of this class.
'''
import datetime
import json
import logging
from typing import Optional, Union, Tuple, Dict, Any, TypedDict

import httpx

from .exceptions import (M1ClientError, M1ServerError)
from .types import (ApplicationId, ContentHostingConfiguration, ContentProtocols,
                    ProvisioningSessionType, ProvisioningSession, ResourceId)

class TagAndDateResponse(TypedDict, total=False):
    '''Response containing ETag and Last-Modified headers
    '''
    ETag: str
    LastModified: datetime.datetime

class ProvisioningSessionResponse(TagAndDateResponse, total=False):
    '''Response containing a provisioning session object
    '''
    ProvisioningSessionId: ResourceId
    ProvisioningSession: ProvisioningSession

class ContentHostingConfigurationResponse(TagAndDateResponse, total=False):
    '''Response containing a content hosting configuration
    '''
    ProvisioningSessionId: ResourceId
    ContentHostingConfiguration: ContentHostingConfiguration

class ServerCertificateResponse(TagAndDateResponse, total=False):
    '''Response containing a server certificate
    '''
    ProvisioningSessionId: ResourceId
    ServerCertificateId: ResourceId
    ServerCertificate: str

class ServerCertificateSigningRequestResponse(TagAndDateResponse, total=False):
    '''Response containing a CSR for a reserved certificate
    '''
    ProvisioningSessionId: ResourceId
    ServerCertificateId: ResourceId
    CertificateSigningRequestPEM: str

class ContentProtocolsResponse(TagAndDateResponse, total=False):
    ProvisioningSessionId: ResourceId
    ContentProtocols: ContentProtocols

class M1Client:
    '''5G-MAG Reference Tools: M1 Client
    '''

    def __init__(self, host_address: Tuple[str,int]):
        '''
        Constructor

        host_address (tuple(str,int)) - 5GMS Application Function to connect to as a tuple of
                                        hostname/ip-addr and TCP port number.
        '''
        self.__host_address = host_address
        self.__connection = None
        self.__log = logging.getLogger(__name__)

    # TS26512_M1_ProvisioningSession

    async def createProvisioningSession(self, provisioning_session_type: ProvisioningSessionType,
                                        external_application_id: ApplicationId,
                                        asp_id: Optional[ApplicationId] = None
                                        ) -> Optional[ProvisioningSessionResponse]:
        '''
        Create a provisioning session on the 5GMS Application Function

        Parameters:
        provisioning_session_type (ProvisioningSessionType)
                The provisioning session type to create.
        external_application_id (str)
                The application ID of the external application requesting the new provisioning
                session.
        asp_id (optional str)
                The Application Server Provider ID.

        Returns the ResourceId of the allocated provisioning session or None if there was an error.

        Throws M1ClientError if there was a problem with the request and M1ServerError if there was
        a server side issue preventing the creation of the provisioning session.
        '''
        self.__debug('M1Client.createProvisioningSession(%r, %r, asp_id=%r)',
                     provisioning_session_type, external_application_id, asp_id)
        send: ProvisioningSession = {
                'provisioningSessionType': provisioning_session_type,
                'externalApplicationId': external_application_id
                }
        if asp_id is not None:
            send['aspId'] = asp_id
        result = await self.__do_request('POST', '/provisioning-sessions', json.dumps(send),
                                         'application/json')
        if result['status_code'] == 201:
            ret: ProvisioningSessionResponse = {'ProvisioningSessionId': result['headers']['location'].split('/')[-1]}
            if len(result['body']) > 0:
                ret.update(self.__tag_and_date(result))
                ret['ProvisioningSession'] = ProvisioningSession.fromJSON(result['body'])
            return ret
        self.__default_response(result)
        return None

    async def getProvisioningSessionById(self,
                                         provisioning_session_id: ResourceId
                                         ) -> Optional[ProvisioningSessionResponse]:
        '''
        Get a provisioning session from the 5GMS Application Function

        provisioning_session_id (ResourceId)
            The provisioning session to find.

        Returns a ProvisioningSession structure if the provisioning session was found, or None if
        the provisioning session was not found.

        Throws M1ClientError if there was a problem with the request and M1ServerError if there was
        a server side issue preventing the creation of the provisioning session.
        '''
        result = await self.__do_request('GET',
                                         '/provisioning-sessions/' + provisioning_session_id, '',
                                         'application/json')
        if result['status_code'] == 200:
            ret: ProvisioningSessionResponse = self.__tag_and_date(result)
            ret.update({
                    'ProvisioningSessionId': provisioning_session_id,
                    'ProvisioningSession': ProvisioningSession.fromJSON(result['body'])
                    })
            return ret
        if result['status_code'] == 404:
            return None
        self.__default_response(result)
        return None

    async def destroyProvisioningSession(self, provisioning_session_id: ResourceId) -> bool:
        '''
        Destroy a provisioning session on the 5GMS Application Function

        provisioning_session_id (ResourceId)
            The provisioning session to find.

        Returns True if a provisioning session was deleted or False if there was no action.

        Throws M1ClientError if there was a problem with the request and M1ServerError if there was
        a server side issue preventing the creation of the provisioning session.
        '''
        result = await self.__do_request('DELETE',
                                         '/provisioning-sessions/' + provisioning_session_id, '',
                                         'application/json')
        if result['status_code'] == 204:
            return True
        self.__default_response(result)
        return False

    # TS26512_M1_ContentHostingProvisioning

    async def createContentHostingConfiguration(self, provisioning_session_id: ResourceId,
                                        content_hosting_configuration: ContentHostingConfiguration
                                                ) -> Union[bool,ContentHostingConfigurationResponse]:
        '''
        Create a content hosting configuration for a provisioning session

        provisioning_session_id (ResourceId)
            The provisioning session to create the content hosting configuration in.
        content_hosting_configuration (ContentHostingConfiguration)
            The content hosting configuration template to use.
        '''
        result = await self.__do_request('POST',
                    f'/provisioning-sessions/{provisioning_session_id}/content-hosting-configuration',
                    json.dumps(content_hosting_configuration), 'application/json')
        if result['status_code'] == 201:
            if len(result['body']) > 0:
                ret: ContentHostingConfigurationResponse = self.__tag_and_date(result)
                ret.update({
                    'ProvisioningSessionId': provisioning_session_id,
                    })
                if len(result['body']) > 0:
                    ret.update({
                        'ContentHostingConfiguration': ContentHostingConfiguration.fromJSON(
                                result['body'])
                        })
                return ret
            return True
        self.__default_response(result)
        return False

    async def retrieveContentHostingConfiguration(self, provisioning_session_id: ResourceId
                                                  ) -> Optional[ContentHostingConfigurationResponse]:
        '''
        Fetch the content hosting configuration for a provisioning session

        provisioning_session_id (ResourceId)
            The provisioning session to fetch the current content hosting configuration for.

        Returns None if the provisioning session does not exist, also returns None if the
                provisioning session exists but does not have a content hosting configuration,
                otherwise returns the content hosting configuration and metadata.
        '''
        result = await self.__do_request('GET',
                    f'/provisioning-sessions/{provisioning_session_id}/content-hosting-configuration',
                                         '', 'application/json')
        if result['status_code'] == 200:
            ret: ContentHostingConfigurationResponse = self.__tag_and_date(result)
            ret.update({
                'ProvisioningSessionId': provisioning_session_id,
                'ContentHostingConfiguration': ContentHostingConfiguration.fromJSON(result['body'])
                })
            return ret
        if result['status_code'] == 404:
            return None
        self.__default_response(result)
        return None

    async def updateContentHostingConfiguration(self, provisioning_session_id: ResourceId,
                                        content_hosting_configuration: ContentHostingConfiguration
                                                ) -> Union[bool,ContentHostingConfigurationResponse]:
        '''
        Update a content hosting configuration for a provisioning session

        provisioning_session_id (ResourceId)
            The provisioning session to update the current content hosting configuration for.
        content_hosting_configuration (ContentHostingConfiguration)
            The new content hosting configuration to apply.

        Returns the content hosting configuration and metadata if the update succeeded and the new
                content hosting configuration was returned, or True if the update succeeded but no
                content hosting configuration was returned, or False if the update failed.
        '''
        result = await self.__do_request('PUT',
                    f'/provisioning-sessions/{provisioning_session_id}/content-hosting-configuration',

                                         str(content_hosting_configuration), 'application/json')
        if result['status_code'] == 204:
            if len(result['body']) > 0:
                ret: ContentHostingConfigurationResponse = self.__tag_and_date(result)
                ret.update({
                    'ProvisioningSessionId': provisioning_session_id,
                    'ContentHostingConfiguration': ContentHostingConfiguration.fromJSON(
                        result['body'])
                    })
                return ret
            return True
        if result['status_code'] == 404:
            return False
        self.__default_response(result)
        return False

    async def patchContentHostingConfiguration(self, provisioning_session_id: ResourceId, patch: str
                                               ) -> Union[bool,ContentHostingConfigurationResponse]:
        '''
        Patch a content hosting configuration for a provisioning session using a JSON patch

        provisioning_session_id (ResourceId)
            The provisioning session to update the current content hosting configuration for.
        patch (str)
            The patch information in JSON patch format.

        Returns the content hosting configuration and metadata if the patch succeeded and the new
                content hosting configuration was returned, or True if the patch succeeded but no
                content hosting configuration was returned, or False if the patch failed.
        '''
        result = await self.__do_request('PATCH',
                    f'/provisioning-sessions/{provisioning_session_id}/content-hosting-configuration',

                                         patch, 'application/json-patch+json')
        if result['status_code'] == 200:
            if len(result['body']) > 0:
                ret: ContentHostingConfigurationResponse = self.__tag_and_date(result)
                ret.update({
                    'ProvisioningSessionId': provisioning_session_id,
                    'ContentHostingConfiguration': ContentHostingConfiguration.fromJSON(
                        result['body'])
                    })
                return ret
            return True
        if result['status_code'] == 404:
            return False
        self.__default_response(result)
        return False

    async def destroyContentHostingConfiguration(self, provisioning_session_id: ResourceId
                                                 ) -> bool:
        '''
        Delete a content hosting configuration for a provisioning session

        provisioning_session_id (ResourceId)
            The provisioning session to remove the content hosting configuration for.

        Return True if the content hosting configuration was deleted or False if the content hosting
               configuration did not exist.
        '''
        result = await self.__do_request('DELETE',
                    f'/provisioning-sessions/{provisioning_session_id}/content-hosting-configuration',
                                         '', 'application/json')
        if result['status_code'] == 204:
            return True
        if result['status_code'] == 404:
            return False
        self.__default_response(result)
        return False

    async def purgeContentHostingCache(self, provisioning_session_id: ResourceId,
                                       filter_regex: Optional[str] = None) -> Optional[int]:
        '''
        Purge cache entries for a provisioning session

        provisioning_session_id (ResourceId)
            The provisioning session to purge cache entries for.
        filter_regex (str)
            Optional regular expression to match the cache entries origin URL path.

        Return the number of purged entries, or None if no purge took place.
        '''
        body = ''
        if filter_regex is not None:
            body = f'pattern={filter_regex}'
        result = await self.__do_request('POST',
              f'/provisioning-sessions/{provisioning_session_id}/content-hosting-configuration/purge',
              body, 'application/x-www-form-urlencoded')
        if result['status_code'] == 200:
            return int(result['body'])
        if result['status_code'] == 204:
            return None
        self.__default_response(result)
        return None

    # TS26512_M1_ServerCertificatesProvisioning

    async def createOrReserveServerCertificate(self, provisioning_session_id: ResourceId, csr=False) -> Optional[ServerCertificateSigningRequestResponse]:
        '''Create or reserve a server certificate for a provisioing session

        provisioning_session_id (ResourceId)
            The provisioning session to create the new certificate entry in.
        csr (bool)
            Whether to reserve a certificate and return the CSR PEM data.

        If csr is True then this will reserve the certificate and request the
        CSR PEM data be returned along side the Id of the newly reserved
        certificate.

        If csr is False or not provided then create a new certificate and just
        return the new certificate Id.

        Return a tuple containing the new certificate Id and an optional CSR
               PEM data string.
        '''

        url = f'/provisioning-sessions/{provisioning_session_id}/certificates'
        if csr:
            url += '?csr=true'
        result = await self.__do_request('POST', url, '', 'application/octet-stream')
        if result['status_code'] == 200:
            certificate_id = result['headers'].get('Location','').rsplit('/',1)[1]
            ret: ServerCertificateSigningRequestResponse = self.__tag_and_date(result)
            ret.update({
                'ProvisioningSessionId': provisioning_session_id,
                'ServerCertificateId': certificate_id,
                })
            if csr and len(result['body']) > 0:
                ret.update({
                    'CertificateSigningRequestPEM': result['body'],
                    })
            return ret
        self.__default_response(result)
        return None

    async def createServerCertificate(self, provisioning_session_id: ResourceId) -> ServerCertificateResponse:
        '''Create a new certificate for a provisioning session

        provisioning_session_id (ResourceId)
            The provisioning session to create the new certificate entry in.

        Returns the certificate Id of the newly created certificate.
        '''
        result = await self.createOrReserveServerCertificate(provisioning_session_id, csr=False)
        return result

    async def reserveServerCertificate(self, provisioning_session_id: ResourceId) -> ServerCertificateSigningRequestResponse:
        '''Reserve a certificate for a provisioning session and get the CSR PEM

        provisioning_session_id (ResourceId)
            The provisioning session to create the new certificate entry in.

        Returns a CSR as a PEM string plus metadata for the reserved certificate.
        '''
        result = await self.createOrReserveServerCertificate(provisioning_session_id, csr=True)
        if result is None or 'CertificateSigningRequestPEM' not in result:
            raise M1ClientError(reason = f'Failed to retrieve CSR for session {provisioning_session_id}', status_code = 200)
        return result

    async def uploadServerCertificate(self, provisioning_session_id: ResourceId, certificate_id: ResourceId, pem_data: str) -> bool:
        '''Upload the signed public certificate for a reserved certificate

        provisioning_session_id (ResourceId)
            The provisioning session the certificate was reserved for.
        certificate_id (ResourceId)
            The certificate Id of the reserved certificate.
        pem_data (str)
            A string containing the PEM data for the public certificate to
            upload.

        Returns True if successful or False if the certificate has already been
                uploaded.
        '''
        result = await self.__do_request('PUT',
              f'/provisioning-sessions/{provisioning_session_id}/certificates/{certificate_id}',
              pem_data, 'application/x-pem-file')
        if result['status_code'] == 204:
            return True
        self.__default_response(result)
        return False

    async def retrieveServerCertificate(self, provisioning_session_id: ResourceId, certificate_id: ResourceId) -> Optional[ServerCertificateResponse]:
        '''Retrieve the public certificate for a given certificate Id

        provisioning_session_id (ResourceId)
            The provisioning session for the certificate.
        certificate_id (ResourceId)
            The certificate Id of the certificate.

        Returns the PEM data for the public certificate and its metadata or
                None if the certificate is reserved and awaiting upload.

        Raises M1ClientError with status_code 404 if the certificate is not found.
        '''
        result = await self.__do_request('GET',
              f'/provisioning-sessions/{provisioning_session_id}/certificates/{certificate_id}',
              '', 'application/octet-stream')
        if result['status_code'] == 200:
            ret: ServerCertificateResponse = self.__tag_and_date(result)
            ret['ProvisioningSessionId'] = provisioning_session_id
            ret['ServerCertificateId'] = certificate_id
            ret['ServerCertificate'] = result['body']
            return ret
        if result['status_code'] == 204:
            return None
        if result['status_code'] == 404:
            raise M1ClientError(reason="Certificate not found", status_code=404)
        self.__default_response(result)
        return None

    async def destroyServerCertificate(self, provisioning_session_id: ResourceId, certificate_id: ResourceId) -> bool:
        '''Delete a certificate.

        provisioning_session_id (ResourceId)
            The provisioning session for the certificate.
        certificate_id (ResourceId)
            The certificate Id of the certificate.

        Returns True if the certificate has been deleted.
        '''
        result = await self.__do_request('DELETE',
              f'/provisioning-sessions/{provisioning_session_id}/certificates/{certificate_id}',
              '', 'application/octet-stream')
        if result['status_code'] == 204:
            return True
        self.__default_response(result)
        return False

    # TS26512_M1_ContentProtocolsDiscovery
    async def retrieveContentProtocols(self, provisioning_session_id: ResourceId) -> Optional[ContentProtocolsResponse]:
        '''Get the ContentProtocols information for the provisioning session

        provisioning_session_id (ResourceId)
            The provisioning session to get the ContentProtocols for.

        Returns a ContentProtocols structure and metadata.
        '''
        result = await self.__do_request('GET',
                f'/provisioning-sessions/{provisioning_session_id}/protocols',
                '', 'application/octet-stream')
        if result['status_code'] == 200:
            ret: ContentProtocolsResponse = self.__tag_and_date(result)
            ret['ContentProtocols'] = ContentProtocols.fromJSON(result['body'])
            return ret
        self.__default_response(result)
        return None

    # TS26512_M1_ConsumptionReportingProvisioning
    #async def activateConsumptionReporting(self, provisioning_session_id: ResourceId, consumption_reporting_config: ConsumptionReportingConfiguration) -> Optional[ResourceId]:
    #async def retrieveConsumptionReportingConfiguration(self, provisioning_session_id: ResourceId, consumption_reporting_id: ResourceId) -> ConsumptionReportingConfigurationResponse:
    #async def updateConsumptionReportingConfiguration(self, provisioning_session_id: ResourceId, consumption_reporting_config: ConsumptionReportingConfiguration) -> bool:
    #async def patchConsumptionReportingConfiguration(self, provisioning_session_id: ResourceId, patch: str) -> ConsumptionReportingConfigurationResponse:
    #async def destroyConsumptionReportingConfiguration(self, provisioning_session_id: ResourceId, consumption_reporting_id: ResourceId) -> bool:

    # TS26512_M1_ContentPreparationTemplatesProvisioning
    #async def createContentPreparationTemplate(self, provisioning_session_id: ResourceId, content_preparation_template: Any) -> Optional[ResourceId]:
    #async def retrieveContentPreparationTemplate(self, provisioning_session_id: ResourceId, content_preparation_template_id: ResourceId) -> ContentPreparationTemplateResponse:
    #async def updateContentPreparationTemplate(self, provisioning_session_id: ResourceId, content_preparation_template_id: ResourceId, content_preparation_template: Any) -> bool:
    #async def patchContentPreparationTemplate(self, provisioning_session_id: ResourceId, content_preparation_template_id: ResourceId, patch: str) -> ContentPreparationTemplateResponse:
    #async def destroyContentPreparationTemplate(self, provisioning_session_id: ResourceId, content_preparation_template_id: ResourceId) -> bool:

    # TS26512_M1_EdgeResourcesProvisioning
    #async def createEdgeResourcesConfiguration(self, provisioning_session_id: ResourceId, edge_resource_config: EdgeResourceConfiguration) -> Optional[ResourceId]:
    #async def retrieveEdgeResourcesConfiguration(self, provisioning_session_id: ResourceId, edge_resource_config_id: ResourceId) -> EdgeResourceConfigurationResponse:
    #async def updateEdgeResourcesConfiguration(self, provisioning_session_id: ResourceId, edge_resource_config_id: ResourceId, edge_resource_config: EdgeResourceConfiguration) -> bool:
    #async def patchEdgeResourcesConfiguration(self, provisioning_session_id: ResourceId, edge_resource_config_id: ResourceId, patch: str) -> EdgeResourceConfigurationResponse:
    #async def destroyEdgeResourcesConfiguration(self, provisioning_session_id: ResourceId, edge_resource_config_id: ResourceId) -> bool:

    # TS26512_M1_EventDataProcessingProvisioning
    #async def createEventDataProcessingConfiguration(self, provisioning_session_id: ResourceId, event_data_processing_config: EventDataProcessingConfiguration) -> Optional[ResourceId]:
    #async def retrieveEventDataProcessingConfiguration(self, provisioning_session_id: ResourceId, event_data_processing_config_id: ResourceId) -> EventDataProcessingConfigurationResponse:
    #async def updateEventDataProcessingConfiguration(self, provisioning_session_id: ResourceId, event_data_processing_config_id: ResourceId, event_data_processing_config: EventDataProcessingConfiguration) -> bool:
    #async def patchEventDataProcessingConfiguration(self, provisioning_session_id: ResourceId, event_data_processing_config_id: ResourceId, patch: str) -> EventDataProcessingConfigurationResponse:
    #async def destroyEventDataProcessingConfiguration(self, provisioning_session_id: ResourceId, event_data_processing_config_id: ResourceId) -> bool:

    # TS26512_M1_MetricsReportingProvisioning
    #async def activateMetricsReporting(self, provisioning_session_id: ResourceId, metrics_reporting_config: MetricsReportingConfiguration) -> ResourceId:
    #async def retrieveMetricsReportingConfiguration(self, provisioning_session_id: ResourceId, metrics_reporting_config_id: ResourceId) -> MetricsReportingConfigurationResponse:
    #async def updateMetricsReportingConfiguration(self, provisioning_session_id: ResourceId, metrics_reporting_config_id: ResourceId, metrics_reporting_config: MetricsReportingConfiguration) -> bool:
    #async def patchMetricsReportingConfiguration(self, provisioning_session_id: ResourceId, metrics_reporting_config_id: ResourceId, patch: str) -> MetricsReportingConfigurationResponse:
    #sync def destroyMetricsReportingConfiguration(self, provisioning_session_id: ResourceId, metrics_reporting_config_id: ResourceId) -> bool:

    # TS26512_M1_PolicyTemplatesProvisioning
    #async def createPolicyTemplate(self, provisioning_session_id: ResourceId, policy_template: PolicyTemplate) -> Optional[ResourceId]:
    #async def retrievePolicyTemplate(self, provisioning_session_id: ResourceId, policy_template_id: ResourceId) -> PolicyTemplateResponse:
    #async def updatePolicyTemplate(self, provisioning_session_id: ResourceId, policy_template_id: ResourceId, policy_template: PolicyTemplate) -> bool:
    #async def patchPolicyTemplate(self, provisioning_session_id: ResourceId, policy_template_id: ResourceId, patch: str) -> PolicyTemplateResponse:
    #async def destroyPolicyTemplate(self, provisioning_session_id: ResourceId, policy_template_id: ResourceId) -> bool:

    # Private methods

    async def __do_request(self, method: str, url_suffix: str, body: Union[str,bytes],
                           content_type: str, headers: Optional[dict] = None) -> Dict[str,Any]:
        '''Send a request to the 5GMS Application Function
        '''
        # pylint: disable=too-many-arguments
        if isinstance(body, str):
            body = bytes(body, 'utf-8')
        req_headers = {'Content-Type': content_type}
        if headers is not None:
            req_headers.update(headers)
        url = f'http://{self.__host_address[0]}:{self.__host_address[1]}/3gpp-m1/v2{url_suffix}'
        if self.__connection is None:
            self.__connection = httpx.AsyncClient(http1=True, http2=False,
                                                  headers={'User-Agent': '5GMS-AF/testing'})
        req = self.__connection.build_request(method, url, headers=req_headers, data=body)
        try:
            resp = await self.__connection.send(req)
        except httpx.RemoteProtocolError as err:
            raise M1ServerError(reason=f'Communication with the Application Function failed: {err}', status_code=500)
        return {'status_code': resp.status_code, 'body': resp.text, 'headers': resp.headers}

    def __default_response(self, result: Dict[str,Any]) -> None:
        '''Handle default actions for all responses from the 5GMS Application Function
        '''
        if result['status_code'] >= 400 and result['status_code'] < 500:
            raise M1ClientError(reason='M1 operation failed: '+str(result['body']),
                                status_code=result['status_code'])
        if result['status_code'] >= 500 and result['status_code'] < 600:
            raise M1ServerError(reason='M1 operation failed: '+str(result['body']),
                                status_code=result['status_code'])

    @staticmethod
    def __tag_and_date(result: Dict[str,Any]) -> TagAndDateResponse:
        ret = {'ETag': result['headers'].get('etag')}
        lm_dt = result['headers'].get('last-modified')
        if lm_dt is not None:
            try:
                lm_dt = datetime.datetime.strptime(lm_dt, '%a, %d %b %Y %H:%M:%S %Z').replace(
                        tzinfo=datetime.timezone.utc)
            except ValueError:
                try:
                    lm_dt = datetime.datetime.strptime(lm_dt, '%A, %d-%b-%y %H:%M:%S %Z').replace(
                            tzinfo=datetime.timezone.utc)
                except ValueError:
                    try:
                        lm_dt = datetime.datetime.strptime(lm_dt, '%a %b %d %H:%M:%S %Y').replace(
                                tzinfo=datetime.timezone.utc)
                    except ValueError:
                        lm_dt = None
        ret['Last-Modified'] = lm_dt
        return ret

    def __debug(self, *args, **kwargs):
        self.__log.debug(*args, **kwargs)

__all__ = [
        # Types
        'ProvisioningSessionResponse',
        'ContentHostingConfigurationResponse',
        'ServerCertificateResponse',
        'ServerCertificateSigningRequestResponse',
        'ContentProtocolsResponse',
        # Classes
        'M1Client',
        ]
