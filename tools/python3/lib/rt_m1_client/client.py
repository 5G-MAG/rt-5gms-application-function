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
from typing import Optional, Union, Tuple, Dict, Any, TypedDict, List

import httpx

from .exceptions import (M1ClientError, M1ServerError)
from .types import (ApplicationId, ContentHostingConfiguration, ContentProtocols,
                    ConsumptionReportingConfiguration,
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
    '''Response containing a ContentProtocols object
    '''
    ProvisioningSessionId: ResourceId
    ContentProtocols: ContentProtocols

class ConsumptionReportingConfigurationResponse(TagAndDateResponse, total=False):
    '''Response containing a consumption reporting configuration
    '''
    ProvisioningSessionId: ResourceId
    ConsumptionReportingConfiguration: ConsumptionReportingConfiguration

class M1Client:
    '''5G-MAG Reference Tools: M1 Client
    '''

    def __init__(self, host_address: Tuple[str,int]):
        '''
        Constructor

        :param Tuple[str,int] host_address: 5GMS Application Function to connect to as a tuple of hostname/ip-addr and TCP port
                                            number.
        '''
        self.__host_address = host_address
        self.__connection = None
        self.__log = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    # TS26512_M1_ProvisioningSession

    async def createProvisioningSession(self, provisioning_session_type: ProvisioningSessionType,
                                        external_application_id: ApplicationId,
                                        asp_id: Optional[ApplicationId] = None
                                        ) -> Optional[ProvisioningSessionResponse]:
        '''
        Create a provisioning session on the 5GMS Application Function

        :param ProvisioningSessionType provisioning_session_type: The provisioning session type.
        :param str external_application_id: The application ID of the external application requesting the new provisioning
                                            session.
        :param Optional[str] asp_id: The Application Server Provider ID.

        :return: the ResourceId of the allocated provisioning session or None if there was an error.

        :raises M1ClientError: if there was a problem with the request
        :raises M1ServerError: if there was a server side issue preventing the creation of the provisioning session.
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

        :param ResourceId provisioning_session_id: The provisioning session to find.

        :return: a ProvisioningSessionResponse structure if the provisioning session was found, or None if the provisioning
                 session was not found.

        :raises M1ClientError: if there was a problem with the request
        :raises M1ServerError: if there was a server side issue preventing the creation of the provisioning session.
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

        :param ResourceId provisioning_session_id: The provisioning session to find.

        :return: True if a provisioning session was deleted (or pending deletion) or False if there was no action.

        :raise M1ClientError: if there was a problem with the request
        :raise M1ServerError: if there was a server side issue preventing the creation of the provisioning session.
        '''
        result = await self.__do_request('DELETE',
                                         '/provisioning-sessions/' + provisioning_session_id, '',
                                         'application/json')
        if result['status_code'] == 204 or result['status_code'] == 202:
            return True
        self.__default_response(result)
        return False

    # TS26512_M1_ContentHostingProvisioning

    async def createContentHostingConfiguration(self, provisioning_session_id: ResourceId,
                                        content_hosting_configuration: ContentHostingConfiguration
                                                ) -> Union[bool,ContentHostingConfigurationResponse]:
        '''
        Create a content hosting configuration for a provisioning session

        :param ResourceId provisioning_session_id: The provisioning session to create the content hosting configuration in.
        :param ContentHostingConfiguration content_hosting_configuration: The content hosting configuration template to use.

        :return: True if the ContentHostingConfiguration was accepted but the response was empty, False if the
                 ContentHostingConfiguration was not accepted or a ContentHostingConfigurationResponse if the
                 ContentHostingConfiguration was accepted and the AF updated version returned.
        :raise M1ClientError: if there was a problem with the request.
        :raise M1ServerError: if there was a server side issue preventing the creation of the provisioning session.
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

        :param ResourceId provisioning_session_id: The provisioning session to fetch the current content hosting configuration
                                                   for.

        :return: None if the provisioning session does not exist, also returns None if the
                 provisioning session exists but does not have a content hosting configuration,
                 otherwise returns a ContentHostingConfigurationResponse.

        :raise M1ClientError: if there was a problem with the request.
        :raise M1ServerError: if there was a server side issue preventing the creation of the provisioning session.
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
                                                ) -> bool:
        '''
        Update a content hosting configuration for a provisioning session

        :param ResourceId provisioning_session_id: The provisioning session to update the current content hosting configuration
                                                   for.
        :param ContentHostingConfiguration content_hosting_configuration: The new content hosting configuration to apply.

        :return: ``True`` if the update succeeded or ``False`` if the update failed.

        :raise M1ClientError: if there was a problem with the request.
        :raise M1ServerError: if there was a server side issue preventing the creation of the provisioning session.
        '''
        result = await self.__do_request('PUT', f'/provisioning-sessions/{provisioning_session_id}/content-hosting-configuration',
                                         json.dumps(content_hosting_configuration), 'application/json')
        if result['status_code'] == 204:
            return True
        if result['status_code'] == 404:
            return False
        self.__default_response(result)
        return False

    async def patchContentHostingConfiguration(self, provisioning_session_id: ResourceId, patch: str
                                               ) -> Union[bool,ContentHostingConfigurationResponse]:
        '''
        Patch a content hosting configuration for a provisioning session using a JSON patch

        :param ResourceId provisioning_session_id: The provisioning session to update the current content hosting configuration
                                                   for.
        :param str patch: The patch information in JSON patch format.

        :return: a `ContentHostingConfigurationResponse` if the patch succeeded and the new ContentHostingConfiguration was
                 returned, or True if the patch succeeded but no ContentHostingConfiguration was returned, or False if the
                 patch failed.

        :raise M1ClientError: if there was a problem with the request.
        :raise M1ServerError: if there was a server side issue preventing the creation of the provisioning session.
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

        :param ResourceId provisioning_session_id: The provisioning session to remove the content hosting configuration for.

        :return: True if the ContentHostingConfiguration was deleted or False if the ContentHostingConfiguration did not exist.

        :raise M1ClientError: if there was a problem with the request.
        :raise M1ServerError: if there was a server side issue preventing the creation of the provisioning session.
        '''
        result = await self.__do_request('DELETE',
                    f'/provisioning-sessions/{provisioning_session_id}/content-hosting-configuration',
                                         '', 'application/json')
        if result['status_code'] == 204 or result['status_code'] == 202:
            return True
        if result['status_code'] == 404:
            return False
        self.__default_response(result)
        return False

    async def purgeContentHostingCache(self, provisioning_session_id: ResourceId,
                                       filter_regex: Optional[str] = None) -> Optional[int]:
        '''
        Purge cache entries for a provisioning session

        :param ResourceId provisioning_session_id: The provisioning session to purge cache entries for.
        :param Optional[str] filter_regex: Optional regular expression to match the cache entries origin URL path.

        :return: the number of purged entries, or None if no purge took place.
        :raise M1ClientError: if there was a problem with the request.
        :raise M1ServerError: if there was a server side issue preventing the creation of the provisioning session.
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

    async def createOrReserveServerCertificate(self, provisioning_session_id: ResourceId, extra_domain_names: Optional[List[str]] = None, csr: bool = False) -> Optional[ServerCertificateSigningRequestResponse]:
        '''Create or reserve a server certificate for a provisioing session

        :param ResourceId provisioning_session_id: The provisioning session to create the new certificate entry in.
        :param extra_domain_names: An optional list of extra domain names to include a CSR as SubjectAltName entries.
        :param bool csr: Whether to reserve a certificate and return the CSR PEM data.

        If *csr* is ``True`` then this will reserve the certificate and request the CSR PEM data be returned along side the Id
        of the newly reserved certificate. The *extra_domain_names* parameter may contain a list of extra domain names to include
        in the SubjectAltNames extension.

        If *csr* is ``False`` or not provided then create a new certificate and just return the new certificate Id. The
        *extra_domain_names* must be an empty list or ``None``.

        :return: a `ServerCertificateSigningRequestResponse` containing the certificate id and metadata optionally with CSR PEM
                 data if *csr* was ``True``.
        :raise M1ClientError: if there was a problem with the request.
        :raise M1ServerError: if there was a server side issue preventing the creation of the provisioning session.
        '''

        url = f'/provisioning-sessions/{provisioning_session_id}/certificates'
        if extra_domain_names is not None and not isinstance(extra_domain_names,list):
            raise M1ServerError(reason = f'Bad parameter passed during certificate creation', status_code = 500)
        if csr:
            url += '?csr=true'
        elif extra_domain_names is not None and len(extra_domain_names) > 0:
            raise M1ClientError(reason = f'Extra domain names cannot be specified when not generating a CSR', status_code = 400)
        body=''
        if extra_domain_names is not None and len(extra_domain_names) > 0:
            body = json.dumps(extra_domain_names)
        result = await self.__do_request('POST', url, body, 'application/json')
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

        :param ResourceId provisioning_session_id: The provisioning session to create the new certificate entry in.

        :return: a ServerCertificateResponse for the newly created certificate.
        :raise M1ClientError: if there was a problem with the request.
        :raise M1ServerError: if there was a server side issue preventing the creation of the provisioning session.
        '''
        result = await self.createOrReserveServerCertificate(provisioning_session_id, csr=False)
        return result

    async def reserveServerCertificate(self, provisioning_session_id: ResourceId, extra_domain_names: Optional[List[str]] = None) -> ServerCertificateSigningRequestResponse:
        '''Reserve a certificate for a provisioning session and get the CSR PEM

        :param ResourceId provisioning_session_id: The provisioning session to create the new certificate entry in.
        :param extra_domain_names: An optional list of extra domain names to include as Subject Alt Names.

        :return: a `ServerCertificateSigningRequestResponse` containing the CSR as a PEM string plus metadata for the reserved
                 certificate.
        :raise M1ClientError: if there was a problem with the request.
        :raise M1ServerError: if there was a server side issue preventing the creation of the provisioning session.
        '''
        result = await self.createOrReserveServerCertificate(provisioning_session_id, extra_domain_names=extra_domain_names, csr=True)
        if result is None or 'CertificateSigningRequestPEM' not in result:
            raise M1ClientError(reason = f'Failed to retrieve CSR for session {provisioning_session_id}', status_code = 200)
        return result

    async def uploadServerCertificate(self, provisioning_session_id: ResourceId, certificate_id: ResourceId, pem_data: str) -> bool:
        '''Upload the signed public certificate for a reserved certificate

        :param ResourceId provisioning_session_id: The provisioning session the certificate was reserved for.
        :param ResourceId certificate_id: The certificate Id of the reserved certificate.
        :param str pem_data: A string containing the PEM data for the public certificate to upload.

        :return: ``True`` if successful or ``False`` if the certificate has already been uploaded.
        :raise M1ClientError: if there was a problem with the request.
        :raise M1ServerError: if there was a server side issue preventing the creation of the provisioning session.
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

        :param ResourceId provisioning_session_id: The provisioning session for the certificate.
        :param ResourceId certificate_id: The certificate Id of the certificate.

        :return: a ServerCertificateResponse containing the PEM data for the public certificate and its metadata or ``None``
                 if the certificate is reserved and awaiting upload.

        :raise M1ClientError: if there was a problem with the request or the certificate was not found.
        :raise M1ServerError: if there was a server side issue preventing the creation of the provisioning session.
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

        :param ResourceId provisioning_session_id: The provisioning session for the certificate.
        :param ResourceId certificate_id: The certificate Id of the certificate.

        :return: ``True`` if the certificate has been deleted.
        :raise M1ClientError: if there was a problem with the request.
        :raise M1ServerError: if there was a server side issue preventing the creation of the provisioning session.
        '''
        result = await self.__do_request('DELETE',
              f'/provisioning-sessions/{provisioning_session_id}/certificates/{certificate_id}',
              '', 'application/octet-stream')
        if result['status_code'] == 204 or result['status_code'] == 202:
            return True
        self.__default_response(result)
        return False

    # TS26512_M1_ContentProtocolsDiscovery
    async def retrieveContentProtocols(self, provisioning_session_id: ResourceId) -> Optional[ContentProtocolsResponse]:
        '''Get the ContentProtocols information for the provisioning session

        :param ResourceId provisioning_session_id: The provisioning session to get the ContentProtocols for.

        :return: a `ContentProtocolsResponse` containing the ContentProtocols structure and metadata or None if the
                 provisioning session was not found.
        :raise M1ClientError: if there was a problem with the request.
        :raise M1ServerError: if there was a server side issue preventing the creation of the provisioning session.
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
    async def activateConsumptionReportingConfiguration(self, provisioning_session_id: ResourceId, consumption_reporting_config: ConsumptionReportingConfiguration) -> Union[Optional[ConsumptionReportingConfigurationResponse],bool]:
        '''Set the ConsumptionReportingConfiguration for the provisioning session

        :param ResourceId provisioning_session_id: The provisioning session to set the ConsumptionReportingConfiguration for.
        :param ConsumptionReportingConfiguration consumption_reporting_config: The ConsumptionReportingConfiguration to set.

        :return: `True` if the ConsumptionReportingConfiguration was set and the Application Function didn't report back the
                 configuration, or a `ConsumptionReportingConfigurationResponse` if the configuration was reported back, or `None`
                 if setting the configuration failed.

        :raise M1ClientError: if there was a problem with the request.
        :raise M1ServerError: if there was a server side issue preventing the creation of the provisioning session.
        '''
        result = await self.__do_request('POST',
                f'/provisioning-sessions/{provisioning_session_id}/consumption-reporting-configuration',
                json.dumps(consumption_reporting_config), 'application/json')
        if result['status_code'] == 200:
            ret: ConsumptionReportingConfigurationResponse = self.__tag_and_date(result)
            ret['ConsumptionReportingConfiguration'] = ConsumptionReportingConfiguration.fromJSON(result['body'])
            return ret
        elif result['status_code'] == 204:
            return True
        self.__default_response(result)
        return None

    async def retrieveConsumptionReportingConfiguration(self, provisioning_session_id: ResourceId) -> Optional[ConsumptionReportingConfigurationResponse]:
        '''Get the ConsumptionReportingConfiguration for the provisioning session

        :param ResourceId provisioning_session_id: The provisioning session to get the ConsumptionReportingConfiguration for.

        :return: A `ConsumptionReportingConfigurationResponse` for the current configuration in the provisioning session.

        :raise M1ClientError: if there was a problem with the request.
        :raise M1ServerError: if there was a server side issue preventing the creation of the provisioning session.
        '''
        result = await self.__do_request('GET',
                f'/provisioning-sessions/{provisioning_session_id}/consumption-reporting-configuration',
                '', 'application/octet-stream')
        if result['status_code'] == 200:
            ret: ConsumptionReportingConfigurationResponse = self.__tag_and_date(result)
            ret['ConsumptionReportingConfiguration'] = ConsumptionReportingConfiguration.fromJSON(result['body'])
            return ret
        if result['status_code'] == 404:
            return None
        self.__default_response(result)
        return None

    async def updateConsumptionReportingConfiguration(self, provisioning_session_id: ResourceId, consumption_reporting_config: ConsumptionReportingConfiguration) -> bool:
        '''Modify the ConsumptionReportingConfiguration for the provisioning session

        :param ResourceId provisioning_session_id: The provisioning session to modify the ConsumptionReportingConfiguration for.
        :param ConsumptionReportingConfiguration consumption_reporting_config: The ConsumptionReportingConfiguration to apply.

        :return: `True` if the configuration was changed successfully.

        :raise M1ClientError: if there was a problem with the request.
        :raise M1ServerError: if there was a server side issue preventing the creation of the provisioning session.
        '''
        result = await self.__do_request('PUT',
                f'/provisioning-sessions/{provisioning_session_id}/consumption-reporting-configuration',
                json.dumps(consumption_reporting_config), 'application/json')
        if result['status_code'] == 204:
            return True
        self.__default_response(result)
        return False

    async def patchConsumptionReportingConfiguration(self, provisioning_session_id: ResourceId, patch: str) -> ConsumptionReportingConfigurationResponse:
        '''Patch the ConsumptionReportingConfiguration for the provisioning session

        :param ResourceId provisioning_session_id: The provisioning session to modify the ConsumptionReportingConfiguration for.
        :param str patch: The JSON patch to apply to the ConsumptionReportingConfiguration.

        :return: A `ConsumptionReportingConfigurationResponse` containing the new configuration after the patch is applied.

        :raise M1ClientError: if there was a problem with the request.
        :raise M1ServerError: if there was a server side issue preventing the creation of the provisioning session.
        '''
        result = await self.__do_request('PATCH',
                f'/provisioning-sessions/{provisioning_session_id}/consumption-reporting-configuration',
                patch, 'application/json-patch+json')
        if result['status_code'] == 200:
            ret: ConsumptionReportingConfigurationResponse = self.__tag_and_date(result)
            ret['ConsumptionReportingConfiguration'] = ConsumptionReportingConfiguration.fromJSON(result['body'])
            return ret
        self.__default_response(result)
        return None

    async def destroyConsumptionReportingConfiguration(self, provisioning_session_id: ResourceId) -> bool:
        '''Remove the ConsumptionReportingConfiguration from the provisioning session

        :param ResourceId provisioning_session_id: The provisioning session to remove the ConsumptionReportingConfiguration from.

        :return: `True` if the ConsumptionReportingConfiguration was successfully removed.

        :raise M1ClientError: if there was a problem with the request.
        :raise M1ServerError: if there was a server side issue preventing the creation of the provisioning session.
        '''
        result = await self.__do_request('DELETE',
                f'/provisioning-sessions/{provisioning_session_id}/consumption-reporting-configuration',
                '', 'application/octet-stream')
        if result['status_code'] == 204:
            return True
        self.__default_response(result)
        return False

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

        :meta private:
        :param str method: The HTTP method for the request.
        :param str url_suffix: The URL path suffix for the request after the protocol and version identifiers.
        :param Union[str,bytes] body: The body of the request as a `str` or `bytes`.
        :param str content_type: The content type to use in the ``Content-Type`` header of the request.
        :param Optional[dict] headers: Extra headers to go along with the request.
        :return: a `dict` with 3 entries ``status_code``, ``body`` and ``headers`` representing the HTTP response status code,
                 the response message body and the response headers.
        :raise M1ServerError: if communication with the AF failed.
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

        This will raise exceptions for 4XX and 5XX response codes.

        :meta private:
        :param Dict[str,Any] result: The result as returned by `__do_request`.

        :raise M1ClientError: if there was a problem with the request.
        :raise M1ServerError: if there was a server side issue preventing the creation of the provisioning session.
        '''
        if result['status_code'] >= 400 and result['status_code'] < 500:
            raise M1ClientError(reason='M1 operation failed: '+str(result['body']),
                                status_code=result['status_code'])
        if result['status_code'] >= 500 and result['status_code'] < 600:
            raise M1ServerError(reason='M1 operation failed: '+str(result['body']),
                                status_code=result['status_code'])

    @staticmethod
    def __tag_and_date(result: Dict[str,Any]) -> TagAndDateResponse:
        '''Get the response message standard metadata

        This will extract metadata from ``ETag``, ``Last-Modified`` and ``Cache-Control`` headers.

        :param Dict[str,Any] result: The result as returned by `__do_request`.

        :return: the base TagAndDateResponse structure for all response messages.
        '''
        # Get ETag
        ret = {'ETag': result['headers'].get('etag')}
        # Get Last-Modified as a datetime.datetime
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
        # Get Cache-Control as a cache expiry time
        cc = result['headers'].get('cache-control')
        if cc is not None:
            age = result['headers'].get('age')
            if age is None:
                age = 0
            else:
                age = int(age)
            max_age_values = [int(c[8:]) for c in [v.strip() for v in cc.split(',')] if c[:8] == 'max-age=']
            if len(max_age_values) > 0:
                cc = datetime.datetime.now(tz=datetime.timezone.utc)+datetime.timedelta(seconds=min(max_age_values)-age)
            else:
                cc = None
        ret['Cache-Until'] = cc
        return ret

    def __debug(self, *args, **kwargs) -> None:
        '''Output a debug message

        :meta private:
        :param args: Positional arguments to pass to `logger.debug()`.
        :param kwargs: Keyword arguments to pass to `logger.debug()`.
        '''
        self.__log.debug(*args, **kwargs)

__all__ = [
        # Types
        'ProvisioningSessionResponse',
        'ContentHostingConfigurationResponse',
        'ConsumptionReportingConfigurationResponse',
        'ServerCertificateResponse',
        'ServerCertificateSigningRequestResponse',
        'ContentProtocolsResponse',
        # Classes
        'M1Client',
        ]
