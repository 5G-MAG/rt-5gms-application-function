#!/usr/bin/python3
#==============================================================================
# 5G-MAG Reference Tools: M1 Client types
#==============================================================================
#
# File: rt_m1_client/types.py
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
# M1 Client types
# ===============
#
# Defines various types from TS 29.571 and TS 26.512 used in M1 requests

'''5G-MAG Reference Tools: M1 Client types
=======================================

This module defines various types from TS 29.571 and TS 26.512 used in M1 requests.

These types can be used in static type checking in Python 3.
'''
import enum
import json
from typing import List, Literal, TypedDict

# TS 26.512 ProvisioningSession

ApplicationId = str
ResourceId = str
Uri = str
ProvisioningSessionId = ResourceId
ProvisioningSessionType = Literal['DOWNLINK','UPLINK']

class ProvisioningSessionMandatory(TypedDict):
    provisioningSessionId: ProvisioningSessionId
    provisioningSessionType: ProvisioningSessionType
    externalApplicationId: ApplicationId

class ProvisioningSession (ProvisioningSessionMandatory, total=False):
    aspId: ApplicationId

    @staticmethod
    def fromJSON(json_str: str) -> "ProvisioningSession":
        ret: dict = json.loads(json_str)
        for mandatory_field in ProvisioningSessionMandatory.__required_keys__:
            if mandatory_field not in ret:
                raise TypeError(f'ProvisioningSession must contain a {mandatory_field} field: {json_str}')
        if ret['provisioningSessionType'] not in ProvisioningSessionType.__args__:
            raise TypeError(f'ProvisioningSession.provisioningSessionType must be one of: {", ".join(ProvisioningSessionType.__args__)}: {json_str}')
            
        return ProvisioningSession(ret)

PROVISIONING_SESSION_TYPE_DOWNLINK: ProvisioningSessionType = 'DOWNLINK'
PROVISIONING_SESSION_TYPE_UPLINK: ProvisioningSessionType = 'UPLINK'

# TS 26.512 ContentHostingConfiguration

class PathRewriteRule(TypedDict):
    '''PathRewriteRule structure in TS 26.512
    '''
    requestPathPattern: str
    mappedPath: str

class CachingDirectivesMandatory(TypedDict):
    '''Mandatory fields from CachingConfiguration.cachingDirectives structure in TS 26.512
    '''
    noCache: bool

class CachingDirectives(CachingDirectivesMandatory, total=False):
    '''CachingConfiguration.cachingDirectives structure in TS 26.512
    '''
    statusCodeFilters: List[int]
    maxAge: int

class CachingConfigurationMandatory(TypedDict):
    '''Mandatory fields from CachingConfiguration structure in TS 26.512
    '''
    urlPatternFilter: str

class CachingConfiguration(CachingConfigurationMandatory, total=False):
    '''CachingConfiguration structure in TS 26.512
    '''
    cachingDirectives: CachingDirectives

class ContentProtocolDescriptorMandatory(TypedDict):
    '''Mandatory fields from ContentProtocolDescriptor in TS 26.512
    '''
    termIdentifier: Uri

class ContentProtocolDescriptor(ContentProtocolDescriptorMandatory, total=False):
    '''ContentProtocolDescriptor structure in TS 26.512
    '''
    descriptionLocator: Uri

class ContentProtocols(TypedDict, total=False):
    '''ContentProtocols structure in TS 26.512
    '''
    downlinkIngestProtocols: List[ContentProtocolDescriptor]
    uplinkEgestProtocols: List[ContentProtocolDescriptor]
    geoFencingLocatorTypes: List[Uri]

    @staticmethod
    def fromJSON(json_str: str) -> "ContentProtocols":
        return ContentProtocols(json.loads(str))

class DistributionNetworkType(enum.Enum):
    '''Enumeration DistributionNetworkType in TS 26.512
    '''
    NETWORK_EMBMS = enum.auto()

    def __str__(self):
        return self.name

class DistributionMode(enum.Enum):
    '''Enumeration DistributionMode in TS 26.512
    '''
    MODE_EXCLUSIVE = enum.auto()
    MODE_HYBRID = enum.auto()
    MODE_DYNAMIC = enum.auto()

    def __str__(self):
        return self.name

class DistributionConfiguration(TypedDict, total=False):
    '''
    DistributionConfiguration structure in TS 26.512
    '''
    contentPreparationTemplateId: ResourceId
    canonicalDomainName: str
    domainNameAlias: str
    baseURL: Uri
    pathRewriteRules: List[PathRewriteRule]
    cachingConfigurations: List[CachingConfiguration]
    geoFencing: TypedDict('GeoFencing', {'locatorType': str, 'locators': List[str]})
    urlSignature: TypedDict('URLSignature', {
        'urlPattern': str,
        'tokenName': str,
        'passphraseName': str,
        'passphrase': str,
        'tokenExpiryName': str,
        'useIPAddress': bool
        })
    certificateId: ResourceId
    supplementaryDistributionNetworks: List[TypedDict('SupplementaryDistributionNetwork', {
        'distributionNetworkType': DistributionNetworkType,
        'distributionMode': DistributionMode,
        })]

class IngestConfiguration(TypedDict, total=False):
    '''
    IngestConfiguration structure from TS 26.512
    '''
    pull: bool
    protocol: Uri
    baseURL: Uri

class ContentHostingConfigurationMandatory(TypedDict):
    '''
    Mandatory fields from ContentHostingConfiguration structure in TS 26.512
    '''
    name: str
    ingestConfiguration: IngestConfiguration
    distributionConfigurations: List[DistributionConfiguration]

class ContentHostingConfiguration(ContentHostingConfigurationMandatory, total=False):
    '''
    ContentHostingConfiguration structure in TS 26.512
    '''
    entryPointPath: str

    @staticmethod
    def fromJSON(chc_json: str) -> "ContentHostingConfiguration":
        '''
        Generate a ContentHostingConfiguration structure from a JSON string
        '''
        # parse the JSON
        chc = json.loads(chc_json)
        # convert enums
        if 'distributionConfigurations' in chc:
            for dist_conf in chc['distributionConfigurations']:
                if 'supplementaryDistributionNetworks' in dist_conf:
                    for supp_net in dist_conf['supplementaryDistributionNetworks']:
                        supp_net['distributionNetworkType'] = DistributionNetworkType(
                                supp_net['distributionNetworkType'])
                        supp_net['distributionMode'] = DistributionMode(
                                supp_net['distributionMode'])
        # Validate against ContentHostingConfiguration type
        return ContentHostingConfiguration(chc)

    @classmethod
    def format(cls, chc: "ContentHostingConfiguration") -> str:
        return f'''Name: {chc['name']}
{cls.__formatEntryPoint(chc)}Ingest:
    Type: {chc['ingestConfiguration']['protocol']}
    URL: {chc['ingestConfiguration']['baseURL']}
Distributions:
{cls.__formatDistributions(chc, indent=2)}
'''

    @classmethod
    def __formatDistributions(cls, chc: "ContentHostingConfiguration", indent: int = 0) -> str:
        prefix = ' '*indent
        dists = []
        for d in chc['distributionConfigurations']:
            s = f"{prefix}- URL: {d['baseURL']}"
            if 'certificateId' in d:
                s += f"\n{prefix}  Certificate: {d['certificateId']}"
            if 'domainNameAlias' in d:
                s += f"\n{prefix}  Domain Name Alias: {d['domainNameAlias']}"
            dists += [s]
        return '\n'.join(dists)

    @classmethod
    def __formatEntryPoint(cls, chc: "ContentHostingConfiguration", indent: int = 0) -> str:
        if 'entryPointPath' not in chc:
            return ''
        prefix = ' '*indent
        return f"{prefix}Entry Point Path: {chc['entryPointPath']}\n"

# TS 29.571 ProblemDetail
class InvalidParamMandatory(TypedDict):
    '''
    Mandatory fields from InvalidParam structure in TS 29.571
    '''
    param: str

class InvalidParam(InvalidParamMandatory, total=False):
    '''
    InvalidParam structure from TS 29.571
    '''
    reason: str

class AccessTokenErrError(enum.Enum):
    '''
    AccessTokenErrError enumeration from TS 29.571
    '''
    invalid_request = enum.auto() # pylint: disable=invalid-name
    invalid_client = enum.auto() # pylint: disable=invalid-name
    invalid_grant = enum.auto() # pylint: disable=invalid-name
    unauthorized_client = enum.auto() # pylint: disable=invalid-name
    unsupported_grant_type = enum.auto() # pylint: disable=invalid-name
    invalid_scope = enum.auto() # pylint: disable=invalid-name

    def __str__(self):
        return self.name

class AccessTokenErrMandatory(TypedDict):
    '''
    Mandatory fields from AccessTokenErr structure in TS 29.571
    '''
    error: AccessTokenErrError

class AccessTokenErr(AccessTokenErrMandatory, total=False):
    '''
    AccessTokenErr structure in TS 29.571
    '''
    error_description: str
    error_uri: str

class AccessTokenReqGrantType(enum.Enum):
    '''
    AccessTokenReqGrantType enumeration in TS 29.571
    '''
    client_credentials = enum.auto() # pylint: disable=invalid-name

    def __str__(self):
        return self.name

class AccessTokenReqMandatory(TypedDict):
    '''
    Mandatory fields from AccessTokenReq structure in TS 29.571
    '''
    grant_type: AccessTokenReqGrantType
    nfInstanceId: str
    scope: str

class AccessTokenReq(AccessTokenReqMandatory, total=False):
    '''
    AccessTokenReq structure in TS 29.571
    '''
    nfType: str
    targetNfType: str
    targetNfInstanceId: str
    requesterPlmn: str
    requesterPlmnList: List[str]
    requesterSnssaiList: List[str]
    requesterFqdn: str
    requesterSnpnList: List[str]
    targetPlmn: str
    targetSnssaiList: List[str]
    targetNsiList: List[str]
    targetNfSetId: str
    targetNfServiceSetId: str
    hnrfAccessTokenUri: str
    sourceNfInstanceId: str

class ProblemDetail(TypedDict, total=False):
    '''
    ProblemDetail structure in TS 29.571
    '''
    problemtype: str
    title: str
    status: int
    detail: str
    instance: str
    cause: str
    invalidParams: List[InvalidParam]
    supportedFeatures: str
    accessTokenError: AccessTokenErr
    accessTokenRequest: AccessTokenReq
    nrfId: str

    @staticmethod
    def fromJSON(problem_detail_json: str):
        '''
        Generate a ProblemDetail structure from a JSON string
        '''
        prob_detail = json.loads(problem_detail_json)
        if 'accessTokenError' in prob_detail:
            for ate in prob_detail['accessTokenError']:
                ate['error'] = AccessTokenErrError(ate['error'])
        if 'accessTokenRequest' in prob_detail:
            for atr in prob_detail['accessTokenRequest']:
                atr['grant_type'] = AccessTokenReqGrantType(atr['grant_type'])
        return prob_detail

__all__ = [
        "ProblemDetail",
        "AccessTokenErr",
        "AccessTokenReq",
        "InvalidParam",
        "ApplicationId",
        "ResourceId",
        "ProvisioningSessionId",
        "ProvisioningSessionType",
        "ProvisioningSession",
        "PROVISIONING_SESSION_TYPE_DOWNLINK",
        "PROVISIONING_SESSION_TYPE_UPLINK",
        ]
