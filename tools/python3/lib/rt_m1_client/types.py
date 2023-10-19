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
    '''Madatory fields for a `ProvisioningSession`
    '''
    provisioningSessionId: ProvisioningSessionId
    provisioningSessionType: ProvisioningSessionType
    externalApplicationId: ApplicationId

class ProvisioningSession (ProvisioningSessionMandatory, total=False):
    '''A `ProvisioningSession` object as defined in TS 26.512
    '''
    aspId: ApplicationId

    @staticmethod
    def fromJSON(json_str: str) -> "ProvisioningSession":
        '''Create a `ProvisioningSession` from a JSON string

        :param str json_str: The JSON string to convert to a `ProvisioningSession`.

        :return: a `ProvisioningSession` holding the data from the *json_str*.
        :rtype: ProvisioningSession
        :raise TypeError: if there is a problem with interpretting the *json_str* as a `ProvisioningSession`.
        '''
        ret: dict = json.loads(json_str)
        for mandatory_field in ProvisioningSessionMandatory.__required_keys__:
            if mandatory_field not in ret:
                raise TypeError(f'ProvisioningSession must contain a {mandatory_field} field: {json_str}')
        if ret['provisioningSessionType'] not in ProvisioningSessionType.__args__:
            raise TypeError(f'ProvisioningSession.provisioningSessionType must be one of: {", ".join(ProvisioningSessionType.__args__)}: {json_str}')
            
        return ProvisioningSession(ret)

PROVISIONING_SESSION_TYPE_DOWNLINK: ProvisioningSessionType = 'DOWNLINK' #: Downlink `ProvisioningSessionType`.
PROVISIONING_SESSION_TYPE_UPLINK: ProvisioningSessionType = 'UPLINK'     #: Uplink `ProvisioningSessionType`.

# TS 26.512 ContentHostingConfiguration

class PathRewriteRule(TypedDict):
    '''PathRewriteRule structure in TS 26.512
    '''
    requestPathPattern: str #: A regex to match the request path.
    mappedPath: str         #: The path to map in instead of the matched path.

class CachingDirectiveMandatory(TypedDict):
    '''Mandatory fields from CachingConfiguration.cachingDirectives structure in TS 26.512
    '''
    noCache: bool #: ``True`` if ``no-cache`` should be included for this directive.

class CachingDirective(CachingDirectiveMandatory, total=False):
    '''CachingConfiguration.cachingDirectives structure in TS 26.512
    '''
    statusCodeFilters: List[int] #: A list of status codes to apply this cache directive for.
    maxAge: int                  #: A ``max-age`` to apply for this directive.

class CachingConfigurationMandatory(TypedDict):
    '''Mandatory fields from CachingConfiguration structure in TS 26.512
    '''
    urlPatternFilter: str #: A URL pattern to match for the cache configuration

class CachingConfiguration(CachingConfigurationMandatory, total=False):
    '''CachingConfiguration structure in TS 26.512
    '''
    cachingDirectives: List[CachingDirective] #: Array of cache directives for the matched URL

class ContentProtocolDescriptorMandatory(TypedDict):
    '''Mandatory fields from ContentProtocolDescriptor in TS 26.512
    '''
    termIdentifier: Uri #: A URI (usually URN) to identify an ingest protocol.

class ContentProtocolDescriptor(ContentProtocolDescriptorMandatory, total=False):
    '''ContentProtocolDescriptor structure in TS 26.512
    '''
    descriptionLocator: Uri #: A URL to documentation describing the *termIdentfier*.

class ContentProtocols(TypedDict, total=False):
    '''ContentProtocols structure in TS 26.512
    '''
    downlinkIngestProtocols: List[ContentProtocolDescriptor] #: An array of available downlink ingest protocols.
    uplinkEgestProtocols: List[ContentProtocolDescriptor]    #: An array of available uplink ingest protocols.
    geoFencingLocatorTypes: List[Uri]                        #: An array of available geo-fencing location types.

    @staticmethod
    def fromJSON(json_str: str) -> "ContentProtocols":
        '''Create a `ContentProtocols` from a JSON string

        :param str json_str: The JSON string to convert to a `ContentProtocols`.
        :return: a `ContentProtocols` containing the data from the *json_str*.
        :rtype: ContentProtocols
        :raise TypeError: if the *json_str* could not be interpretted as a `ContentProtocols`.
        '''
        return ContentProtocols(json.loads(json_str))

class DistributionNetworkType(enum.Enum):
    '''Enumeration DistributionNetworkType in TS 26.512
    '''
    NETWORK_EMBMS = enum.auto() #: Distribution type is via EMBMS network.

    def __str__(self) -> str:
        '''String representation of the `DistributionNetworkType`.

        :return: a `str` containing the name of the enumerated `DistributionNetworkType`.
        '''
        return self.name

class DistributionMode(enum.Enum):
    '''Enumeration DistributionMode in TS 26.512
    '''
    MODE_EXCLUSIVE = enum.auto() #: Distribution mode is exclusive
    MODE_HYBRID = enum.auto()    #: Distribution mode is hybrid
    MODE_DYNAMIC = enum.auto()   #: Distribution mode is dynamic

    def __str__(self):
        '''String representation of the `DistributionMode`.

        :return: a `str` containing the name of the enumerated `DistributionMode`.
        '''
        return self.name

class M1MediaEntryPointMandatory(TypedDict, total=True):
    '''Mandatory fields from M1MediaEntryPoint in TS 26.512 (v17.5.0)
    '''
    relativePath: str
    contentType: str

class M1MediaEntryPoint(M1MediaEntryPointMandatory, total=False):
    '''M1MediaEntryPoint in TS 26.512 (v17.5.0)
    '''
    profiles: List[str]

class DistributionConfiguration(TypedDict, total=False):
    '''
    DistributionConfiguration structure in TS 26.512
    '''
    contentPreparationTemplateId: ResourceId
    canonicalDomainName: str
    domainNameAlias: str
    baseURL: Uri
    entryPoint: M1MediaEntryPoint
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

    @staticmethod
    def format(dc: "DistributionConfiguration", indent: int = 0) -> str:
        prefix = ' ' * indent
        s = f"{prefix}- URL: {dc['baseURL']}"
        if 'canonicalDomainName' in dc:
            s += f'''
{prefix}  Canonical Domain Name: {dc['canonicalDomainName']}'''
        if 'contentPreparationTemplateId' in dc:
            s += f'''
{prefix}  Content Preparation Template: {dc['contentPreparationTemplateId']}'''
        if 'certificateId' in dc:
            s += f'''
{prefix}  Certificate: {dc['certificateId']}'''
        if 'domainNameAlias' in dc:
            s += f'''
{prefix}  Domain Name Alias: {dc['domainNameAlias']}'''
        if 'entryPoint' in dc:
            s += f'''
{prefix}  Entry point:
{prefix}    Relative Path: {dc['entryPoint']['relativePath']}
{prefix}    Content Type: {dc['entryPoint']['contentType']}'''
            if 'profiles' in dc['entryPoint']:
                s += f'''
{prefix}    Profiles:'''
                for p in dc['entryPoint']['profiles']:
                    s += f'''
{prefix}    - {p}'''
        if 'pathRewriteRules' in dc:
            s += f'''
{prefix}  Path Rewrite Rules:'''
            for prr in dc['pathRewriteRules']:
                s += f'''
{prefix}  - {prr['requestPathPattern']} => {prr['mappedPath']}'''
        if 'cachingConfigurations' in dc:
            s += f'''
{prefix}  Caching Configurations:'''
            for cc in dc['cachingConfigurations']:
                s += f'''
{prefix}  - URL Pattern: {cc['urlPatternFilter']}'''
                if 'cachingDirectives' in cc:
                    cd = cc['cachingDirectives']
                    s += f'''
{prefix}    Directive:
{prefix}      no-cache={repr(cd['noCache'])}'''
                    if 'maxAge' in cd:
                        s += f'''
{prefix}      max-age={cd['maxAge']}'''
                    if 'statusCodeFilters' in cd:
                        s += f'''
{prefix}      filters=[{', '.join([str(i) for i in cd['statusCodeFilters']])}]'''
        if 'geoFencing' in dc:
            gf = dc['geoFencing']
            s += f'''
{prefix}  Geo-fencing({gf['locatorType']}):'''
            for l in gf['locators']:
                s += f'''
{prefix}  - {l}'''
        if 'urlSignature' in dc:
            us = dc['urlSignature']
            s += f'''
{prefix}  URL Signature:
{prefix}  - Pattern: {us['urlPattern']}
{prefix}    Token: {us['tokenName']}
{prefix}    Passphase name: {us['passphraseName']}
{prefix}    Passphase: {us['passphrase']}
{prefix}    Token Expiry name: {us['tokenExpiryName']}
{prefix}    Use IP Address?: {us['useIPAddress']!r}'''
            if 'ipAddressName' in us:
                s += f'''
{prefix}    IP Address name: {us['ipAddressName']}'''
        return s

class IngestConfiguration(TypedDict, total=False):
    '''
    IngestConfiguration structure from TS 26.512
    '''
    pull: bool
    protocol: Uri
    baseURL: Uri

    @staticmethod
    def format(ic: "IngestConfiguration", indent: int = 0) -> str:
        prefix = ' ' * indent
        return f'''{prefix}Type: {ic['protocol']}
{prefix}Pull Ingest?: {ic['pull']!r}
{prefix}URL: {ic['baseURL']}'''

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
        '''Get a formatted `str` representation of a `ContentHostingConfiguration`.

        :param ContentHostingConfiguration chc: The `ContentHostingConfiguration` to format.
        :return: a formatted `str` representation of the `ContentHostingConfiguration`.
        '''
        return f'''Name: {chc['name']}
Ingest:
{IngestConfiguration.format(chc['ingestConfiguration'], 2)}
Distributions:
{cls.__formatDistributions(chc)}
'''

    @classmethod
    def __formatDistributions(cls, chc: "ContentHostingConfiguration", indent: int = 0) -> str:
        '''Format a ContentHostingConfiguration.distributionConfigurations

        :meta private:
        :param ContentHostingConfiguration chc: The `ContentHostingConfiguration` to get the distributionConfigurations from.
        :param int indent: The amount of spaces to indent the formatted distributionConfigurations by.

        :return: a `str` containing the distributionConfigurations as formatted text.
        '''
        return '\n'.join([DistributionConfiguration.format(d, indent) for d in chc['distributionConfigurations']])

# TS 26.512 ConsumptionReportingConfiguration

class ConsumptionReportingConfiguration(TypedDict, total=False):
    '''
    ConsumptionReportingConfiguration structure from TS 26.512
    '''
    reportingInterval: int
    samplePercentage: float
    locationReporting: bool
    accessReporting: bool

    @staticmethod
    def fromJSON(crc_json: str) -> "ConsumptionReportingConfiguration":
        '''Create a ConsumptionReportingConfiguration from a JSON string

        :param str json: The JSON string to parse into a ConsumptionReportingConfiguration structure.

        :return: The `ConsumptionReportingConfiguration` generated from the JSON string.

        :raise ValueError: If the JSON could not be parsed.
        '''
        # parse the JSON
        crc = json.loads(crc_json)
        # validate types
        if 'reportingInterval' in crc:
            if not isinstance(crc['reportingInterval'], int):
                raise ValueError('ConsumptionReportingConfiguration.reportingInterval must be an integer')
            if crc['reportingInterval'] <= 0:
                raise ValueError('ConsumptionReportingConfiguration.reportingInterval must be an integer greater than 0')
        if 'samplePercentage' in crc:
            if isinstance(crc['samplePercentage'], int):
                crc['samplePercentage'] = float(crc['samplePercentage'])
            if not isinstance(crc['samplePercentage'], float):
                raise ValueError('ConsumptionReportingConfiguration.samplePercentage must be an integer or floating point number')
            if crc['samplePercentage'] < 0.0 or crc['samplePercentage'] > 100.0:
                raise ValueError('ConsumptionReportingConfiguration.samplePercentage must be between 0.0 and 100.0 inclusive')
        if 'locationReporting' in crc:
            if not isinstance(crc['locationReporting'], bool):
                raise ValueError('ConsumptionReportingConfiguration.locationReporting must be a boolean')
        if 'accessReporting' in crc:
            if not isinstance(crc['accessReporting'], bool):
                raise ValueError('ConsumptionReportingConfiguration.accessReporting must be a boolean')
        # Validate against ContentHostingConfiguration type
        return ConsumptionReportingConfiguration(crc)

    @classmethod
    def format(cls, crc: "ConsumptionReportingConfiguration", indent: int = 0) -> str:
        prefix: str = ' ' * indent
        ret: str = ''
        if 'reportingInterval' in crc:
            ret += f"{prefix}Reporting interval: {crc['reportingInterval']}s\n"
        if 'samplePercentage' in crc:
            ret += f"{prefix}Sample percentage: {crc['samplePercentage']}\n"
        if 'locationReporting' in crc and crc['locationReporting']:
            ret += f"{prefix}With location reporting\n"
        if 'accessReporting' in crc and crc['accessReporting']:
            ret += f"{prefix}With access reporting\n"
        if len(ret) == 0:
            ret = f'{prefix}Active with no parameters set\n'
        return ret

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
    def fromJSON(problem_detail_json: str) -> "ProblemDetail":
        '''
        Generate a `ProblemDetail` structure from a JSON string

        :param str problem_detail_json: The JSON string to convert to a `ProblemDetail`.
        :return: a `ProblemDetail` containing the data from the *problem_detail_json* JSON string.
        '''
        prob_detail = json.loads(problem_detail_json)
        # Convert enumerated type strings to their enum values
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
