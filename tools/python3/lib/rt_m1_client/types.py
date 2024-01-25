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
import string
from typing import List, Literal, TypedDict, Union

def wrapped_default(self, obj):
    return getattr(obj.__class__, "__jsontype__", wrapped_default.default)(obj)
wrapped_default.default = json.JSONEncoder().default

json.JSONEncoder.default = wrapped_default

# TS 26.512 ProvisioningSession

ApplicationId = str
ResourceId = str
Uri = str
ProvisioningSessionId = ResourceId
ProvisioningSessionType = Literal['DOWNLINK','UPLINK']

class ProvisioningSessionMandatory(TypedDict):
    '''Mandatory fields for a `ProvisioningSession` v17.7.0
    '''
    provisioningSessionId: ProvisioningSessionId
    provisioningSessionType: ProvisioningSessionType
    appId: ApplicationId

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

    def __jsontype__(self, **options):
        return str(self)

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

    def __jsontype__(self, **options):
        return str(self)

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
                        supp_net['distributionNetworkType'] = DistributionNetworkType[
                                supp_net['distributionNetworkType']]
                        supp_net['distributionMode'] = DistributionMode[
                                supp_net['distributionMode']]
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
            ret = f"{prefix}Active with no parameters set\n"
        return ret

# TS 26.512 PolicyTemplate
class PolicyTemplateState(enum.Enum):
    '''
    PolicyTemplate.state enumeration from TS 26.512
    '''
    PENDING = enum.auto() # pylint: disable=invalid-name
    INVALID = enum.auto() # pylint: disable=invalid-name
    READY = enum.auto() # pylint: disable=invalid-name
    SUSPENDED = enum.auto() # pylint: disable=invalid-name

    def __jsontype__(self, **options):
        return str(self)

    def __str__(self):
        return self.name

class SnssaiMandatory(TypedDict):
    '''
    Snssai structure mandatory fields from TS 29.571
    '''
    sst: int

class Snssai(SnssaiMandatory, total=False):
    '''
    Snssai structure from TS 29.571
    '''
    sd: str

    @staticmethod
    def validate(snssai: "Snssai", json: str) -> bool:
        # check mandatory fields presence
        for mandatory_field in SnssaiMandatory.__required_keys__:
            if mandatory_field not in snssai:
                raise TypeError(f'Snssai must contain a {mandatory_field} field: {json}')

        # convert enums
        #asc['?'] = ???(asc['?'])

        # validate substructures
        if not isinstance(snssai['sst'], int):
            raise ValueError(f'''Snssai.sst must be an integer''')
        if snssai['sst'] < 0 or snssai['sst'] > 255:
            raise ValueError(f'''Snssai.sst must be an integer between 0 and 255 inclusive: found Snssai.sst = {snssai['sst']}''')
        if 'sd' in snssai:
            if len(snssai['sd']) != 6 or any(c not in string.hexdigits for c in snssai['sd']):
                raise ValueError(f'''Snssai.sd must be a 6 digit hexadecimal string: found Snssai.sd = {snssai['sd']}''')
        return True

    @staticmethod
    def format(snssai: "Snssai", indent: int = 0) -> str:
        prefix: str = ' ' * indent
        ret: str = f'''{prefix}Sst: {snssai['sst']}'''
        if 'sd' in snssai:
            ret += f"\n{prefix}Sd: {snssai['sd']}"
        return ret

class BitRate(object):
    '''
    BitRate string from TS 29.571
    '''
    def __init__(self, *args, **kwargs):
        if len(args) == 1 and len(kwargs) == 0:
            if isinstance(args[0], bytes):
                args[0] = args[0].decode('utf-8')
            if isinstance(args[0], str):
                self.__bitrate = self.__parseBitrateString(args[0])
            elif isinstance(args[0], int):
                self.__bitrate = float(args[0])
            elif isinstance(args[0], float):
                self.__bitrate = args[0]
            elif isinstance(args[0], BitRate):
                self.__bitrate = args[0].bitrate()
            else:
                raise TypeError(f'BitRate initialiser must be str, int or float: given {type(args[0]).__name__}')
        elif len(args) == 0 and len(kwargs) == 1 and kwargs.keys()[0] in ['bps', 'kbps', 'mbps', 'gbps', 'tbps', 'pbps']:
            k,v = kwargs.items()[0]
            if k == 'bps':
                self.__bitrate = float(v)
            elif k == 'kbps':
                self.__bitrate = v*1000.0
            elif k == 'mbps':
                self.__bitrate = v*1000000.0
            elif k == 'gbps':
                self.__bitrate = v*1000000000.0
            elif k == 'tbps':
                self.__bitrate = v*1000000000000.0
            else: # 'pbps'
                self.__bitrate = v*1000000000000000.0
        else:
            raise ValueError('Only a bitrate string or one of the bitrate keywords can be used to initialise a BitRate')

    def bitrate(self):
        return self.__bitrate

    def __repr__(self) -> str:
        if self.__bitrate < 1000:
            return f'BitRate(bps={self.__bitrate})'
        if self.__bitrate < 1000000:
            return f'BitRate(kbps={self.__bitrate/1000.0})'
        if self.__bitrate < 1000000000:
            return f'BitRate(mbps={self.__bitrate/1000000.0})'
        if self.__bitrate < 1000000000000:
            return f'BitRate(gbps={self.__bitrate/1000000000.0})'
        if self.__bitrate < 1000000000000000:
            return f'BitRate(tbps={self.__bitrate/1000000000000.0})'
        return f'BitRate(pbps={self.__bitrate/1000000000000000.0})'

    def __str__(self) -> str:
        if self.__bitrate < 1000:
            return f'{self.__bitrate} bps'
        if self.__bitrate < 1000000:
            return f'{self.__bitrate/1000.0:.3f} Kbps'
        if self.__bitrate < 1000000000:
            return f'{self.__bitrate/1000000.0:.3f} Mbps'
        if self.__bitrate < 1000000000000:
            return f'{self.__bitrate/1000000000.0:.3f} Gbps'
        if self.__bitrate < 1000000000000000:
            return f'{self.__bitrate/1000000000000.0:.3f} Tbps'
        return f'{self.__bitrate/1000000000000000.0:.3f} Pbps'

    def __jsontype__(self, **options):
        return str(self)

    def __lt__(self, other: Union[int,float,"BitRate"]) -> bool:
        if isinstance(other, int) or isinstance(other, float):
            return self.__bitrate < other
        if isinstance(other, BitRate):
            return other > self.__bitrate
        raise TypeError('Can only compare a BitRate to another BitRate, int or float')

    def __gt__(self, other: Union[int,float,"BitRate"]) -> bool:
        if isinstance(other, int) or isinstance(other, float):
            return self.__bitrate > other
        if isinstance(other, BitRate):
            return other < self.__bitrate
        raise TypeError('Can only compare a BitRate to another BitRate, int or float')

    def __eq__(self, other: Union[int,float,"BitRate"]) -> bool:
        if isinstance(other, int) or isinstance(other, float):
            return self.__bitrate == other
        if isinstance(other, BitRate):
            return other == self.__bitrate
        raise TypeError('Can only compare a BitRate to another BitRate, int or float')

    def __le__(self,  other: Union[int,float,"BitRate"]) -> bool:
        return not self > other

    def __ge__(self,  other: Union[int,float,"BitRate"]) -> bool:
        return not self < other

    def __ne__(self,  other: Union[int,float,"BitRate"]) -> bool:
        return not self == other

    @staticmethod
    def __parseBitrateString(br: str) -> float:
        val,units = (br.split(' ',1) + [None])[:2]
        val = float(val)
        if units not in ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps', 'Pbps']:
            raise ValueError('BitRate string must have units of bps, Kbps, Mbps, Gbps, Tbps or Pbps')
        if units == 'bps':
            return val
        if units == 'Kbps':
            return val*1000.0
        if units == 'Mbps':
            return val*1000000.0
        if units == 'Gbps':
            return val*1000000000.0
        if units == 'Tbps':
            return val*1000000000000.0
        return val*1000000000000000.0

class AppSessionContext(TypedDict, total=False):
    '''
    PolicyTemplate.applicationSessionContext structure in TS 26.512
    '''
    sliceInfo: Snssai
    dnn: str

    @staticmethod
    def fromJSON(asc_json: str) -> "AppSessionContext":
        '''Create an AppSessionContext from a JSON string

        :param str json: The JSON string to parse into a AppSessionContext structure.

        :return: The `AppSessionContext` generated from the JSON string.

        :raise TypeError: If the AppSessionContext is missing mandatory fields.
        :raise ValueError: If the JSON could not be parsed.
        '''
        # parse the JSON
        asc = json.loads(asc_json)
        AppSessionContext.validate(asc, asc_json)
        return AppSessionContext(asc)

    @staticmethod
    def validate(asc: "AppSessionContext", json: str) -> bool:
        # check mandatory fields presence
        #for mandatory_field in AppSessionContextMandatory.__required_keys__:
        #    if mandatory_field not in pt:
        #        raise TypeError(f'AppSessionContext must contain a {mandatory_field} field: {json}')

        # convert enums
        #asc['?'] = ???(asc['?'])

        # validate substructures
        if 'sliceInfo' in asc:
            Snssai.validate(asc['sliceInfo'], json)
        if 'dnn' in asc:
            if not isinstance(asc['dnn'], str):
                raise ValueError(f'''AppSessionContext.dnn must be a string if present''')
        return True

    @classmethod
    def format(cls, asc: "AppSessionContext", indent: int = 0) -> str:
        prefix: str = ' ' * indent
        ret: str = ''
        if 'sliceInfo' in asc:
            ret += f'''{prefix}Slice Info:
{Snssai.format(asc['sliceInfo'], indent+2)}
'''
        if 'dnn' in asc:
            ret += f'''{prefix}Network Name: {asc['dnn']}
'''
        return ret

class M1QoSSpecification(TypedDict, total=False):
    '''
    M1QoSSpecification object from TS 26.512
    '''
    qosReference: str
    maxBtrUl: BitRate
    maxBtrDl: BitRate
    maxAuthBtrUl: BitRate
    maxAuthBtrDl: BitRate
    defPacketLossRateDl: int
    defPacketLossRateUl: int

    @staticmethod
    def fromJSON(qs_json: str) -> "M1QoSSpecification":
        '''Create an M1QoSSpecification from a JSON string

        :param str qs_json: The JSON string to parse into a M1QoSSpecification structure.

        :return: The `M1QoSSpecification` generated from the JSON string.

        :raise TypeError: If the M1QoSSpecification is missing mandatory fields.
        :raise ValueError: If the JSON could not be parsed.
        '''
        # parse the JSON
        try:
            qs = json.loads(qs_json)
        except json.JSONDecodeError as err:
            raise ValueError("Unable to parse JSON as M1QoSSpecification")
        M1QoSSpecification.validate(qs, qs_json)
        return M1QoSSpecification(qs)

    @staticmethod
    def validate(qs: "M1QoSSpecification", json: str) -> bool:
        # check mandatory fields presence
        #for mandatory_field in AppSessionContextMandatory.__required_keys__:
        #    if mandatory_field not in pt:
        #        raise TypeError(f'AppSessionContext must contain a {mandatory_field} field: {json}')

        # convert enums
        #asc['?'] = ???(asc['?'])

        # validate substructures
        for br_field in ['maxBtrUl', 'maxBtrDl', 'maxAuthBtrUl', 'maxAuthBtrDl']:
            if br_field in qs:
                qs[br_field] = BitRate(qs[br_field])
        for lr_field in ['defPacketLossRateDl', 'defPacketLossRateUl']:
            if lr_field in qs:
                if not isinstance(qs[lr_field],int):
                    raise ValueError(f'{lr_field} is {type(qs[lr_field])} not an integer')
                if qs[lr_field] < 0:
                    raise ValueError(f'{lr_field} must be a positive integer')
        return True

    @classmethod
    def format(cls, qs: "M1QoSSpecification", indent: int = 0) -> str:
        prefix: str = ' ' * indent
        ret: str = ''
        if 'qosReference' in qs:
            ret += f'''{prefix}QoS Reference: {qs['qosReference']}
'''
        if 'maxBtrUl' in qs:
            ret += f'''{prefix}Maximum Uplink Bitrate: {qs['maxBtrUl']}
'''
        if 'maxBtrDl' in qs:
            ret += f'''{prefix}Maximum Downlink Bitrate: {qs['maxBtrDl']}
'''
        if 'maxAuthBtrUl' in qs:
            ret += f'''{prefix}Maximum Authorised Uplink Bitrate: {qs['maxAuthBtrUl']}
'''
        if 'maxAuthBtrDl' in qs:
            ret += f'''{prefix}Maximum Authorised Downlink Bitrate: {qs['maxAuthBtrDl']}
'''
        if 'defPacketLossRateDl' in qs:
            ret += f'''{prefix}Default Downlink Packet Loss Rate: {qs['defPacketLossRateDl']} packets/s
'''
        if 'defPacketLossRateUl' in qs:
            ret += f'''{prefix}Default Uplink Packet Loss Rate: {qs['defPacketLossRateUl']} packets/s
'''
        return ret

class SponsoringStatus(enum.Enum):
    '''
    SponsoringStatus enumeration from TS 29.514
    '''
    SPONSOR_DISABLED = enum.auto()  # pylint: disable=invalid-name
    SPONSOR_ENABLED = enum.auto()  # pylint: disable=invalid-name

    def __jsontype__(self, **options):
        return str(self)

    def __str__(self):
        return self.name

class ChargingSpecification(TypedDict, total=False):
    '''
    ChargingSpecification object from TS 26.512
    '''
    sponId: str
    sponStatus: SponsoringStatus
    gpsi: List[str]

    @staticmethod
    def fromJSON(cs_json: str) -> "ChargingSpecification":
        '''Create a ChargingSpecification from a JSON string
        '''
        try:
            cs = json.loads(cs_json)
        except json.JSONDecodeError as err:
            raise ValueError(f'Unable to parse JSON from: {cs_json}')
        ChargingSpecification.validate(cs)
        return ChargingSpecification(cs)

    @staticmethod
    def validate(cs: dict, json: str) -> bool:
        '''Validate a dict as a ChargingSpecification
        '''
        # convert enums
        if 'sponStatus' in cs:
            cs['sponStatus'] = SponsoringStatus[cs['sponStatus']]
        # check types
        if 'sponId' in cs and not isinstance(cs['sponId'], str):
            raise ValueError(f'Sponsor ID should be a string in ChargingSpecification: {json}')
        if 'gpsi' in cs:
            if not isinstance(cs['gpsi'], list):
                raise ValueError(f'GPSI in ChargingSpecification should be a list when present: {json}')
            for v in cs['gpsi']:
                if not isinstance(v, str):
                    raise ValueError(f'GPSI list in ChargingSpecification should only contain strings: {json}')
        return True

    @staticmethod
    def format(cs: "ChargingSpecification", indent: int = 0) -> str:
        '''Format a ChargingSpecification as a multiline string
        '''
        prefix: str = ' ' * indent
        nlprefix: str = f"\n{prefix}"
        ret: str = ''
        if 'sponId' in cs:
            ret += f"{nlprefix}Sponsor ID: {cs['sponId']}"
        if 'sponStatus' in cs:
            ret += f"{nlprefix}Sponsor Status: {cs['sponStatus']}"
        if 'gpsi' in cs:
            ret += f"{nlprefix}GPSIs:{nlprefix}  {f'{nlprefix}  '.join(cs['gpsi'])}"
        return ret[1:]

class PolicyTemplateMandatory(TypedDict):
    '''
    Mandatory fields from PolicyTemplate structure in TS 26.512
    '''
    externalReference: str

class PolicyTemplate(PolicyTemplateMandatory, total=False):
    '''
    PolicyTemplate structure from TS 26.512
    '''
    policyTemplateId: ResourceId
    applicationSessionContext: AppSessionContext
    state: PolicyTemplateState
    stateReason: "ProblemDetail"
    qoSSpecification: M1QoSSpecification
    chargingSpecification: ChargingSpecification

    @staticmethod
    def fromJSON(policy_template_json: str) -> "PolicyTemplate":
        '''Create a PolicyTemplate from a JSON string

        :param str policy_template_json: The JSON string to parse into a PolicyTemplate structure.

        :return: The `PolicyTemplate` generated from the JSON string.

        :raise TypeError: If the PolicyTemplate is missing mandatory fields.
        :raise ValueError: If the JSON could not be parsed.
        '''
        # parse the JSON
        pt = json.loads(policy_template_json)
        PolicyTemplate.validate(pt, policy_template_json)
        return PolicyTemplate(pt)

    @staticmethod
    def validate(pt: "PolicyTemplate", policy_template_json: str) -> bool:
        # check mandatory fields presence
        for mandatory_field in PolicyTemplateMandatory.__required_keys__:
            if mandatory_field not in pt:
                raise TypeError(f'PolicyTemplate must contain a {mandatory_field} field: {policy_template_json}')
        # convert enums
        if 'state' in pt:
            pt['state'] = PolicyTemplateState[pt['state']]
        #ProblemDetail.validate(pt['stateReason'])
        if 'applicationSessionContext' in pt:
            AppSessionContext.validate(pt['applicationSessionContext'], policy_template_json)
        if 'qoSSpecification' in pt:
            M1QoSSpecification.validate(pt['qoSSpecification'], policy_template_json)
        if 'chargingSpecification' in pt:
            ChargingSpecification.validate(pt['chargingSpecification'], policy_template_json)
        return True

    @classmethod
    def format(cls, pt: "PolicyTemplate", indent: int = 0) -> str:
        prefix: str = ' ' * indent
        ret: str = f'''{prefix}PolicyTemplate:
{prefix}  Policy Template Id: {pt['policyTemplateId']}
{prefix}  State: {pt['state']}
{prefix}  State Reason:
{ProblemDetail.format(pt['stateReason'],indent+4)}
{prefix}  External Reference: {pt['externalReference']}
'''
        if 'applicationSessionContext' in pt:
            ret += f"{prefix}  AppSessionContext:\n{AppSessionContext.format(pt['applicationSessionContext'], indent+4)}"
        if 'qoSSpecification' in pt:
            ret += f"{prefix}  QoS Specification:\n{M1QoSSpecification.format(pt['qoSSpecification'], indent+4)}"
        if 'chargingSpecification' in pt:
            ret += f"{prefix}  Charging Specification:\n{ChargingSpecification.format(pt['chargingSpecification'], indent+4)}"
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

    @staticmethod
    def format(ip: "InvalidParam", indent: int = 0):
        prefix = ' ' * indent
        ret = f'''{prefix}Parameter: {ip['param']}
'''
        if 'reason' in ip:
            ret += f"{prefix}Reason: {ip['reason']}\n"
        return ret

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

    def __jsontype__(self, **options):
        return str(self)

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

    @staticmethod
    def format(ate: "AccessTokenErr", indent: int = 0) -> str:
        prefix = ' ' * indent
        ret = f'''{prefix}Error: {ate['error']}'''
        if 'error_description' in ate:
            ret += f"\n{prefix}Description: {ate['error_description']}"
        if 'error_uri' in ate:
            ret += f"\n{prefix}URI: {ate['error_uri']}"
        return ret

class AccessTokenReqGrantType(enum.Enum):
    '''
    AccessTokenReqGrantType enumeration in TS 29.571
    '''
    client_credentials = enum.auto() # pylint: disable=invalid-name

    def __jsontype__(self, **options):
        return str(self)

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

    @staticmethod
    def format(atr: "AccessTokenReq", indent: int = 0) -> str:
        prefix = ' ' * indent
        ret = f'''{prefix}Grant Type: {atr['grant_type']}
{prefix}NF Instance Id: {atr['nfInstanceId']}
{prefix}Scope: {atr['scope']}'''
        if 'nfType' in atr:
            ret += f"\n{prefix}NF Type: {atr['nfType']}"
        if 'requesterPlmn' in atr:
            ret += f"\n{prefix}Requester PLMN: {atr['requesterPlmn']}"
        if 'requesterPlmnList' in atr:
            ret += f"\n{prefix}Requester PLMNs: {', '.join(atr['requesterPlmnList'])}"
        if 'requesterSnssaiList' in atr:
            ret += f"\n{prefix}Requester S-NSSAIs: {', '.join(atr['requesterSnssaiList'])}"
        if 'requesterFqdn' in atr:
            ret += f"\n{prefix}Requester FQDN: {atr['requesterFqdn']}"
        if 'requesterSnpnList' in atr:
            ret += f"\n{prefix}Requester SNPNs: {', '.join(atr['requesterSnpnList'])}"
        if 'targetNfType' in atr:
            ret += f"\n{prefix}Target NF Type: {atr['targetNfType']}"
        if 'targetNfInstanceId' in atr:
            ret += f"\n{prefix}Target NF Instance Id: {atr['targetNfInstanceId']}"
        if 'targetPlmn' in atr:
            ret += f"\n{prefix}Target PLMN: {atr['targetPlmn']}"
        if 'targetSnssaiList' in atr:
            ret += f"\n{prefix}Target S-NSSAIs: {', '.join(atr['targetSnssaiList'])}"
        if 'targetNsiList' in atr:
            ret += f"\n{prefix}Target NSIs: {', '.join(atr['targetNsiList'])}"
        if 'targetNfSetId' in atr:
            ret += f"\n{prefix}Target NF Set Id: {atr['targetNfSetId']}"
        if 'targetNfServiceSetId' in atr:
            ret += f"\n{prefix}Target NF Service Set Id: {atr['targetNfServiceSetId']}"
        if 'hnrfAccessTokenUri' in atr:
            ret += f"\n{prefix}HNRF Access Token Uri: {atr['hnrfAccessTokenUri']}"
        if 'sourceNfInstanceId' in atr:
            ret += f"\n{prefix}Souce NF Instance Id: {atr['sourceNfInstanceId']}"
        return ret

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

    @staticmethod
    def format(pd: "ProblemDetail", indent: int = 0) -> str:
        prefix = ' ' * indent
        ret = ''
        if 'problemtype' in pd:
            ret += f"\n{prefix}Problem Type: {pd['problemtype']}"
        if 'title' in pd:
            ret += f"\n{prefix}Title: {pd['title']}"
        if 'status' in pd:
            ret += f"\n{prefix}Status: {pd['status']}"
        if 'detail' in pd:
            ret += f'''
{prefix}Detail:
{prefix}  {pd['detail']}'''
        if 'instance' in pd:
            ret += f"\n{prefix}Instance: {pd['instance']}"
        if 'cause' in pd:
            ret += f"\n{prefix}Cause: {pd['cause']}"
        if 'invalidParams' in pd:
            ret += f'''
{prefix}Invalid Parameters:
{''.join([InvalidParam.format(p, indent+2) for p in pd['invalidParams']])}'''
        if 'supportedFeatures' in pd:
            ret += f"\n{prefix}Supported Features: {pd['supportedFeatures']}"
        if 'accessTokenError' in pd:
            ret += f'''
{prefix}Access Token Error:
{AccessTokenErr.format(pd['accessTokenError'], indent+2)}'''
        if 'accessTokenRequest' in pd:
            ret += f'''
{prefix}Access Token Request:
{AccessTokenReq.format(pd['accessTokenRequest'], indent+2)}'''
        if 'nrfId' in pd:
            ret += f"\n{prefix}NRF Id: {pd['nrfId']}"
        return ret[1:]

__all__ = [
        "ProblemDetail",
        "AccessTokenErr",
        "AccessTokenReq",
        "InvalidParam",
        "ApplicationId",
        "ResourceId",
        "PolicyTemplate",
        "ProvisioningSessionId",
        "ProvisioningSessionType",
        "ProvisioningSession",
        "PROVISIONING_SESSION_TYPE_DOWNLINK",
        "PROVISIONING_SESSION_TYPE_UPLINK",
        ]
