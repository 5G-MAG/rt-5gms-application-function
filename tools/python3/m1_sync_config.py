#!/usr/bin/python3
#==============================================================================
# 5G-MAG Reference Tools: M1 Session CLI
#==============================================================================
#
# File: m1_sync_config.py
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
# AF configuration sync tool
# ==========================
#
# This is a command line tool which takes a configuration from
# /etc/rt-5gms/streams.json and applies it to the running AF.
#
# Communication with the AF should be preconfigured using m1-session configure.
#
'''
==================================================
5G-MAG Reference Tools: AF configuration sync tool
==================================================

This command line app takes the configuration in /etc/rt-5gms/streams.json and
applies it to a running 5GMS AF using the M1 interface. It also stores M8 JSON
data in the HTTP document roots for any hostnames defined as domainNameAlias 
entries in the streams.json.

This shares some configuration with the m1-session tool and
`m1-session configure` should be used to configure the M1 communication address
and port.

This tool is designed to be run immediately after the AF is started in order to configure the Provisioning Sessions in the AF. As such it will normally only be invoked by t

The streams to configure are found in the /etc/rt-5gms/streams.json file.

**af-sync.conf file**

This file defines configuration values specifically for this AF configuration
sync tool, and can be found at `/etc/rt-5gms/af-sync.conf`.

```ini
[af-sync]
m5_authority = af.example.com:1234
docroot = /var/cache/rt-5gms/as/docroots
default_docroot = /usr/share/nginx/html
```

The *m5_authority* is a URL authority describing the location of the M5
interface to be advertised via the M8 interface.

The *docroot* is the file path of the document roots used by the 5GMS
Application Server. This is for publishing the M8 JSON file. The file will be
placed at `{docroot}/{domain_name}/m8.json`.

The *default_docroot* is for the directory path to the root directory for the
fallback AS listening point. This will normally be `/usr/share/nginx/html`.

**streams.json format**

This file defines the streams to configure and is located at
`/etc/rt-5gms/streams.json`.

```json
{
    "aspId": "MyASPId",
    "appId": "BBCRD5GTestbed",
    "streams": {
        "stream-id-1": {
            "name": "Stream name to appear in 5GMS Aware App",
            "ingestURL": "http://media.example.com/some-media-asset/",
            "distributionConfigurations": [
                {
                    "domainNameAlias": "5gms-as.example.com",
                    "entryPoint": {
                        "relativePath": "media.mpd",
                        "contentType": "application/dash+xml",
                        "profiles": ["urn:mpeg:dash:profile:isoff-live:2011"]
                    }
                },
                {
                    "domainNameAlias": "5gms-as.example.com",
                    "entryPoint": {
                        "relativePath": "media.m3u8",
                        "contentType": "application/vnd.apple.mpegurl"
                    }
                }
            ],
            "consumptionReporting": {
                "reportingInterval": 30,
                "samplePercentage": 66.666,
                "locationReporting": true,
                "accessReporting": true,
            },
            "policies": {
                "policy-external-ref-1": {
                    "applicationSessionContext": {
                        "sliceInfo": {
                            "sst": 1,
                            "sd": "000001"
                        },
                        "dnn": "internet"
                    },
                    "qoSSpecification": {
                        "qosReference": "qos-1",
                        "maxAuthBtrUl": "200 Kbps",
                        "maxAuthBtrDl": "20 Mbps",
                        "defPacketLossRateDl": 0,
                        "defPacketLossRateUl": 0
                    },
                    "chargingSpecification": {
                        "sponId": "sponsor-id-1",
                        "sponsorEnabled": true,
                        "gpsi": ["msimsi-1234567890"]
                    }
                }
            }
        },
        "vod-root-1": {
            "name": "VoD Service Name",
            "ingestURL": "http://media.example.com/",
            "distributionConfigurations": [
                {"domainNameAlias": "5gms-as.example.com"},
                {"domainNameAlias": "5gms-as.example.com", "certificateId": "placeholder1"}
            ],
            "consumptionReporting": {
                "reportingInterval": 20,
                "samplePercentage": 80,
            },
            "policies": {
                "policy-external-ref-1": {}
            }
        }
    },
    "vodMedia": [
        {
            "name": "VoD Stream 1 Name for UE",
            "stream": "vod-root-1",
            "entryPoints": [
                {
                    "relativePath": "stream1/media.mpd",
                    "contentType": "application/dash+xml",
                    "profiles": ["urn:mpeg:dash:profile:isoff-live:2011"]
                },
                {
                    "relativePath": "stream1/media.m3u8",
                    "contentType": "application/vnd.apple.mpegurl"
                }
            ]
        },
        {
            "name": "VoD Stream 2 Name for UE",
            "stream": "vod-root-1",
            "entryPoints": [
                {
                    "relativePath": "stream2/media.mpd",
                    "contentType": "application/dash+xml",
                    "profiles": ["urn:mpeg:dash:profile:isoff-live:2011"]
                },
                {
                    "relativePath": "stream2/media.m3u8",
                    "contentType": "application/vnd.apple.mpegurl"
                }
            ]
        }
    ]
}
```

The *aspId* is optional and is the ASP identifier for the provisioning sessions.

The *appId* is the mandatory external application identifier for the
provisioning sessions.

The *streams* map lists Provisioning Session configurations with a local
identfier as the map key. This identifier can be used in the *vodMedia* list to
identfiy the stream used for VoD media lists (media entry points described in
the M8 interface). If a stream contains *entryPoint* fields in the
*distributionConfigurations* then these will be advertised via M5 only and will
not appear in the M8 entry points. The *consumptionReporting* parameters, if
present, will configure consumption reporting for the Provisioning Session. See
3GPP TS 26.512 for a discription of what may appear in a
DistributionConfiguration or the ConsumptionReportingConfiguration.

The *vodMedia* list is for describing media and their entry points that use a
common Provisioning Session. The Provisioning Session is identfied by the
*stream* field which is a reference to a key in the *streams* map. The entry in
the *streams* map should not have any *distributionConfigurations.entryPoint*
fields defined so that it acts as a top level ingest point for multiple media.
'''

import aiofiles
import asyncio
import configparser
import importlib
import json
import logging
import os.path
import sys
from typing import List, Optional

installed_packages_dir = '@python_packages_dir@'
if os.path.isdir(installed_packages_dir) and installed_packages_dir not in sys.path:
    sys.path.append(installed_packages_dir)

from rt_m1_client.session import M1Session
from rt_m1_client.exceptions import M1Error
from rt_m1_client.data_store import JSONFileDataStore
from rt_m1_client.types import ContentHostingConfiguration, DistributionConfiguration, IngestConfiguration, M1MediaEntryPoint, PathRewriteRule, ConsumptionReportingConfiguration, PolicyTemplate, M1QoSSpecification, ChargingSpecification, AppSessionContext, Snssai
from rt_m1_client.configuration import Configuration

g_streams_config = os.path.join(os.path.sep, 'etc', 'rt-5gms', 'streams.json')
g_sync_config = os.path.join(os.path.sep, 'etc', 'rt-5gms', 'af-sync.conf')

logging.basicConfig(level=logging.INFO)
g_log = logging.getLogger(__name__)

def log_debug(*args, **kwargs):
    global g_log
    g_log.debug(*args, **kwargs)

def log_info(*args, **kwargs):
    global g_log
    g_log.info(*args, **kwargs)

def log_warn(*args, **kwargs):
    global g_log
    g_log.warn(*args, **kwargs)

def log_error(*args, **kwargs):
    global g_log
    g_log.error(*args, **kwargs)

async def path_rewrite_rule_equal(a: PathRewriteRule, b: PathRewriteRule) -> bool:
    if a['requestPathPattern'] != b['requestPathPattern']:
        return False
    if a['mappedPath'] != b['mappedPath']:
        return False
    return True

async def path_rewrite_rules_equal(a: List[PathRewriteRule], b: List[PathRewriteRule]) -> bool:
    if len(a) != len(b):
        return False
    for prr_a in a:
        for prr_b in b:
            if await path_rewrite_rule_equal(prr_a, prr_b):
                break
        else:
            return False
    return True

async def entry_points_equal(a: M1MediaEntryPoint, b: M1MediaEntryPoint) -> bool:
    if a['relativePath'] != b['relativePath']:
        return False
    if a['contentType'] != b['contentType']:
        return False
    if 'profiles' not in a and 'profiles' not in b:
        return True
    if 'profiles' in a and 'profiles' in b and set(a['profiles']) == set(b['profiles']):
        return True
    return False

async def distrib_config_equal(a: DistributionConfiguration, b: DistributionConfiguration) -> bool:
    a_keys = set(a.keys())
    b_keys = set(b.keys())
    # Ignore fields generated by the AF
    for gen_field in ['canonicalDomainName', 'baseURL']:
        a_keys.discard(gen_field)
        b_keys.discard(gen_field)
    # Distribution configuration must have the same fields present
    if a_keys != b_keys:
        return False

    if 'entryPoint' in a and not await entry_points_equal(a['entryPoint'], b['entryPoint']):
        return False
    if 'contentPreparationTemplateId' in a and a['contentPreparationTemplateId'] != b['contentPreparationTemplateId']:
        return False
    if 'domainNameAlias' in a and a['domainNameAlias'] != b['domainNameAlias']:
        return False
    if 'pathRewriteRules' in a and not await path_rewrite_rules_equal(a['pathRewriteRules'], b['pathRewriteRules']):
        return False

    # Ignore: cachingConfigurations, geoFencing, urlSignature, supplementaryDistributionNetworks

    return True

async def distrib_configs_equal(a: List[DistributionConfiguration], b: List[DistributionConfiguration]) -> bool:
    if len(a) != len(b):
        return False
    for dc_a in a:
        for dc_b in b:
            if await distrib_config_equal(dc_a, dc_b):
                break
        else:
            return False
    return True

async def _flagsEqual(a: Optional[bool], b: Optional[bool]) -> bool:
    if a is None and b is None:
        return True
    if a is None and b is not None and not b:
        return True
    if b is None and a is not None and not a:
        return True
    if a is not None and b is not None and a == b:
        return True
    return False

async def consumption_reporting_equal(a: Optional[ConsumptionReportingConfiguration], b: Optional[ConsumptionReportingConfiguration]) -> bool:
    if a is None and b is None:
        return True
    if a is None and b is not None:
        return False
    if b is None and a is not None:
        return False
    for i in ['locationReporting', 'accessReporting']:
        if not await _flagsEqual(a.get(i, None), b.get(i, None)):
            return False
    for i in ['reportingInterval', 'samplePercentage']:
        if i in a and i not in b:
            return False
        if i in b and i not in a:
            return False
        if i in a and a[i] != b[i]:
            return False
    return True

async def snssai_match(sai1: Optional[Snssai], sai2: Optional[Snssai]) -> bool:
    if sai1 is None and sai2 is None:
        return True
    if sai1 is None or sai2 is None:
        return False
    for i in ['sst', 'sd']:
        if i not in sai1 and i in sai2:
            return False
        if i in sai1 and i not in sai2:
            return False
        if i in sai1 and sai1[i] != sai2[i]:
            return False
    return True

async def m1_qos_specs_match(qos1: Optional[M1QoSSpecification], qos2: Optional[M1QoSSpecification]) -> bool:
    if qos1 is None and qos2 is None:
        return True
    if qos1 is None or qos2 is None:
        return False
    for i in ['qosReference', 'maxAuthBtrUl', 'maxAuthBtrDl', 'defPacketLossRateDl', 'defPacketLossRateUl']:
        if i not in qos1 and i in qos2:
            return False
        if i in qos1 and i not in qos2:
            return False
        if i in qos1 and qos1[i] != qos2[i]:
            return False
    return True

async def policy_app_sessions_match(as1: Optional[AppSessionContext], as2: Optional[AppSessionContext]) -> bool:
    if as1 is None and as2 is None:
        return True
    if as1 is None or as2 is None:
        return False
    if not await snssai_match(as1.get('sliceInfo', None), as2.get('sliceInfo', None)):
        return False
    if 'dnn' not in as1 and 'dnn' in as2:
        return False
    if 'dnn' in as1 and 'dnn' not in as2:
        return False
    if 'dnn' in as1 and as1['dnn'] != as2['dnn']:
        return False
    return True

async def charging_specs_match(cs1: Optional[ChargingSpecification], cs2: Optional[ChargingSpecification]) -> bool:
    if cs1 is None and cs2 is None:
        return True
    if cs1 is None or cs2 is None:
        return False
    for i in ['sponId', 'sponStatus']:
        if i in cs1 and i not in cs2:
            return False
        if i not in cs1 and i in cs2:
            return False
        if i in cs1 and cs1[i] != cs2[i]:
            return False
    if 'gpsi' in cs1 and 'gpsi' not in cs2:
        return False
    if 'gpsi' not in cs1 and 'gpsi' in cs2:
        return False
    if 'gpsi' in cs1 and sorted(cs1['gpsi']) != sorted(cs2['gpsi']):
        return False
    return True

async def policies_match(p1: Optional[PolicyTemplate], p2: Optional[PolicyTemplate]) -> bool:
    if p1 is None and p2 is None:
        return True
    if p1 is None or p2 is None:
        return False
    if 'externalReference' in p1 and 'externalReference' not in p2:
        return False
    if 'externalReference' not in p1 and 'externalReference' in p2:
        return False
    if 'externalReference' in p1 and p1['externalReference'] != p2['externalReference']:
        return False
    if not await policy_app_sessions_match(p1.get('applicationSessionContext', None), p2.get('applicationSessionContext', None)):
        return False
    # ignore read-only fields policyTemplateId, state and stateReason
    if not await m1_qos_specs_match(p1.get('qoSSpecification', None), p2.get('qoSSpecification', None)):
        return False
    if not await charging_specs_match(p1.get('chargingSpecification', None), p2.get('chargingSpecification', None)):
        return False
    return True

async def sync_configuration(m1: M1Session, streams: dict) -> dict:
    have = {}
    to_check = streams['streams']
    del_ps_id = []
    stream_map = {}
    for ps_id in await m1.provisioningSessionIds():
        chc = await m1.contentHostingConfigurationGet(ps_id)
        if chc is None:
            log_warn(f'Provisioning Session {ps_id} has no ContentHostingConfiguration, removing from the AF')
            del_ps_id += [ps_id]
            continue
        for chk_id, chk_stream in to_check.items():
            if (
                    chk_stream['name'] == chc['name'] and
                    chk_stream['ingestURL'] == chc['ingestConfiguration']['baseURL'] and
                    await distrib_configs_equal(chk_stream['distributionConfigurations'], chc['distributionConfigurations'])
                    ):
                del to_check[chk_id]
                have[chk_id] = chk_stream
                stream_map[chk_id] = ps_id
                break
        else:
            del_ps_id += [ps_id]
    # have = already configured, to_check = need to configure, del_ps_id = configuration not found in the configured streams
    for ps_id in del_ps_id:
        await m1.provisioningSessionDestroy(ps_id)
    for cfg_id, cfg in to_check.items():
        chc = { 'name': cfg['name'],
                'ingestConfiguration': {
                    'baseURL': cfg['ingestURL'],
                    'pull': True,
                    'protocol': 'urn:3gpp:5gms:content-protocol:http-pull-ingest',
                },
                'distributionConfigurations': cfg['distributionConfigurations'],
                }
        crc = cfg.get('consumptionReporting', None)
        policies = cfg.get('policies', None)
        ps_id = await m1.createDownlinkPullProvisioningSession(streams.get('appId'), streams.get('aspId', None))
        if ps_id is None:
            log_error("Failed to create Provisioning Session for %r", cfg)
        else:
            stream_map[cfg_id] = ps_id
            certs = {}
            for dc in chc['distributionConfigurations']:
                if 'certificateId' in dc:
                    if dc['certificateId'] not in certs:
                        cert_id = await m1.createNewCertificate(ps_id, extra_domain_names=dc.get('domainNameAlias', None))
                        if cert_id is None:
                            log_error("Failed to create certificate for Provisioning Session %s, skipping %r", ps_id, cfg)
                            chc = None
                            break
                        certs[dc['certificateId']] = cert_id
                    else:
                        cert_id = certs[dc['certificateId']]
                    dc['certificateId'] = cert_id
            if chc is not None:
                if not await m1.contentHostingConfigurationCreate(ps_id, chc):
                    log_error("Failed to create ContentHostingConfiguration for Provisioning Session %s, skipping %r", ps_id, cfg)
            if crc is not None:
                if not await m1.consumptionReportingConfigurationCreate(ps_id, crc):
                    log_error("Failed to activate ConsumptionReportingConfiguration for Provisioning Session %s")
            if policies is not None:
                if isinstance(policies,dict):
                    pol_list = policies.items()
                elif isinstance(policies,list):
                    pol_list = [(p.get('externalReference', None), p) for p in policies]
                else:
                    log_error(f'Configured policies for provisioning session "{cfg_id}" should be an object or array')
                    pol_list = None
                if pol_list is not None:
                    for ext_id, pol in pol_list:
                        pt = dict()
                        if ext_id is not None:
                            pt.update({'externalReference': ext_id})
                        pt.update(pol)
                        result = await m1.policyTemplateCreate(ps_id, pt)
                        if result is None:
                            log_error(f'Failed to create policy template {ext_id!r} in provisioning session {ps_id}')
    # Check for other changes in the configured sessions
    for cfg_id, cfg in have.items():
        # Check for ConsumptionReportingConfiguration changes in already configured sessions
        ps_id = stream_map[cfg_id]
        old_crc: Optional[ConsumptionReportingConfiguration] = await m1.consumptionReportingConfigurationGet(ps_id)
        new_crc: Optional[ConsumptionReportingConfiguration] = cfg.get('consumptionReporting', None)
        if not await consumption_reporting_equal(old_crc, new_crc):
            if old_crc is None:
                # No pre-existing CRC, add the new one
                if not await m1.consumptionReportingConfigurationCreate(ps_id, new_crc):
                    log_error("Failed to activate ConsumptionReportingConfiguration for Provisioning Session %s", ps_id)
            elif new_crc is None:
                # There is a CRC, but shouldn't be one, remove it
                if not await m1.consumptionReportingConfigurationDelete(ps_id):
                    log_error("Failed to remove ConsumptionReportingConfiguration for Provisioning Session %s", ps_id)
            else:
                # The CRC has changed, update it
                if not await m1.consumptionReportingConfigurationUpdate(ps_id, new_crc):
                    log_error("Failed to update ConsumptionReportingConfiguration for Provisioning Session %s", ps_id)
        # Check PolicyTemplates for changes in the already configured sessions
        del_policy: List[ResourceId] = []
        have_policy: List[ResourceId] = []
        new_policy: List[PolicyTemplate] = []
        old_pol_ids: Optional[List[ResourceId]] = await m1.policyTemplateIds(ps_id)
        policies = cfg.get('policies', None)
        pol_list = None
        if policies is not None:
            if isinstance(policies,dict):
                pol_list = policies.items()
            elif isinstance(policies,list):
                pol_list = [(p.get('externalReference', None), p) for p in policies]
            else:
                log_error(f'Configured policies for provisioning session "{cfg_id}" should be an object or array')
        if old_pol_ids is None or len(old_pol_ids) == 0:
            if policies is not None:
                if pol_list is not None:
                    for pol_ext_id, pol in pol_list:
                        pt = dict()
                        if pol_ext_id is not None:
                            pt.update({'externalReference': pol_ext_id})
                        pt.update(pol)
                        new_policy += [pt]
        else:
            new_pol_left = pol_list
            for pol_id in old_pol_ids:
                if new_pol_left is None or len(new_pol_left) == 0:
                    del_policy += [pol_id]
                else:
                    old_pol: Optional[PolicyTemplate] = await m1.policyTemplateGet(ps_id, pol_id)
                    next_new_pol_list = []
                    found = False
                    for pol_ext_id, pol in new_pol_left:
                        if not found and await policies_match(old_pol, pol):
                            have_policy += [pol_id]
                            found = True
                        else:
                            next_new_pol_list += [(pol_ext_id, pol)]
                    if not found:
                        del_policy += [pol_id]
                    new_pol_left = next_new_pol_list
            for pol_ext_id, pol in new_pol_left:
                pt = dict()
                if pol_ext_id is not None:
                    pt.update({'externalReference': pol_ext_id})
                pt.update(pol)
                new_policy += [pt]
        # Now we have del_policy as a list of policy ids to delete, have_policy as a list of ids to keep and new_policy as a list
        # of new policies to add.
        for pol_id in del_policy:
            await m1.policyTemplateDelete(ps_id, pol_id)
        for pol in new_policy:
            await m1.policyTemplateCreate(ps_id, pol)
    return stream_map

async def get_app_config() -> configparser.ConfigParser:
    global g_sync_config
    config = configparser.ConfigParser()
    config.read_string('''
[af-sync]
m5_authority = 127.0.0.23:7777
docroot = /var/cache/rt-5gms/as/docroots
default_docroot = /usr/share/nginx/html
''', source='defaults')
    async with aiofiles.open(g_sync_config, mode='r') as conffile:
        config.read_string(await conffile.read(), source=g_sync_config)
    return config

async def get_streams_config() -> dict:
    global g_streams_config
    async with aiofiles.open(g_streams_config, mode='r') as infile:
        streams = json.loads(await infile.read())
    return streams

async def get_m1_session(cfg: Configuration) -> M1Session:
    data_store = None
    data_store_dir = cfg.get('data_store')
    if data_store_dir is not None:
        data_store = await JSONFileDataStore(data_store_dir)
    session = await M1Session((cfg.get('m1_address', 'localhost'), cfg.get('m1_port',7777)), data_store, cfg.get('certificate_signing_class'))
    return session

async def dump_m8_files(m1: M1Session, stream_map: dict, vod_streams: List[dict], cfg: Configuration, config: configparser.ConfigParser):
    # Assume M5 and M1 share an interface
    m8_config = {'m5BaseUrl': f'http://{config.get("af-sync", "m5_authority")}/3gpp-m5/v2/', 'serviceList': []}
    publish_dirs = {config.get("af-sync", "default_docroot")}
    vod_stream_ids = set([v['stream'] for v in vod_streams])
    vod_ps_ids = set([v for k,v in stream_map.items() if k in vod_stream_ids])
    for ps_id in await m1.provisioningSessionIds():
        log_debug("Probing Provisioning Session %s", ps_id)
        chc = await m1.contentHostingConfigurationGet(ps_id)
        if chc is not None:
            if ps_id not in vod_ps_ids:
                m8_config['serviceList'] += [{'provisioningSessionId': ps_id, 'name': chc['name']}]
            for dc in chc['distributionConfigurations']:
                for hostfield in ['canonicalDomainName', 'domainNameAlias']:
                    if hostfield in dc:
                        publish_dirs.add(os.path.join(config.get("af-sync", "docroot"), dc[hostfield]))
        else:
            log_error(f"Provisioning Session {ps_id} was not initialised correctly: omitting")
    for vod in vod_streams:
        ps_id = stream_map[vod['stream']]
        chc = await m1.contentHostingConfigurationGet(ps_id)
        if chc is not None:
            entryPoints = []
            for vep in vod['entryPoints']:
                for dc in chc['distributionConfigurations']:
                    ep = {'locator': dc['baseURL'] + vep['relativePath'], 'contentType': vep['contentType']}
                    if 'profiles' in vep:
                        ep['profiles'] = vep['profiles']
                    entryPoints += [ep]
            m8_config['serviceList'] += [{'provisioningSessionId': ps_id, 'name': vod['name'], 'entryPoints': entryPoints}]
        else:
            log_error(f"Provisioning Session {ps_id} not initialised correctly: unable to include '{vod['name']}' in M8 data")
    m8_json = json.dumps(m8_config)
    log_debug("m8_json = %r", m8_json)
    log_info("Publishing M8 info to: %s", ', '.join(publish_dirs))
    for pdir in publish_dirs:
        pfile = os.path.join(pdir, 'm8.json')
        async with aiofiles.open(pfile, mode='w') as outfile:
            await outfile.write(m8_json)

async def main():
    cfg = Configuration()
    session = await get_m1_session(cfg)
    streams = await get_streams_config()
    config = await get_app_config()

    stream_map = await sync_configuration(session, streams)

    await dump_m8_files(session, stream_map, streams['vodMedia'], cfg, config)

    return 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

# vim:ts=8:sts=4:sw=4:expandtab:
