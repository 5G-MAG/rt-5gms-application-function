#!/usr/bin/python3
#==============================================================================
# 5G-MAG Reference Tools: M1 Session CLI
#==============================================================================
#
# File: m1_session_cli.py
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
# M1 Session CLI
# ===============
#
# This is a command line tool to perform operations on the 5GMS Application
# Function via the M1 interface.
#
'''
======================================
5G-MAG Reference Tools: M1 Session CLI
======================================

Perform operations on the 5GMS Application Function via the interface at
reference point M1.

Syntax:
    m1-session-cli -h
    m1-session-cli configure -h
    m1-session-cli configure show
    m1-session-cli configure set <key> <value>
    m1-session-cli configure get <key>
    m1-session-cli list -h
    m1-session-cli list [-v]
    m1-session-cli new-provisioning-session -h
    m1-session-cli new-provisioning-session [-e <application-id>] [-a <asp-id>]
    m1-session-cli new-stream [-e <application-id>] [-a <asp-id>] [-n <name>] [--with-ssl|--ssl-only]
                              <ingest-URL> [<entry-point-suffix-URL>]
    m1-session-cli del-stream -h
    m1-session-cli del-stream -p <provisioning-session-id>
    m1-session-cli del-stream <ingest-URL> [<entry-point-suffix-URL>]
    m1-session-cli set-stream -h
    m1-session-cli set-stream -p <provisioning-session-id> <ContentHostingConfiguration-JSON>
    m1-session-cli new-certificate -h
    m1-session-cli new-certificate -p <provisioning-session-id> [-d <domain-name>...] [--csr]
    m1-session-cli show-certificate -h
    m1-session-cli show-certificate -p <provisioning-session-id> -c <certificate-id>
    m1-session-cli set-certificate -h
    m1-session-cli set-certificate -p <provisioning-session-id> -c <certificate-id> [<certificate-PEM-file>]
    m1-session-cli del-certificate -h
    m1-session-cli del-certificate -p <provisioning-session-id> -c <certificate-id>
    m1-session-cli check-certificates-renewal -h
    m1-session-cli check-certificates-renewal
    m1-session-cli renew-certificates -h
    m1-session-cli renew-certificates -p <provisioning-session-id>
    m1-session-cli renew-certificates <ingest-URL> [<entry-point-suffix-URL>]
    m1-session-cli set-consumption-reporting -h
    m1-session-cli set-consumption-reporting -p <provisioning-session-id> [-i <interval>] [-s <sample-percent>] [-l] [-A]
    m1-session-cli show-consumption-reporting -h
    m1-session-cli show-consumption-reporting -p <provisioning-session-id>
    m1-session-cli del-consumption-reporting -h
    m1-session-cli del-consumption-reporting -p <provisioning-session-id>
    m1-session-cli new-policy-template -h
    m1-session-cli new-policy-template -p <provisioning-session-id> -e <external-policy-id> [-D <dnn>] [-S <s-nssai>]
                                       [--qos-reference <qos-ref>] [--max-up <bitrate>] [--max-down <bitrate>]
                                       [--max-auth-up <bitrate>] [--max-auth-down <bitrate>]
                                       [--default-packet-loss-up <rate>] [--default-packet-loss-down <rate>]
                                       [--chg-sponsor-id <sponsor-id>] [--chg-sponsor-enabled|--chg-sponsor-disabled]
                                       [--gpsi <gpsi>]...
    m1-session-cli update-policy-template -h
    m1-session-cli update-policy-template -p <provisioning-session-id> -t <policy-template-id> [-D <dnn>] [-S <s-nssai>]
                                       [--qos-reference <qos-ref>] [--max-up <bitrate>] [--max-down <bitrate>]
                                       [--max-auth-up <bitrate>] [--max-auth-down <bitrate>]
                                       [--default-packet-loss-up <rate>] [--default-packet-loss-down <rate>]
                                       [--chg-sponsor-id <sponsor-id>]
                                       [--chg-sponsor-enabled|--chg-sponsor-disabled|--chg-sponsor-none]
                                       [--gpsi <gpsi> [--gpsi <gpsi>]...|--no-gpsi]
    m1-session-cli del-policy-template -h
    m1-session-cli del-policy-template -p <provisioning-session-id> -t <policy-template-id>
    m1-session-cli show-policy-template -h
    m1-session-cli show-policy-template -p <provisioning-session-id> -t <policy-template-id>

Parameters:
    -a ID   --asp-id ID                      The application service provider id.
    -A      --access-reporting               Include access reporting.
    -c ID   --certificate-id ID              The certificate id to operate on.
    -d FQDN --domain-name-alias FQDN         The alternate domain name to use.
    -D DNN  --designated-network-name DNN    The designated network name to set in a policy template.
    -e ID   --external-app-id ID             The external application id.
    -h      --help                           Display the help message.
    -i SEC  --interval SEC                   The reporting interval in seconds.
    -l      --location-reporting             Include location reporting.
    -n NAME --name NAME                      The hosting name.
    -p ID   --provisioning-session-id ID     The provisioning session id to use.
    -s PCT  --sample-percentage PCT          The sampling percentage.
    -S ID   --s-nssai ID                     The 6 digit S-NSSAI for the policy template.
    -t ID   --policy-template-id ID          The policy template id to use.
            --ssl-only                       Provide HTTPS only.
            --with-ssl                       Provide both HTTPS and HTTP.
            --csr                            When reserving a cetrificate, pass back the CSR.
            --qos-reference REF              The QoS Reference name.
            --max-up BITRATE                 The QoS maximum uplink bitrate.
            --max-down BITRATE               The QoS maximum downlink bitrate.
            --max-auth-up BITRATE            The QoS maximum authorised uplink bitrate.
            --max-auth-down BITRATE          The QoS maximum authorised downlink bitrate.
            --default-packet-loss-up RATE    The QoS default packet loss rate for uplink traffic.
            --default-packet-loss-down RATE  The QoS default packet loss rate for downlink traffic.
            --chg-sponsor-id ID              The charging specification sponsor id.
            --chg-sponsor-enabled            The charging sponsor is enabled flag.
            --chg-sponsor-disabled           The charging sponsor is disabled flag.
            --chg-sponsor-none               Remove the charging sponsor flag on update.
            --gpsi GPSI                      A charging GPSI value (may be given multiple times).
            --no-gpsi                        Remove all charging GPSI values on update.

Arguments:
    certificate-PEM-file              The file path of a PEM holding a public certificate.
    ContentHostingConfiguration-JSON  The file path of a JSON file holding a ContentHostingConfiguration.
    entry-point-suffix-URL            Optional media entry URL path.
    ingest-URL                        The base URL to fetch content from.
    key                               The configuration field name.
    value                             The configuration field value.
'''

import aiofiles
import argparse
import asyncio
import configparser
import copy
import datetime
from io import StringIO
import logging
import os
import os.path
import sys
import traceback
from typing import Tuple, List, Optional

#logging.basicConfig(level=logging.DEBUG)

import json
import OpenSSL

installed_packages_dir = '@python_packages_dir@'
if os.path.isdir(installed_packages_dir) and installed_packages_dir not in sys.path:
    sys.path.append(installed_packages_dir)

from rt_m1_client.session import M1Session
from rt_m1_client.exceptions import M1Error
from rt_m1_client.data_store import JSONFileDataStore
from rt_m1_client.types import ContentHostingConfiguration, ConsumptionReportingConfiguration, PolicyTemplate, BitRate, SponsoringStatus
from rt_m1_client.configuration import Configuration

async def cmd_configure_show(args: argparse.Namespace, config: Configuration) -> int:
    '''Perform ``configure show`` operation

    Will write to stdout the current configuration.
    '''
    default_marker = {True: ' (default)', False: ''}
    print('Configuration settings:')
    print('\n'.join([f'{key} = {config.get(key, raw=True)}{default_marker[config.isDefault(key)]}' for key in config.getKeys()]))
    return 0

async def cmd_configure_reset(args: argparse.Namespace, config: Configuration) -> int:
    '''Perform ``configure reset`` operation

    Will reset the configuration option *key* back to its default value.
    '''
    config.resetValue(args.key)
    return 0

async def cmd_configure_get(args: argparse.Namespace, config: Configuration) -> int:
    '''Perform ``configure get`` operation

    Write to stdout an interpolated configuration option in the form ``<key>="<value>"``. This could be evaluated in an external
    shell.
    '''
    print(f'{args.key}={repr(config.get(args.key))}')
    return 0

async def cmd_configure_set(args: argparse.Namespace, config: Configuration) -> int:
    '''Perform ``configure set`` operation

    Set a configuration value and save the new configuration.
    '''
    config.set(args.key, args.value)
    return 0

def __formatX509Name(x509name: OpenSSL.crypto.X509Name) -> str:
    '''Format an X509Name as a comma separated DN string

    :meta private:
    :param OpenSSL.crypto.X509Name x509name: The X509 name to convert to a string.
    :return: a ``str`` version of the X509 Name as comma separated DN fields.
    :rtype: str
    '''
    ret = ",".join([f"{name.decode('utf-8')}={value.decode('utf-8')}" for name,value in x509name.get_components()])
    return ret

async def __prettyPrintCertificate(cert: str, indent: int = 0) -> None:
    '''Print certificate information from X509 PEM data

    :param str cert: X509 certificate encoded as PEM data
    :param int indent: The indent to use in the certificate output
    '''
    try:
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    except OpenSSL.crypto.Error as err:
        print(f'{" "*indent} Certificate not understood as PEM data: {err}')
        return
    serial = x509.get_serial_number()
    subject = x509.get_subject()
    issuer = x509.get_issuer()
    start_str = x509.get_notBefore()
    if isinstance(start_str, bytes):
        start_str = start_str.decode('utf-8')
    start = datetime.datetime.strptime(start_str, '%Y%m%d%H%M%SZ').replace(tzinfo=datetime.timezone.utc)
    end_str = x509.get_notAfter()
    if isinstance(end_str, bytes):
        end_str = end_str.decode('utf-8')
    end = datetime.datetime.strptime(end_str, '%Y%m%d%H%M%SZ').replace(tzinfo=datetime.timezone.utc)
    subject_key = None
    issuer_key = None
    sans = []
    for ext_num in range(x509.get_extension_count()):
        ext = x509.get_extension(ext_num)
        ext_name = ext.get_short_name().decode('utf-8')
        if ext_name == "subjectKeyIdentifier":
            subject_key = str(ext)
        elif ext_name == "authorityKeyIdentifier":
            issuer_key = str(ext)
        elif ext_name == "subjectAltName":
            sans += [s.strip() for s in str(ext).split(',')]
    cert_info_prefix=' '*indent
    cert_desc=f'{cert_info_prefix}Serial = {serial}\n{cert_info_prefix}Not before = {start}\n{cert_info_prefix}Not after = {end}\n{cert_info_prefix}Subject = {__formatX509Name(subject)}\n'
    if subject_key is not None:
        cert_desc += f'{cert_info_prefix}          key={subject_key}\n'
    cert_desc += f'{cert_info_prefix}Issuer = {__formatX509Name(issuer)}'
    if issuer_key is not None:
        cert_desc += f'\n{cert_info_prefix}         key={issuer_key}'
    if len(sans) > 0:
        cert_desc += f'\n{cert_info_prefix}Subject Alternative Names:'
        cert_desc += ''.join([f'\n{cert_info_prefix}  {san}' for san in sans])
    print(f'{cert_desc}')

async def cmd_list_verbose(args: argparse.Namespace, config: Configuration) -> int:
    '''Perform ``list -v`` operation

    Output to stdout a verbose list of the defined provisioning sessions and their resources.
    '''
    session = await get_session(config)
    for ps_id in await session.provisioningSessionIds():
        print(f'{ps_id}:')
        certs = await session.certificateIds(ps_id)
        print('  Certificates:')
        for cert_id in certs:
            print(f'    {cert_id}:')
            try:
                cert = await session.certificateGet(ps_id, cert_id)
                if cert is not None:
                    await __prettyPrintCertificate(cert, indent=6)
                else:
                    print('      Certificate not yet uploaded')
            except M1Error as err:
                print(f'      Certificate not available: {str(err)}')
        chc = await session.contentHostingConfigurationGet(ps_id)
        print('  ContentHostingConfiguration:')
        if chc is not None:
            print('\n'.join(['    '+line for line in ContentHostingConfiguration.format(chc).split('\n')]))
        else:
            print('    Not defined')
        crc = await session.consumptionReportingConfigurationGet(ps_id)
        print('  ConsumptionReportingConfiguration:')
        if crc is not None:
            print(ConsumptionReportingConfiguration.format(crc, indent=4))
        else:
            print('    Not defined')
        pol_ids = await session.policyTemplateIds(ps_id)
        if pol_ids is not None and len(pol_ids) > 0:
            print('  PolicyTemplates:')
            for polid in pol_ids:
                print(f'    {polid}:')
                pol = await session.policyTemplateGet(ps_id, polid)
                if pol is not None:
                    print(PolicyTemplate.format(pol, indent=6))
    return 0

async def cmd_list(args: argparse.Namespace, config: Configuration) -> int:
    '''Perform ``list`` operation

    Output to stdout a list of the defined provisioning session ids, one per line.
    '''
    if args.verbose:
        return await cmd_list_verbose(args, config)
    session = await get_session(config)
    print('\n'.join(await session.provisioningSessionIds()))
    return 0

async def cmd_new_provisioning_session(args: argparse.Namespace, config: Configuration) -> int:
    '''Perform ``new-provisioning-session`` operation

    This will reserve a new, empty, provisioning session.

    Will output to stdout the result including the new provisioning session id.
    '''
    session = await get_session(config)
    app_id = args.app_id or config.get('external_app_id')
    asp_id = args.asp_id or config.get('asp_id')
    provisioning_session_id: Optional[ResourceId] = await session.createDownlinkPullProvisioningSession(app_id, asp_id=asp_id)
    if provisioning_session_id is None:
        print(f'Failed to create a new provisioing session')
        return 1
    print(f'Provisioning session {provisioning_session_id} created')
    return 0

async def cmd_set_stream(args: argparse.Namespace, config: Configuration) -> int:
    '''Perform ``set-stream`` operation

    This will set the ContentHostingConfiguration for a provisioning session.

    Will output to stdout the result.
    '''
    session = await get_session(config)
    provisioning_session_id = args.provisioning_session

    async with aiofiles.open(args.file, 'r') as json_in:
        chc = json.loads(await json_in.read())
    old_chc = await session.contentHostingConfigurationGet(provisioning_session_id)
    if old_chc is None:
        result = await session.contentHostingConfigurationCreate(provisioning_session_id, chc)
    else:
        # Remove any read-only fields
        for dc in chc['distributionConfigurations']:
            for strip_field in ['canonicalDomainName', 'baseURL']:
                if strip_field in dc:
                    del dc[strip_field]
        result = await session.contentHostingConfigurationUpdate(provisioning_session_id, chc)
    if not result:
        print(f'Failed to set hosting for provisioning session {provisioning_session_id}')
        return 1
    print(f'Hosting set for provisioning session {provisioning_session_id}')
    return 0

async def cmd_new_stream(args: argparse.Namespace, config: Configuration) -> int:
    '''Perform ``new-stream`` operation

    This will generate and set the ContentHostingConfiguration for a provisioning session. If asked to provide an SSL distribution
    point it will also generate the ServerCertificate within the provisioning session.

    Will output to stdout the result.
    '''
    session = await get_session(config)
    name = args.name
    use_ssl = args.with_ssl or args.ssl_only
    use_plain = not args.ssl_only
    app_id = args.app_id or config.get('external_app_id')
    asp_id = args.asp_id or config.get('asp_id')
    domain_name_alias = args.domain_name_alias
    provisioning_session_id = await session.createNewDownlinkPullStream(args.ingesturl, app_id, args.entrypoints, name=name, ssl=use_ssl, insecure=use_plain, asp_id=asp_id, domain_name_alias=domain_name_alias)
    print(f'Hosting created as provisioning session {provisioning_session_id}')
    return 0

async def cmd_delete_stream(args: argparse.Namespace, config: Configuration) -> int:
    '''Perform ``delete-stream`` operation

    This will delete the provisioning session.

    This will remove the provisioning session and all its resources.
    '''
    session = await get_session(config)
    if args.provisioning_session is not None:
        ps_id = args.provisioning_session
    else:
        ps_id = await session.provisioningSessionIdByIngestUrl(args.ingesturl, args.entrypoint)
        if ps_id is None:
            print('No such hosting session found')
            return 1
    result = await session.provisioningSessionDestroy(ps_id)
    if result is None:
        print(f'Provisioning Session {ps_id} not found')
        return 1
    if not result:
        print(f'Failed to destroy Provisioning Session {ps_id}')
        return 1
    print(f'Provisioning Session {ps_id} and all its resources were destroyed')
    return 0

async def cmd_show_stream(args: argparse.Namespace, config: Configuration) -> int:
    session = await get_session(config)
    if args.provisioning_session is not None:
        ps_id = args.provisioning_session
    else:
        ps_id = await session.provisioningSessionIdByIngestUrl(args.ingesturl, args.entrypoint)
        if ps_id is None:
            print('No such hosting session found')
            return 1
    result = await session.contentHostingConfigurationGet(ps_id)
    if result is None:
        print(f'Provisioning Session {ps_id} does not have a ContentHostingConfiguration')
        return 1
    if args.raw:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f'ContentHostingConfiguration for provisioning session {ps_id}:')
        print('\n'.join(['  '+line for line in ContentHostingConfiguration.format(result).split('\n')]))
    return 0

async def cmd_protocols(args: argparse.Namespace, config: Configuration) -> int:
    '''Perform ``protocols`` operation

    This will list the download and upload protocols for the provisioning session.
    '''
    session = await get_session(config)
    result = await session.provisioningSessionProtocols(args.provisioning_session)
    if result is None:
        print(f'Failed to fetch the content protocols for provisioning session {args.provisioning_session}')
        return 1
    print(f'Protocols for {args.provisioning_session}:')
    if 'downlinkIngestProtocols' in result:
        print('  Downlink:')
        print('\n'.join([f'    {proto["termIdentifier"]}' for proto in result['downlinkIngestProtocols']]))
    else:
        print('  No downlink capability')
    if 'uplinkEgestProtocols' in result:
        print('  Uplink:')
        print('\n'.join([f'    {proto["termIdentifier"]}' for proto in result['uplinkEgestProtocols']]))
    else:
        print('  No uplink capability')
    if 'geoFencingLocatorTypes' in result:
        print('  Geo-fencing:')
        print('\n'.join([f'    {proto}' for proto in result['geoFencingLocatorTypes']]))
    else:
        print('  No geo-fencing capability')
    return 0

async def cmd_new_certificate(args: argparse.Namespace, config: Configuration) -> int:
    ''' Perform ``new-certificate`` operation

    This will create or reserve a new certificate in the provisioning session.
    '''
    session = await get_session(config)
    if args.csr:
        result = await session.certificateNewSigningRequest(args.provisioning_session, extra_domain_names=args.domain_name_alias)
        if result is None:
            print('Failed to reserve certificate')
            return 1
        cert_id, csr = result
        print(f'certificate_id={cert_id}')
        print(csr)
        return 0
    cert_id = await session.createNewCertificate(args.provisioning_session, extra_domain_names=args.domain_name_alias)
    if cert_id is None:
        print('Failed to create certificate')
        return 1
    print(f'certificate_id={cert_id}')
    return 0

async def cmd_show_certificate(args: argparse.Namespace, config: Configuration) -> int:
    ''' Perform ``show-certificate`` operation

    Display the certificate details for a given certificate.
    '''
    session = await get_session(config)
    result = await session.certificateGet(args.provisioning_session, args.certificate_id)
    if result is None:
        print(f'Unable to get certificate {args.certificate_id} for provisioning session {args.provisioning_session}')
        return 1
    if args.raw:
        print(result)
    else:
        print(f'Certificate details for {args.certificate_id}:')
        await __prettyPrintCertificate(result, indent=2)
    return 0

async def cmd_set_certificate(args: argparse.Namespace, config: Configuration) -> int:
    ''' Perform ``set-certificate`` operation

    Set the public certificate for a ``new-certificate`` generated with the ``--csr`` flag.
    '''
    session = await get_session(config)
    if args.certificate_pem_file is None:
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    else:
        reader = aiofiles.open(args.certificate_pem_file, 'r')
    cert_pem = await reader.read()
    await reader.close()
    result = await session.certificateSet(args.provisioning_session, args.certificate_id, cert_pem)
    if result is None:
        print('Failed to set certificate')
        return 1
    if not result:
        print('Certificate already set')
        return 1
    print('Certificate set')
    return 0

async def cmd_check_all_renewal(args: argparse.Namespace, config: Configuration) -> int:
    '''Perform ``check-all-renewal`` operation

    **TODO**
    '''
    session = await get_session(config)
    for ps_id in await session.provisioningSessionIds():
        chc = await session.getContentHostingConfiguration(ps_id)
        # extract current cert ids
        # get public cert for each cert id
        #   check for soon or past expiry
        #     request a new certificate
        #     change id in chc and remember old cert ids
        # if any cert ids changed in chc upload replacement chc
        # delete old certs
    sys.stderr.write('check-all-renewal not yet implemented\n')
    return 1

async def cmd_renew_certs(args: argparse.Namespace, config: Configuration) -> int:
    '''Perform ``renew-certs`` operation

    **TODO**
    '''
    session = await get_session(config)
    ps_id = args.provisioning_session
    chc = await session.getContentHostingConfiguration(ps_id)
    # get list of unique cert ids in chc
    # for each cert id in list
    #   request a new certificate
    #   change ids in chc for new cert id
    # upload replacement chc
    # delete old certs
    sys.stderr.write('renew-certs not yet implemented\n')
    return 1

async def cmd_set_consumption(args: argparse.Namespace, config: Configuration) -> int:
    '''Activate or set consumption reporting parameters on a provisioning session

    '''
    session = await get_session(config)
    ps_id = args.provisioning_session
    crc: ConsumptionReportingConfiguration = {}
    if args.interval is not None:
        crc['reportingInterval'] = args.interval
    if args.sample_percentage is not None:
        crc['samplePercentage'] = args.sample_percentage
    if args.location_reporting:
        crc['locationReporting'] = True
    if args.access_reporting:
        crc['accessReporting'] = True
    result: bool = await session.setOrUpdateConsumptionReporting(ps_id, crc)
    if result:
        print('Consumption reporting parameters set')
        return 0
    print('Failed to set consumption reporting parameters')
    return 1

async def cmd_show_consumption(args: argparse.Namespace, config: Configuration) -> int:
    '''Display current consumption reporting parameters for a provisioning session

    '''
    session = await get_session(config)
    ps_id = args.provisioning_session
    crc: Optional[ConsumptionReportingConfiguration] = await session.consumptionReportingConfigurationGet(ps_id)
    if crc is None:
        print('No consumption reporting configured')
    else:
        print('Consumption Reporting:')
        print(ConsumptionReportingConfiguration.format(crc, indent=2))
    return 0

async def cmd_del_consumption(args: argparse.Namespace, config: Configuration) -> int:
    '''Remove the consumption reporting parameters for a provisioning session

    '''
    session = await get_session(config)
    ps_id = args.provisioning_session
    result: bool = await session.consumptionReportingConfigurationDelete(ps_id)
    if result:
        print('Consumption reporting removed')
        return 0
    print('No consumption reporting to remove')
    return 1

async def _make_policy_template_from_args(args: argparse.Namespace, extra_flags: bool = False,
                                          base_policy: Optional[PolicyTemplate] = None) -> Optional[PolicyTemplate]:
    if base_policy is None:
        pt = dict()
    else:
        pt = copy.deepcopy(base_policy)
    if not extra_flags:
        if args.external_policy_id:
            pt['externalReference'] = args.external_policy_id
    else:
        for v,a in [('dnn', 'dnn'), ('qos_reference', 'qos-reference'), ('max_auth_up', 'max-auth-up'), ('max_auth_down', 'max-auth-down'), ('default_packet_loss_up', 'default-packet-loss-up'), ('default_packet_loss_down', 'default-packet-loss-down'), ('gpsi', 'gpsi')]:
            if getattr(args, 'no_'+v, False) and getattr(args, v, None) is not None:
                print(f'Cannot specify both --no-{a} and --{a} arguments')
                return None
        if getattr(args, 'chg_sponsor_none', False) and (getattr(args, 'chg_sponsor_status', None) is not None or getattr(args, 'chg_sponsor_id', None) is not None):
            print('Cannot specify both --chg-sponsor-none and other --chg-sponsor-... arguments')
            return None

    # [--s-nssai <SST[:SD]>]
    v = getattr(args, 's_nssai', None)
    if v is not None:
        (sst,sd) = (v.split(':') + [None])[:2]
        if 'applicationSessionContext' not in pt:
            pt['applicationSessionContext'] = {}
        pt['applicationSessionContext']['sliceInfo'] = {'sst': int(sst)}
        if sd is not None:
            pt['applicationSessionContext']['sliceInfo']['sd'] = sd

    # [--no-s-nssai]
    v = getattr(args, 'no_s_nssai', False)
    if v:
        if 'applicationSessionContext' in pt and 'sliceInfo' in pt['applicationSessionContext']:
            del pt['applicationSessionContext']['sliceInfo']
            if len(pt['applicationSessionContext'].keys()) == 0:
                del pt['applicationSessionContext']

    # [--dnn <DNN>]
    v = getattr(args, 'dnn', None)
    if v is not None:
        if 'applicationSessionContext' not in pt:
            pt['applicationSessionContext'] = {}
        pt['applicationSessionContext']['dnn'] = v

    # [--no-dnn]
    v = getattr(args, 'no_dnn', False)
    if v:
        if 'applicationSessionContext' in pt and 'dnn' in pt['applicationSessionContext']:
            del pt['applicationSessionContext']['dnn']
            if len(pt['applicationSessionContext'].keys()) == 0:
                del pt['applicationSessionContext']

    # [--qos-reference <qos-ref>]
    v = getattr(args, 'qos_reference', None)
    if v is not None:
        if 'qoSSpecification' not in pt:
            pt['qoSSpecification'] = {}
        pt['qoSSpecification']['qosReference'] = v

    # [--no-qos-reference]
    v = getattr(args, 'no_qos_reference', False)
    if v:
        if 'qoSSpecification' in pt and 'qosReference' in pt['qoSSpecification']:
            del pt['qoSSpecification']['qosReference']
            if len(pt['qoSSpecification'].keys()) == 0:
                del pt['qoSSpecification']

    # [--max-auth-up <bitrate>]
    v = getattr(args, 'max_auth_up', None)
    if v is not None:
        if 'qoSSpecification' not in pt:
            pt['qoSSpecification'] = {}
        pt['qoSSpecification']['maxAuthBtrUl'] = BitRate(v)

    # [--no-max-auth-up]
    v = getattr(args, 'no_max_auth_up', False)
    if v:
        if 'qoSSpecification' in pt and 'maxAuthBtrUl' in pt['qoSSpecification']:
            del pt['qoSSpecification']['maxAuthBtrUl']
            if len(pt['qoSSpecification'].keys()) == 0:
                del pt['qoSSpecification']

    # [--max-auth-down <bitrate>]
    v = getattr(args, 'max_auth_down', None)
    if v is not None:
        if 'qoSSpecification' not in pt:
            pt['qoSSpecification'] = {}
        pt['qoSSpecification']['maxAuthBtrDl'] = BitRate(v)

    # [--no-max-auth-down]
    v = getattr(args, 'no_max_auth_down', False)
    if v:
        if 'qoSSpecification' in pt and 'maxAuthBtrDl' in pt['qoSSpecification']:
            del pt['qoSSpecification']['maxAuthBtrDl']
            if len(pt['qoSSpecification'].keys()) == 0:
                del pt['qoSSpecification']

    # [--default-packet-loss-up <rate>]
    v = getattr(args, 'default_packet_loss_up', None)
    if v is not None:
        if 'qoSSpecification' not in pt:
            pt['qoSSpecification'] = {}
        pt['qoSSpecification']['defPacketLossRateUl'] = int(v)

    # [--no-default-packet-loss-up]
    v = getattr(args, 'no_default_packet_loss_up', False)
    if v:
        if 'qoSSpecification' in pt and 'defPacketLossRateUl' in pt['qoSSpecification']:
            del pt['qoSSpecification']['defPacketLossRateUl']
            if len(pt['qoSSpecification'].keys()) == 0:
                del pt['qoSSpecification']

    # [--default-packet-loss-down <rate>]
    v = getattr(args, 'default_packet_loss_down', None)
    if v is not None:
        if 'qoSSpecification' not in pt:
            pt['qoSSpecification'] = {}
        pt['qoSSpecification']['defPacketLossRateDl'] = int(v)

    # [--no-default-packet-loss-down]
    v = getattr(args, 'no_default_packet_loss_down', False)
    if v:
        if 'qoSSpecification' in pt and 'defPacketLossRateDl' in pt['qoSSpecification']:
            del pt['qoSSpecification']['defPacketLossRateDl']
            if len(pt['qoSSpecification'].keys()) == 0:
                del pt['qoSSpecification']

    # [--chg-sponsor-id <sponsor-id>]
    v = getattr(args, 'chg_sponsor_id', None)
    if v is not None:
        if 'chargingSpecification' not in pt:
            pt['chargingSpecification'] = {}
        pt['chargingSpecification']['sponId'] = v
        if 'sponStatus' not in pt['chargingSpecification']:
            pt['chargingSpecification']['sponStatus'] = SponsoringStatus.SPONSOR_DISABLED

    # [--chg-sponsor-enabled]
    # [--chg-sponsor-disabled]
    v = getattr(args, 'chg_sponsor_status', None)
    if v is not None:
        if 'chargingSpecification' not in pt:
            pt['chargingSpecification'] = {}
        if v:
            pt['chargingSpecification']['sponStatus'] = SponsoringStatus.SPONSOR_ENABLED
        else:
            pt['chargingSpecification']['sponStatus'] = SponsoringStatus.SPONSOR_DISABLED

    # [--chg-sponsor-none]
    v = getattr(args, 'chg_sponsor_none', False)
    if v:
        if 'chargingSpecification' in pt:
            if 'sponId' in pt['chargingSpecification']:
                del pt['chargingSpecification']['sponId']
            if 'sponStatus' in pt['chargingSpecification']:
                del pt['chargingSpecification']['sponStatus']
            if len(pt['chargingSpecification'].keys()) == 0:
                del pt['chargingSpecification']

    # [--gpsi <gpsi>...]
    v = getattr(args, 'gpsi', None)
    if v is not None:
        if not isinstance(v, list):
            v = [v]
        if 'chargingSpecification' not in pt:
            pt['chargingSpecification'] = {}
        pt['chargingSpecification']['gpsi'] = v

    # --no-gpsi
    v = getattr(args, 'no_gpsi', False)
    if v:
        if 'chargingSpecification' in pt and 'gpsi' in pt['chargingSpecification']:
            del pt['chargingSpecification']['gpsi']
            if len(pt['chargingSpecification'].keys()) == 0:
                del pt['chargingSpecification']

    return PolicyTemplate(pt)

async def cmd_new_policy_template(args: argparse.Namespace, config: Configuration) -> int:
    session = await get_session(config)
    ps_id = args.provisioning_session
    pol = await _make_policy_template_from_args(args, extra_flags=False)
    result: Optional[ResourceId] = await session.policyTemplateCreate(ps_id, pol)
    if result is not None:
        print(f'Added PolicyTemplate {result} to provisioning session')
        return 0
    print(f'Addition of PolicyTemplate to provisioning session failed!')
    return 1

async def cmd_update_policy_template(args: argparse.Namespace, config: Configuration) -> int:
    session = await get_session(config)
    ps_id = args.provisioning_session
    pol_id = args.policy_template_id
    pol: Optional[PolicyTemplate] = await session.policyTemplateGet(ps_id, pol_id)
    if pol is None:
        print('Attempt to update a PolicyTemplate that does not exist')
        return 1
    pol = await _make_policy_template_from_args(args, extra_flags=True, base_policy=pol)
    result: Optional[PolicyTemplate] = await session.policyTemplateUpdate(ps_id, pol_id, pol)
    if result is not None:
        print(f'Updated PolicyTemplate for the provisioning session')
        return 0
    print(f'Update of PolicyTemplate {pol_id} for the provisioning session {ps_id} failed!')
    return 1

async def cmd_del_policy_template(args: argparse.Namespace, config: Configuration) -> int:
    session = await get_session(config)
    ps_id = args.provisioning_session
    pol_id = args.policy_template_id
    result: bool = await session.policyTemplateDelete(ps_id, pol_id)
    if result:
        print(f'Policy template {pol_id} removed from provisioning session {ps_id}')
        return 0
    print(f'Failed to delete policy template {pol_id} removed from provisioning session {ps_id}')
    return 1

async def cmd_show_policy_template(args: argparse.Namespace, config: Configuration) -> int:
    session = await get_session(config)
    ps_id = args.provisioning_session
    pol_id = args.policy_template_id
    result: Optional[PolicyTemplate] = await session.policyTemplateGet(ps_id, pol_id)
    if result is not None:
        print(PolicyTemplate.format(result, indent=0))
        return 0
    print(f'Failed to find policy template {pol_id} for provisioning session {ps_id}')
    return 1

async def parse_args() -> Tuple[argparse.Namespace,Configuration]:
    '''Parse command line options and load app configuration

    :return: Tuple containing the command line arguments after validation and the app configuration
    :rtype: Tuple[argparse.Namespace,Configuration]
    '''
    cfg = Configuration()

    parser = argparse.ArgumentParser(prog='m1-session', description='M1 Session Tool')
    parser.add_argument('-D', '--debug', action='store_true', help='Enable debugging mode')
    subparsers = parser.add_subparsers(required=True)

    # m1-session-cli configure <cmd> ...
    parser_configure = subparsers.add_parser('configure', help='Local configuration')
    configure_subparsers = parser_configure.add_subparsers(required=True)
    # m1-session-cli configure show
    parser_configure_show = configure_subparsers.add_parser('show', help='Show local configuration')
    parser_configure_show.set_defaults(command=cmd_configure_show)
    # m1-session-cli configure get <KEY>
    parser_configure_get = configure_subparsers.add_parser('get', help='Get local configuration value')
    parser_configure_get.set_defaults(command=cmd_configure_get)
    parser_configure_get.add_argument('key', metavar='KEY', type=cfg.isKey)
    # m1-session-cli configure set <KEY> <VALUE>
    parser_configure_set = configure_subparsers.add_parser('set', help='Set local configuration value')
    parser_configure_set.set_defaults(command=cmd_configure_set)
    parser_configure_set.add_argument('key', metavar='KEY', type=cfg.isKey)
    parser_configure_set.add_argument('value', metavar='VALUE')
    # m1-session-cli configure reset <KEY>
    parser_configure_reset = configure_subparsers.add_parser('reset', help='Reset configuration value to its default')
    parser_configure_reset.set_defaults(command=cmd_configure_reset)
    parser_configure_reset.add_argument('key', metavar='KEY', type=cfg.isKey)

    # m1-session-cli list [-v]
    parser_list = subparsers.add_parser('list', help='List provisioning sessions')
    parser_list.set_defaults(command=cmd_list)
    parser_list.add_argument('-v', '--verbose', required=False, action='store_true')

    # m1-session-cli new-stream [-e <APPLICATION-ID>] [-a <PROVIDER-ID>] [-n <NAME>] [--with-ssl|--ssl-only] [-d <FQDN>] \
    #                           <ingest-URL> [<entry-point-path[:profile...]>...]
    parser_newstream = subparsers.add_parser('new-stream', help='Create a new ingest stream')
    parser_newstream.set_defaults(command=cmd_new_stream)
    parser_newstream.add_argument('-n', '--name', metavar='NAME', help='The name of the new stream', required=False)
    parser_newstream.add_argument('-e', '--external-app-id', dest='app_id', metavar="APPLICATION-ID", help='The external application id to register the stream to', required=False)
    parser_newstream.add_argument('-a','--asp-id', metavar="PROVIDER-ID", help="The Application Service Provider Id to use", required=False)
    parser_newstream_ssl_options = parser_newstream.add_mutually_exclusive_group(required=False)
    parser_newstream_ssl_options.add_argument('--with-ssl', action='store_true')
    parser_newstream_ssl_options.add_argument('--ssl-only', action='store_true')
    parser_newstream.add_argument('-d', '--domain-name-alias', dest='domain_name_alias', metavar='FQDN', help='Optional domain name alias for the distribution', required=False)
    parser_newstream.add_argument('ingesturl', metavar='ingest-URL', help='The ingest URL prefix to use')
    parser_newstream.add_argument('entrypoints', metavar='entry-point-path', nargs='*',
                                  help='The media player entry point paths.')

    # m1-session-cli del-stream -p <provisioning-session-id>
    # m1-session-cli del-stream <ingest-URL> [<entry-point-path>]
    parser_delstream = subparsers.add_parser('del-stream', help='Delete an ingest stream')
    parser_delstream.set_defaults(command=cmd_delete_stream)
    parser_delstream_filter = parser_delstream.add_mutually_exclusive_group(required=True)
    parser_delstream_filter.add_argument('-p', '--provisioning-session', help='Delete by provisioning session id')
    parser_delstream_filter.add_argument('ingesturl', metavar='ingest-URL', nargs='?', help='The ingest URL prefix to identify the provisioning session.')
    # The entry-point-path should go with ingest-URL, but argparser lacks the ability to do subgroups
    parser_delstream.add_argument('entrypoint', metavar='entry-point-path', nargs='?', help='The media player entry point suffix to identify the provisioning session.')

    # m1-session-cli set-stream -p <provisioning-session-id> <CHC-JSON-FILE>
    parser_set_stream = subparsers.add_parser('set-stream', help='Set the hosting for a provisioning session from a JSON file')
    parser_set_stream.set_defaults(command=cmd_set_stream)
    parser_set_stream.add_argument('-p', '--provisioning-session', help='The provisioning session id to set the hosting for',
                                   required=True)
    parser_set_stream.add_argument('file', metavar='CHC-JSON-FILE', help='A filepath to a JSON encoded ContentHostingConfiguration')

    # m1-session-cli show-stream (-p <provisioning-session-id>|<ingest-URL> [<entry-point-path>]) [-r]
    parser_show_stream = subparsers.add_parser('show-stream',
                                               help='Display the ContentHostingConfiguration for a provisioning session')
    parser_show_stream.set_defaults(command=cmd_show_stream)
    parser_show_stream_filter = parser_show_stream.add_mutually_exclusive_group(required=True)
    parser_show_stream_filter.add_argument('-p', '--provisioning-session', help='The provisioning session id to show',
                                           required=False)
    parser_show_stream_filter.add_argument('ingesturl', metavar='ingest-URL', nargs='?',
                                           help='The ingest URL prefix used to identify the provisioing session')
    parser_show_stream.add_argument('entrypoint', metavar='entry-point-path', nargs='?',
                                    help='A media player entry point suffix to identify the provisioning session.')
    parser_show_stream.add_argument('-r', '--raw', required=False, action="store_true",
                                    help='Use "raw" output mode to present the ContentHostingConfiguration JSON')

    # m1-session-cli new-provisioning-session [-e <APPLICATION-ID>] [-a <PROVIDER-ID>]
    parser_new_provisioning_session = subparsers.add_parser('new-provisioning-session', help='Create a new provisioning session')
    parser_new_provisioning_session.set_defaults(command=cmd_new_provisioning_session)
    parser_new_provisioning_session.add_argument('-e', '--external-app-id', dest='app_id', metavar="APPLICATION-ID",
                                                 help='The external application id to register the stream to', required=False)
    parser_new_provisioning_session.add_argument('-a','--asp-id', metavar="PROVIDER-ID",
                                                 help="The Application Service Provider Id to use", required=False)

    # m1-session-cli protocols -p <provisioning-session-id>
    parser_protocols = subparsers.add_parser('protocols',
                                             help='Get the available upload/download protocols for a provisioning session')
    parser_protocols.set_defaults(command=cmd_protocols)
    parser_protocols.add_argument('-p', '--provisioning-session',
                                  help='Provisioning session id to list the upload and download protocols for')

    # m1-session-cli new-certificate -p <provisioning-session-id> [-d <domain-name>...] [--csr]
    parser_new_certificate = subparsers.add_parser('new-certificate', help='Create a new certificate')
    parser_new_certificate.set_defaults(command=cmd_new_certificate)
    parser_new_certificate.add_argument('-p', '--provisioning-session',
                                        help='Provisioning session id to create the new certificate for')
    parser_new_certificate.add_argument('-d', '--domain-name-alias', dest='domain_name_alias', nargs='*', metavar='FQDN',
                                               help='FQDN to add as an extra domain name to the certificate')
    parser_new_certificate.add_argument('--csr', action='store_true',
                                               help='Return a CSR to be signed externally and published using set-certificate')

    # m1-session-cli show-certificate -p <provisioning-session-id> -c <certificate-id>
    parser_show_certificate = subparsers.add_parser('show-certificate', help='Retrieve a public certificate')
    parser_show_certificate.set_defaults(command=cmd_show_certificate)
    parser_show_certificate.add_argument('-p', '--provisioning-session', required=True,
                                         help='Provisioning session id to show the certificate for')
    parser_show_certificate.add_argument('-c', '--certificate-id', required=True,
                                         help='The certificate id of the certificate to show')
    parser_show_certificate.add_argument('-r', '--raw', required=False, action="store_true",
                                         help='Use "raw" output mode to present the public certificate PEM data')

    # m1-session-cli set-certificate -p <provisioning-session-id> -c <certificate-id> [<certificate-PEM-file>]
    parser_set_certificate = subparsers.add_parser('set-certificate',
                                                   help='Set the public certificate for a certificate created using --csr')
    parser_set_certificate.set_defaults(command=cmd_set_certificate)
    parser_set_certificate.add_argument('-p', '--provisioning-session', required=True,
                                         help='Provisioning session id to set the certificate for')
    parser_set_certificate.add_argument('-c', '--certificate-id', required=True,
                                         help='The certificate id of the certificate to set')
    parser_set_certificate.add_argument('certificate-PEM-file', nargs='?',
                                        help='PEM file to load the public certificate from, if omitted will use stdin instead')

    # m1-session-cli check-certificate-renewal
    #parser_checkrenewal = subparsers.add_parser('check-certificate-renewal', help='Renew all certificates if close to expiry')
    #parser_checkrenewal.set_defaults(command=cmd_check_all_renewal)

    # m1-session-cli renew-certificate -p <provisioning-session-id>
    # m1-session-cli renew-certificate <ingest-URL> [<entry-point-path>]
    #parser_renewcert = subparsers.add_parser('renew-certificate', help='Force renewal of a specific certificate')
    #parser_renewcert.set_defaults(command=cmd_renew_certs)
    #parser_renewcert_filter = parser_renewcert.add_mutually_exclusive_group(required=True)
    #parser_renewcert_filter.add_argument('-p', '--provisioning-session', help='Renew by provisioning session id')
    #parser_renewcert_filter.add_argument('ingesturl', metavar='ingest-URL', nargs='?', help='The ingest URL prefix to use')
    # The entry-point-path should go with ingest-URL, but argparser lacks the ability to do subgroups
    #parser_renewcert.add_argument('entrypoint', metavar='entry-point-path', nargs='?', help='The media player entry point suffix.')

    # m1-session-cli set-consumption-reporting -p <provisioning-session-id> [-i <interval>] [-s <sample-percent>] [-l] [-A]
    parser_set_consumption = subparsers.add_parser('set-consumption-reporting', help='Activate/set consumption reporting')
    parser_set_consumption.set_defaults(command=cmd_set_consumption)
    parser_set_consumption.add_argument('-p', '--provisioning-session', required=True,
                                        help='Provisioning session id to set the consumption reporting for')
    parser_set_consumption.add_argument('-i', '--interval', type=int, help='The reporting interval to request in seconds')
    parser_set_consumption.add_argument('-s', '--sample-percentage', dest='sample_percentage', type=float,
                                        help='The sampling percentage to request')
    parser_set_consumption.add_argument('-l', '--location-reporting', dest='location_reporting', action='store_true',
                                        help='Include location reporting')
    parser_set_consumption.add_argument('-A', '--access-reporting', dest='access_reporting', action='store_true',
                                        help='Include access reporting')

    # m1-session-cli show-consumption-reporting -p <provisioning-session-id>
    parser_show_consumption = subparsers.add_parser('show-consumption-reporting', help='Display the consumption reporting parameters')
    parser_show_consumption.set_defaults(command=cmd_show_consumption)
    parser_show_consumption.add_argument('-p', '--provisioning-session', required=True,
                                         help='Provisioning session id to get the consumption reporting for')

    # m1-session-cli del-consumption-reporting -p <provisioning-session-id>
    parser_del_consumption = subparsers.add_parser('del-consumption-reporting', help='Deactivate consumption reporting')
    parser_del_consumption.set_defaults(command=cmd_del_consumption)
    parser_del_consumption.add_argument('-p', '--provisioning-session', required=True,
                                        help='Provisioning session id to remove the consumption reporting for')

    # m1-session-cli new-policy-template -p <provisioning-session-id> -e <external-policy-id> [-D <dnn>] [-S <s-nssai>]
    #                                    [--qos-reference <qos-ref>] [--max-auth-up <bitrate>] [--max-auth-down <bitrate>]
    #                                    [--default-packet-loss-up <rate>] [--default-packet-loss-down <rate>]
    #                                    [--chg-sponsor-id <sponsor-id>] [--chg-sponsor-enabled|--chg-sponsor-disabled]
    #                                    [--gpsi <gpsi>]...
    parser_new_policy_template = subparsers.add_parser('new-policy-template', help='Add a new policy template')
    parser_new_policy_template.set_defaults(command=cmd_new_policy_template)
    parser_new_policy_template.add_argument('-p', '--provisioning-session', required=True,
                                        help='Provisioning session id to create the policy template for')
    parser_new_policy_template.add_argument('-e', '--external-policy-id', required=True,
                                        help='The external identifier for this policy template')
    parser_new_policy_template.add_argument('-D', '--dnn', help='The designated network name for the app session context')
    parser_new_policy_template.add_argument('-S', '--s-nssai', metavar='SST[:SD]',
                                        help='The Single NSSAI which will be used in the app session context')
    parser_new_policy_template.add_argument('--qos-reference', help='The QoS reference for the QoS Specification')
    parser_new_policy_template.add_argument('--max-auth-up', type=BitRate,
                                        help='The maximum authorised uplink bitrate for the QoS Specification')
    parser_new_policy_template.add_argument('--max-auth-down', type=BitRate,
                                        help='The maximum authorised downlink bitrate for the QoS Specification')
    parser_new_policy_template.add_argument('--default-packet-loss-up', type=int,
                                        help='The number of packets that can be lost for an uplink in the QoS Specification')
    parser_new_policy_template.add_argument('--default-packet-loss-down', type=int,
                                        help='The number of packets that can be lost for an downlink in the QoS Specification')
    parser_new_policy_template.add_argument('--chg-sponsor-id', metavar='sponsor-id',
                                        help='The Sponsor id for the charging specification')
    parser_new_policy_template.add_argument('--chg-sponsor-enabled', action='store_true', dest='chg_sponsor_status', default=None,
                                        help='The Sponsor is enabled for charging')
    parser_new_policy_template.add_argument('--chg-sponsor-disabled', action='store_false', dest='chg_sponsor_status', default=None,
                                        help='The Sponsor is disabled for charging')
    parser_new_policy_template.add_argument('--gpsi', action='append', help='The GPSI(s) to use for charging')

    # m1-session-cli update-policy-template -p <provisioning-session-id> -t <policy-template-id> [-D <dnn>] [-S <s-nssai>]
    #                                    [--qos-reference <qos-ref>] [--max-auth-up <bitrate>|--no-max-auth-up]
    #                                    [--max-auth-down <bitrate>|--no-max-auth-down]
    #                                    [--default-packet-loss-up <rate>|--no-default-packet-loss-up]
    #                                    [--default-packet-loss-down <rate>|--no-default-packet-loss-down]
    #                                    [--chg-sponsor-id <sponsor-id> [--chg-sponsor-enabled|--chg-sponsor-disabled]
    #                                     |--chg-sponsor-none]
    #                                    [--gpsi <gpsi> [--gpsi <gpsi>]...|--no-gpsi]
    parser_update_policy_template = subparsers.add_parser('update-policy-template', help='Modify a policy template')
    parser_update_policy_template.set_defaults(command=cmd_update_policy_template)
    parser_update_policy_template.add_argument('-p', '--provisioning-session', required=True,
                                        help='Provisioning session id to update the policy template for')
    parser_update_policy_template.add_argument('-t', '--policy-template-id', required=True,
                                        help='The policy template id of the policy template to update')
    parser_update_policy_template.add_argument('-D', '--dnn', help='The designated network name for the app session context')
    parser_update_policy_template.add_argument('--no-dnn', action='store_true',
                                        help='Remove the designated network name for the app session context')
    parser_update_policy_template.add_argument('-S', '--s-nssai', metavar='SST[:SD]',
                                        help='The Single NSSAI which will be used in the app session context')
    parser_update_policy_template.add_argument('--no-s-nssai', action='store_true',
                                        help='Remove the Single NSSAI used in the app session context')
    parser_update_policy_template.add_argument('--qos-reference', help='The QoS reference for the QoS Specification')
    parser_update_policy_template.add_argument('--no-qos-reference', action='store_true',
                                        help='Remove the QoS reference from the QoS Specification')
    parser_update_policy_template.add_argument('--max-auth-up', type=BitRate,
                                        help='The maximum authorised uplink bitrate for the QoS Specification')
    parser_update_policy_template.add_argument('--no-max-auth-up', action='store_true',
                                        help='Remove maximum authorised uplink bitrate for the QoS Specification')
    parser_update_policy_template.add_argument('--max-auth-down', type=BitRate,
                                        help='The maximum authorised downlink bitrate for the QoS Specification')
    parser_update_policy_template.add_argument('--no-max-auth-down', action='store_true',
                                        help='Remove maximum authorised downlink bitrate for the QoS Specification')
    parser_update_policy_template.add_argument('--default-packet-loss-up', type=int,
                                        help='The number of packets that can be lost for an uplink in the QoS Specification')
    parser_update_policy_template.add_argument('--no-default-packet-loss-up', action='store_true',
                                        help='Remove number of packets that can be lost for an uplink in the QoS Specification')
    parser_update_policy_template.add_argument('--default-packet-loss-down', type=int,
                                        help='The number of packets that can be lost for an downlink in the QoS Specification')
    parser_update_policy_template.add_argument('--no-default-packet-loss-down', action='store_true',
                                        help='Remove number of packets that can be lost for an downlink in the QoS Specification')
    parser_update_policy_template.add_argument('--chg-sponsor-id', metavar='sponsor-id',
                                        help='The Sponsor id for the charging specification')
    parser_update_policy_template.add_argument('--chg-sponsor-enabled', action='store_true', dest='chg_sponsor_status', default=None,
                                        help='The Sponsor is enabled for charging')
    parser_update_policy_template.add_argument('--chg-sponsor-disabled', action='store_false', dest='chg_sponsor_status', default=None,
                                        help='The Sponsor is disabled for charging')
    parser_update_policy_template.add_argument('--chg-sponsor-none', action='store_true', dest='chg_sponsor_none',
                                        help='The Sponsor status and id should be removed for charging')
    parser_update_policy_template.add_argument('--gpsi', action='append',
                                        help='The set the GPSI(s) to use for charging (use --no-gpsi to remove gpsis)')
    parser_update_policy_template.add_argument('--no-gpsi', action='store_true', help='Remove all GPSI values for charging')

    # m1-session-cli del-policy-template -p <provisioning-session-id> -t <policy-template-id>
    parser_del_policy_template = subparsers.add_parser('del-policy-template', help='Delete a policy template')
    parser_del_policy_template.set_defaults(command=cmd_del_policy_template)
    parser_del_policy_template.add_argument('-p', '--provisioning-session', required=True,
                                        help='Provisioning session id to remove the policy template for')
    parser_del_policy_template.add_argument('-t', '--policy-template-id', required=True,
                                        help='The policy template id of the policy template to delete')

    # m1-session-cli show-policy-template -p <provisioning-session-id> -t <policy-template-id>
    parser_show_policy_template = subparsers.add_parser('show-policy-template', help='Display a policy template')
    parser_show_policy_template.set_defaults(command=cmd_show_policy_template)
    parser_show_policy_template.add_argument('-p', '--provisioning-session', required=True,
                                        help='Provisioning session id to display the policy template for')
    parser_show_policy_template.add_argument('-t', '--policy-template-id', required=True,
                                        help='The policy template id of the policy template to display')

    args = parser.parse_args()

    return (args,cfg)

_m1_session = None #: singleton variable for the M1Session object

async def get_session(config: Configuration) -> M1Session:
    '''Get the current M1Session object

    If the M1Session object does not exist, create it.

    :param Configuration config: The application configuration to use for connection information.
    :return: the M1Session instance.
    :rtype: M1Session
    '''
    global _m1_session
    if _m1_session is None:
        data_store_dir = config.get('data_store')
        if data_store_dir is not None:
            data_store = await JSONFileDataStore(config.get('data_store'))
        else:
            data_store = None
        _m1_session = await M1Session((config.get('m1_address', 'localhost'), config.get('m1_port',7777)), data_store, config.get('certificate_signing_class'))
    return _m1_session

async def main():
    '''
    Async application entry point
    '''
    log_levels = {
            'debug': logging.DEBUG,
            'info': logging.INFO,
            'warn': logging.WARN,
            'error': logging.ERROR,
            'crit': logging.CRITICAL,
            }
    try:
        (args, config) = await parse_args()
        if args.debug:
            log_lvl = logging.DEBUG
        elif config.get('log_level') in log_levels:
            log_lvl = log_levels[config.get('log_level')]
        else:
            print(f'Warning: Bad logging level "{config.get("log_level")}" in configuration.')
            log_lvl = logging.INFO
        logging.basicConfig(level=log_lvl)
        log = logging.getLogger()
        for lgr in log.manager.loggerDict.values():
            if isinstance(lgr, logging.Logger):
                if not args.debug and lgr.name == 'httpx':
                    lgr.setLevel(logging.WARN)
                else:
                    lgr.setLevel(log_lvl)
        if hasattr(args, 'command'):
            return await args.command(args, config)
        else:
            print(repr(parse_args()))
    except M1Error as err:
        print(f'Communication error: {err}')
        return 2
    except Exception as err:
        print(f'General failure: {err}')
        if args.debug:
            traceback.print_exc()
        return 2
    return 0

def app():
    '''
    Sync application entry point
    '''
    logging.basicConfig(level=logging.INFO)
    return asyncio.run(main())

if __name__ == '__main__':
    sys.exit(app())
