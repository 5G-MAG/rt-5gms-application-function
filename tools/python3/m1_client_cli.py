#!/usr/bin/python3
#==============================================================================
# 5G-MAG Reference Tools: M1 Client CLI
#==============================================================================
#
# File: m1_client_cli.py
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
# M1 Client CLI
# ===============
#
# This is a simple command line tool which will communicate with a 5GMS
# Application Function via the M1 interface.
#
'''5G-MAG Reference Tools: M1 Client CLI

This provides a simple command line interface which can be used to manipulate
the configuration of a 5GMS Application Function via the M1 interface.

Syntax:
    m1-client -h
    m1-client provisioning create [-h] <address:port> (-d|-u) <external-app-id> [<asp-id>]
    m1-client provisioning show [-h] <address:port> <provisioning-session-id>
    m1-client provisioning delete [-h] <address:port> <provisioning-session-id>
    m1-client protocols [-h] <address:port> <provisioning-session-id>
    m1-client certificates create [-h] <address:port> <provisioning-session-id> [--csr [<fqdn>...]]
    m1-client certificates upload [-h] <address:port> <provisioning-session-id> <certificate-id> <PEM-file>
    m1-client certificates show [-h] <address:port> <provisioning-session-id> <certificate-id> [--info]
    m1-client certificates delete [-h] <address:port> <provisioning-session-id> <certificate-id>
    m1-client hosting create [-h] <address:port> <provisioning-session-id> <CHC-JSON-file>
    m1-client hosting show [-h] <address:port> <provisioning-session-id>
    m1-client hosting update [-h] <address:port> <provisioning-session-id> <CHC-JSON-file>
    m1-client hosting delete [-h] <address:port> <provisioning-session-id>
    m1-client hosting purge [-h] <address:port> <provisioning-session-id> [<path-regex>]
    m1-client consumption create [-h] <address:port> <provisioning-session-id> [-i <interval>] [-p <percentage>] [-l] [-a]
    m1-client consumption show [-h] <address:port> <provisioning-session-id>
    m1-client consumption update [-h] <address:port> <provisioning-session-id> [-i <interval>] [-p <percentage>] [-l] [-a]
    m1-client consumption delete [-h] <address:port> <provisioning-session-id>
    m1-client policy create [-h] <address:port> <provisioning-session-id> <PolicyTemplate-JSON-file>
    m1-client policy show [-h] <address:port> <provisioning-session-id> <policy-template-id>
    m1-client policy update [-h] <address:port> <provisioning-session-id> <policy-template-id> <PolicyTemplate-JSON-file>
    m1-client policy delete [-h] <address:port> <provisioning-session-id> <policy-template-id>
'''

import aiofiles
import argparse
import asyncio
import datetime
import os.path
import sys
from typing import Optional, Union

import cryptography
import OpenSSL

installed_packages_dir = '@python_packages_dir@'
if os.path.isdir(installed_packages_dir) and installed_packages_dir not in sys.path:
    sys.path.append(installed_packages_dir)

from rt_m1_client.client import M1Client, ProvisioningSessionResponse, ContentProtocolsResponse, ServerCertificateSigningRequestResponse, ServerCertificateResponse, ContentHostingConfigurationResponse, ConsumptionReportingConfigurationResponse, PolicyTemplateResponse
from rt_m1_client.types import PROVISIONING_SESSION_TYPE_DOWNLINK, PROVISIONING_SESSION_TYPE_UPLINK, ContentHostingConfiguration, ConsumptionReportingConfiguration, PolicyTemplate
from rt_m1_client.exceptions import M1Error

async def cmd_provisioning_create(args: argparse.Namespace) -> int:
    client = await getClient(args)
    asp_id = args.asp_id
    app_id = args.external_app_id
    if args.downlink:
        prov_type = PROVISIONING_SESSION_TYPE_DOWNLINK
    else:
        prov_type = PROVISIONING_SESSION_TYPE_UPLINK
    prov_sess_resp: Optional[ProvisioningSessionResponse] = await client.createProvisioningSession(prov_type, app_id, asp_id)
    if prov_sess_resp is None:
        print('Failed to create provisioning session')
        return 1
    print(f"provisioning_session_id={prov_sess_resp['ProvisioningSessionId']}")
    return 0

async def cmd_provisioning_show(args: argparse.Namespace) -> int:
    client = await getClient(args)
    provisioning_session_id = args.provisioning_session_id
    prov_sess_resp: Optional[ProvisioningSessionResponse] = await client.getProvisioningSessionById(provisioning_session_id)
    if prov_sess_resp is None:
        print('Failed to fetch provisioning session')
        return 1
    print(f"{prov_sess_resp['ProvisioningSession']!r}")
    return 0

async def cmd_provisioning_delete(args: argparse.Namespace) -> int:
    client = await getClient(args)
    provisioning_session_id = args.provisioning_session_id
    prov_sess_resp: bool = await client.destroyProvisioningSession(provisioning_session_id)
    if not prov_sess_resp:
        print('Failed to delete provisioning session')
        return 1
    print('Provisioning session deleted')
    return 0

async def cmd_protocols(args: argparse.Namespace) -> int:
    client = await getClient(args)
    provisioning_session_id = args.provisioning_session_id
    resp: Optional[ContentProtocolsResponse] = await client.retrieveContentProtocols(provisioning_session_id)
    if resp is None:
        print('Failed to get ContentProtocols for provisioning session')
        return 1
    print(f"{resp['ContentProtocols']!r}")
    return 0

async def cmd_certificates_create(args: argparse.Namespace) -> int:
    client = await getClient(args)
    provisioning_session_id = args.provisioning_session_id
    csr = args.csr is not None
    fqdns = args.csr
    resp: Optional[ServerCertificateSigningRequestResponse] = await client.createOrReserveServerCertificate(provisioning_session_id, extra_domain_names=fqdns, csr=csr)
    if resp is None:
        print('Failed to create a server certificate in the provisioning session')
        return 1
    print(f"certificate_id={resp['ServerCertificateId']}")
    if csr:
        print(resp['CertificateSigningRequestPEM'])
    return 0


async def cmd_certificates_upload(args: argparse.Namespace) -> int:
    client = await getClient(args)
    provisioning_session_id = args.provisioning_session_id
    certificate_id = args.certificate_id
    pem_file = args.PEM_file
    async with aiofiles.open(pem_file, mode='r') as in_file:
        pem = await in_file.read()
    resp: bool = await client.uploadServerCertificate(provisioning_session_id, certificate_id, pem)
    if not resp:
        print('Failed to upload public certificate')
        return 1
    print('Public certificate uploaded')
    return 0

def format_int_hex_block(v: int, bits: int, bytes_per_line: int, indent: int = 0) -> str:
    digits = int(bits/4)
    h = hex(v)[2:]
    if len(h) < digits:
        zeros = digits - len(h)
        h = '0' * zeros + h
    out_prefix = ' ' * indent
    line_sep = f'\n{out_prefix}'
    line_digits = bytes_per_line*2
    return (out_prefix + line_sep.join([''.join([s[i:i+2]+':' for i in range(0,len(s),2)]) for s in [h[i:i+line_digits] for i in range(0,len(h),line_digits)]]))[:-1]

def format_x509_name(name: OpenSSL.crypto.X509Name, indent: int = 0) -> str:
    '''Return a human readable `str` representing the X509Name

    :param pkey: The X509Name for format as a `str`.
    :param indent: The number of space characters to preceed every output line with.

    :return: a human readable version of *name*.
    '''
    out_prefix = ' ' * indent
    return out_prefix + ', '.join([k.decode('utf-8')+'='+v.decode('utf-8') for k,v in name.get_components()])

def format_x509_extension(ext: OpenSSL.crypto.X509Extension, indent: int = 0) -> str:
    '''Return a human readable `str` representing the X509Extension

    :param pkey: The X509Extension for format as a `str`.
    :param indent: The number of space characters to preceed every output line with.

    :return: a human readable version of *ext*.
    '''
    out_prefix = ' ' * indent
    ret = ''
    critical: bool = ext.get_critical()
    value: str = str(ext)
    short_name: str = ext.get_short_name().decode('utf-8')
    name: str = short_name
    long_names = {
            'subjectAltName': 'X509v3 Subject Alternative Names',
            'basicConstraints': 'X509v3 Basic Constraints',
            'authorityKeyIdentifier': 'X509v3 Authority Key Identifier',
            'subjectKeyIdentifier': 'X509v3 Subject Key Identifier',
            'authorityInformationAccess': 'Authority Information Access',
            'extendedKeyUsage': 'X509v3 Extended Key Usage',
            'crlDistributionPoints': 'X509v3 CRL Distribution Points',
            'keyUsage': 'X509v3 Key Usage',
            }
    if short_name in long_names:
        name = long_names[short_name]
    ret += out_prefix+name+':'
    if critical:
        ret += ' critical'
    ret += '\n'
    ret += '\n'.join([out_prefix+'    '+s for s in value.split('\n')])+'\n'
    return ret

def format_rsa_public_key(key: cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey, indent: int = 0) -> str:
    out_prefix = ' ' * indent
    numbers = key.public_numbers()
    ret = f'''{out_prefix}RSA Public Key: ({key.key_size} bits)
{out_prefix}    Exponent: {numbers.e} ({hex(numbers.e)})
{out_prefix}    Modulus:
{format_int_hex_block(numbers.n, key.key_size, 15, indent+8)}'''
    return ret

def format_dsa_public_key(key: cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey, indent: int = 0) -> str:
    out_prefix = ' ' * indent
    numbers = key.public_numbers()
    ret = f'''{out_prefix}DSA Public Key: ({key.key_size} bits)
{out_prefix}    Parameters:
{out_prefix}        p: {numbers.parameter_numbers.p}
{out_prefix}        q: {numbers.parameter_numbers.q}
{out_prefix}        g: {numbers.parameter_numbers.g}
{out_prefix}    y:
{format_int_hex_block(numbers.y, key.key_size, 15, indent=indent+8)}'''
    return ret

def format_dh_public_key(key: cryptography.hazmat.primitives.asymmetric.dh.DHPublicKey, indent: int = 0) -> str:
    out_prefix = ' ' * indent
    numbers = key.public_numbers()
    ret = f'''{out_prefix}Diffie-Hellman Public Key: ({key.key_size} bits)
{out_prefix}    Parameters:
{out_prefix}        p: {numbers.parameter_numbers.p}
{out_prefix}        g: {numbers.parameter_numbers.g}
{out_prefix}        q: {numbers.parameter_numbers.q}
{out_prefix}    y:
{format_int_hex_block(numbers.y, key.key_size, 15, indent=indent+8)}'''
    return ret

def format_ec_public_key(key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey, indent: int = 0) -> str:
    out_prefix = ' ' * indent
    numbers = key.public_numbers()
    ret = f'''{out_prefix}Elliptic-Curve Public Key: ({key.key_size} bits)
{out_prefix}    Curve: {numbers.curve.name}
{out_prefix}    x:
{format_int_hex_block(numbers.x, key.key_size, 15, indent=indent+8)}
{out_prefix}    y:
{format_int_hex_block(numbers.y, key.key_size, 15, indent=indent+8)}'''
    return ret

def format_pkey(pkey: OpenSSL.crypto.PKey, indent: int = 0) -> str:
    '''Return a human readable `str` representing the PKey

    :param pkey: The PKey for format as a `str`.
    :param indent: The number of space characters to preceed every output line with.

    :return: a human readable version of *pkey*.
    '''
    cryptokey = pkey.to_cryptography_key()
    if isinstance(cryptokey, cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey):
        return format_rsa_public_key(cryptokey, indent)
    if isinstance(cryptokey, cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey):
        return format_dsa_public_key(cryptokey, indent)
    if isinstance(cryptokey, cryptography.hazmat.primitives.asymmetric.dh.DHPublicKey):
        return format_dh_public_key(cryptokey, indent)
    if isinstance(cryptokey, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey):
        return format_ec_public_key(cryptokey, indent)
    out_prefix = ' ' * indent
    ret = f'{out_prefix}{cryptokey.__class__.__name__} type public key, unable to format'
    return ret

def format_x509_pem(pem: str, indent: int = 0) -> str:
    '''Return a human readable `str` representing the X509 public certificate

    :param pem: The PEM data for the public certificate.
    :return: the PEM data in human readable form.
    '''
    x509: OpenSSL.crypto.X509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem)
    serial: int = x509.get_serial_number()
    subject: OpenSSL.crypto.X509Name = x509.get_subject()
    issuer: OpenSSL.crypto.X509Name = x509.get_issuer()
    start_str: Optional[bytes] = x509.get_notBefore()
    start: Optional[datetime.datetime] = None
    if start_str is not None:
        start = datetime.datetime.strptime(start_str.decode('utf-8'), '%Y%m%d%H%M%SZ').replace(tzinfo=datetime.timezone.utc)
    end_str: Optional[bytes] = x509.get_notAfter()
    end: Optional[datetime.datetime] = None
    if end_str is not None:
        end = datetime.datetime.strptime(end_str.decode('utf-8'), '%Y%m%d%H%M%SZ').replace(tzinfo=datetime.timezone.utc)
    public_key: OpenSSL.crypto.PKey = x509.get_pubkey()
    sig_alg: str = x509.get_signature_algorithm().decode('utf-8')
    version: int = x509.get_version()
    out_prefix = ' ' * indent
    ret: str = f'''{out_prefix}Certificate:
{out_prefix}    Data:
{out_prefix}        Version: {1+version} ({hex(version)})
{out_prefix}        Serial Number: {serial} ({hex(serial)})
{out_prefix}        Signature Algorithm: {sig_alg}
{out_prefix}        Issuer: {format_x509_name(issuer)}
'''
    if start is not None or end is not None:
        ret += f'{out_prefix}        Validity\n'
        if start is not None:
            ret += f'{out_prefix}            Not Before: {start:%b %d %H:%M:%S %Y %Z}\n'
        if end is not None:
            ret += f'{out_prefix}            Not After: {end:%b %d %H:%M:%S %Y %Z}\n'
    ret += f'{out_prefix}        Subject: {format_x509_name(subject)}\n'
    ret += f'''{out_prefix}        Subject Public Key Info:
{format_pkey(public_key, indent=indent+12)}
'''
    if x509.get_extension_count() > 0:
        ret += f'{out_prefix}        X509v3 extensions:\n'
        for ext_idx in range(x509.get_extension_count()):
            ext = x509.get_extension(ext_idx)
            ret += f'{format_x509_extension(ext, indent=indent+12)}'
    return ret

async def cmd_certificates_show(args: argparse.Namespace) -> int:
    client = await getClient(args)
    provisioning_session_id = args.provisioning_session_id
    certificate_id = args.certificate_id
    info = args.info
    resp: Optional[ServerCertificateResponse] = await client.retrieveServerCertificate(provisioning_session_id, certificate_id)
    if resp is None:
        print('Certificate pending upload')
        return 1
    if info:
        print(f'''certificate_id={resp['ServerCertificateId']}
{format_x509_pem(resp['ServerCertificate'])}
''')
    else:
        print(resp['ServerCertificate'])
    return 0

async def cmd_certificates_delete(args: argparse.Namespace) -> int:
    client = await getClient(args)
    provisioning_session_id = args.provisioning_session_id
    certificate_id = args.certificate_id
    resp: bool = await client.destroyServerCertificate(provisioning_session_id, certificate_id)
    if not resp:
        print('Failed to delete server certificate')
        return 1
    return 0

def format_ContentHostingConfigurationResponse(resp: ContentHostingConfigurationResponse, indent: int = 0) -> str:
    ret = ''
    out_prefix = ' ' * indent
    if resp['ETag'] is not None:
        ret += f'{out_prefix}ETag: {resp["ETag"]}\n'
    if resp['Last-Modified'] is not None:
        ret += f'{out_prefix}Last-Modified: {resp["Last-Modified"]:%b %d %H:%M:%S %Y %Z}\n'
    if resp['Cache-Until'] is not None:
        ret += f'{out_prefix}Cache-Until: {resp["Cache-Until"]:%b %d %H:%M:%S %Y %Z}\n'
    ret += f'''{out_prefix}Provisioning-Session-Id: {resp["ProvisioningSessionId"]}

{out_prefix}{resp["ContentHostingConfiguration"]!r}
'''
    return ret

async def cmd_hosting_create(args: argparse.Namespace) -> int:
    client = await getClient(args)
    provisioning_session_id = args.provisioning_session_id
    chc_file = args.CHC_JSON_file
    async with aiofiles.open(chc_file, mode='r') as chc_in:
        chc = ContentHostingConfiguration.fromJSON(await chc_in.read())
    resp: Union[bool,ContentHostingConfigurationResponse] = await client.createContentHostingConfiguration(provisioning_session_id,
                                                                                                           chc)
    if isinstance(resp, dict):
        print(format_ContentHostingConfigurationResponse(resp))
        return 0
    if resp:
        print('ContentHostingConfiguration set for provisioning session {provisioning_session_id}')
        return 0
    print('Failed to set ContentHostingConfiguration for provisioning session {provisioning_session_id}')
    return 1

async def cmd_hosting_show(args: argparse.Namespace) -> int:
    client = await getClient(args)
    provisioning_session_id = args.provisioning_session_id
    resp: Optional[ContentHostingConfigurationResponse] = await client.retrieveContentHostingConfiguration(provisioning_session_id)
    if resp is None:
        print('ContentHostingConfiguration not found for provisioning session {provisioning_session_id}')
        return 1
    print(format_ContentHostingConfigurationResponse(resp))
    return 0

async def cmd_hosting_update(args: argparse.Namespace) -> int:
    client = await getClient(args)
    provisioning_session_id = args.provisioning_session_id
    chc_file = args.CHC_JSON_file
    async with aiofiles.open(chc_file, mode='r') as chc_in:
        chc = ContentHostingConfiguration.fromJSON(await chc_in.read())
    resp: bool = await client.updateContentHostingConfiguration(provisioning_session_id, chc)
    if not resp:
        print(f'Failed to update ContentHostingConfiguration for provisioning session {provisioning_session_id}')
        return 1
    print(f'Updated ContentHostingConfiguration for provisioning session {provisioning_session_id}')
    return 0

async def cmd_hosting_delete(args: argparse.Namespace) -> int:
    client = await getClient(args)
    provisioning_session_id = args.provisioning_session_id
    resp: bool = await client.destroyContentHostingConfiguration(provisioning_session_id)
    if not resp:
        print(f'Failed to remove ContentHostingConfiguration for provisioning session {provisioning_session_id}')
        return 1
    print(f'ContentHostingConfiguration for provisioning session {provisioning_session_id} has been removed')
    return 0

async def cmd_hosting_purge(args: argparse.Namespace) -> int:
    client = await getClient(args)
    provisioning_session_id: ResourceId = args.provisioning_session_id
    pattern: Optional[str] = args.path_regex
    resp: Optional[int] = await client.purgeContentHostingCache(provisioning_session_id, pattern)
    if resp is None:
        print('No entries purged')
    else:
        print(f'There were {resp} entries purged from the cache')
    return 0

async def __consumptionReportingConfigurationFromArgs(args: argparse.Namespace) -> ConsumptionReportingConfiguration:
    crc: ConsumptionReportingConfiguration = {}
    if args.interval is not None:
        crc['reportingInterval'] = args.interval
    if args.percentage is not None:
        crc['samplePercentage'] = args.percentage
    if args.locationReport:
        crc['locationReporting'] = True
    if args.accessReport:
        crc['accessReporting'] = True
    return crc

async def cmd_consumption_create(args: argparse.Namespace) -> int:
    client = await getClient(args)
    provisioning_session_id: ResourceId = args.provisioning_session_id
    crc: ConsumptionReportingConfiguration = await __consumptionReportingConfigurationFromArgs(args)
    resp: Union[bool, ConsumptionReportingConfigurationResponse] = await client.activateConsumptionReportingConfiguration(provisioning_session_id, crc)
    if isinstance(resp, bool) and resp or isinstance(resp, ConsumptionReportingConfigurationResponse):
        print('ConsumptionReportingConfiguration created')
    return 0

async def cmd_consumption_show(args: argparse.Namespace) -> int:
    client = await getClient(args)
    provisioning_session_id: ResourceId = args.provisioning_session_id
    try:
        resp: ConsumptionReportingConfigurationResponse = await client.retrieveConsumptionReportingConfiguration(provisioning_session_id)
        print(ConsumptionReportingConfiguration.format(resp['ConsumptionReportingConfiguration']))
    except M1ClientError as err:
        if err.args[1] == 404:
            print('No ConsumptionReportingConfiguration for provisioning session')
        else:
            raise err
    return 0

async def cmd_consumption_update(args: argparse.Namespace) -> int:
    client = await getClient(args)
    provisioning_session_id: ResourceId = args.provisioning_session_id
    crc: ConsumptionReportingConfiguration = await __consumptionReportingConfigurationFromArgs(args)
    resp: bool = await client.updateConsumptionReportingConfiguration(provisioning_session_id, crc)
    if resp:
        print('ConsumptionReportingConfiguration updated')
    else:
        print('ConsumptionReportingConfiguration update failed')
    return 0

async def cmd_consumption_delete(args: argparse.Namespace) -> int:
    client = await getClient(args)
    provisioning_session_id: ResourceId = args.provisioning_session_id
    resp: bool = await client.destroyConsumptionReportingConfiguration(provisioning_session_id)
    if resp:
        print('ConsumptionReportingConfiguration deleted')
    else:
        print('ConsumptionReportingConfiguration failed to delete')
    return 0

async def __policyTemplateFromArgs(args: argparse.Namespace) -> PolicyTemplate:
    with open(args.policy_template,'r') as pol_file:
        return PolicyTemplate.fromJSON(pol_file.read())

async def cmd_policy_create(args: argparse.Namespace) -> int:
    client = await getClient(args)
    provisioning_session_id: ResourceId = args.provisioning_session_id
    policy: PolicyTemplate = await __policyTemplateFromArgs(args)
    resp: Optional[PolicyTemplateResponse] = await client.createPolicyTemplate(provisioning_session_id, policy)
    if resp is None:
        print('PolicyTemplate creation failed: No such provisioning session')
    else:
        print(f'''PolicyTemplate {resp['PolicyTemplate']['policyTemplateId']} created''')
    return 0

async def cmd_policy_show(args: argparse.Namespace) -> int:
    client = await getClient(args)
    provisioning_session_id: ResourceId = args.provisioning_session_id
    policy_template_id: ResourceId = args.policy_template_id
    resp: Optional[PolicyTemplateResponse] = await client.retrievePolicyTemplate(provisioning_session_id, policy_template_id)
    if resp is None:
        print(f'PolicyTemplate "{policy_template_id}" for provisioning session "{provisioning_session_id}" not found')
    else:
        print(f'''{PolicyTemplate.format(resp['PolicyTemplate'])}''')
    return 0

async def cmd_policy_update(args: argparse.Namespace) -> int:
    client = await getClient(args)
    provisioning_session_id: ResourceId = args.provisioning_session_id
    policy_template_id: ResourceId = args.policy_template_id
    policy: PolicyTemplate = await __policyTemplateFromArgs(args)
    resp: bool = await client.updatePolicyTemplate(provisioning_session_id, policy_template_id, policy)
    if resp:
        print('PolicyTemplate updated successfully')
    else:
        print('PolicyTemplate update failed')
    return 0

async def cmd_policy_delete(args: argparse.Namespace) -> int:
    client = await getClient(args)
    provisioning_session_id: ResourceId = args.provisioning_session_id
    policy_template_id: ResourceId = args.policy_template_id
    resp: bool = await client.destroyPolicyTemplate(provisioning_session_id, policy_template_id)
    if resp:
        print('PolicyTemplate deleted')
    else:
        print('Failed to delete policy {policy_template_id} for provisioning session {provisioning_session_id}')
    return 0

async def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog='m1-client', description='M1 Client API tool')
    subparsers = parser.add_subparsers(required=True)

    # Parent parser for AF address
    parent_addr = argparse.ArgumentParser(add_help=False)
    parent_addr.add_argument('address', metavar='address:port', help='Address of the 5GMS AF')

    # Parent parser for AF address and provisioning session id
    parent_addr_prov = argparse.ArgumentParser(parents=[parent_addr], add_help=False)
    parent_addr_prov.add_argument('provisioning_session_id', metavar='provisioning-session-id', help='The provisioning session id')

    # m1-client provisioning <cmd> ...
    parser_provisioning = subparsers.add_parser('provisioning', help='Provisioning Session Management')
    provisioning_subparsers = parser_provisioning.add_subparsers(required=True)

    # m1-client provisioning create [-h] <address:port> (-d|-u) <external-app-id> [<asp-id>]
    parser_provisioning_create = provisioning_subparsers.add_parser('create', parents=[parent_addr],
                                                                    help='Create a new provisioning session')
    parser_provisioning_create.set_defaults(command=cmd_provisioning_create)
    parser_provisioning_create_type = parser_provisioning_create.add_mutually_exclusive_group(required=True)
    parser_provisioning_create_type.add_argument('-d', '--downlink', action='store_true', help='Provisioning session is a downlink')
    parser_provisioning_create_type.add_argument('-u', '--uplink', action='store_true', help='Provisioning session is an uplink')
    parser_provisioning_create.add_argument('external_app_id', metavar='external-app-id', help='The external application id')
    parser_provisioning_create.add_argument('asp_id', metavar='asp-id', nargs='?', help='The Application Service Provider id')

    # m1-client provisioning show [-h] <address:port> <provisioning-session-id>
    parser_provisioning_show = provisioning_subparsers.add_parser('show', parents=[parent_addr_prov],
                                                                  help='Retreive and display a provisioning session')
    parser_provisioning_show.set_defaults(command=cmd_provisioning_show)

    # m1-client provisioning delete [-h] <address:port> <provisioning-session-id>
    parser_provisioning_delete = provisioning_subparsers.add_parser('delete', parents=[parent_addr_prov],
                                                                    help='Delete a provisioning session')
    parser_provisioning_delete.set_defaults(command=cmd_provisioning_delete)

    # m1-client protocols [-h] <address:port> <provisioning-session-id>
    parser_protocols = subparsers.add_parser('protocols', parents=[parent_addr_prov],
                                             help='Get the ContentProtocols for a provisioning session')
    parser_protocols.set_defaults(command=cmd_protocols)

    # m1-client certificates <cmd> ...
    parser_certificates = subparsers.add_parser('certificates', help='ServerCertificatesProvisioning API')
    certificates_subparsers = parser_certificates.add_subparsers(required=True)

    # m1-client certificates create [-h] <address:port> <provisioning-session-id> [--csr]
    parser_certificates_create = certificates_subparsers.add_parser('create', parents=[parent_addr_prov],
                                                                    help='Create or reserve a new certificate')
    parser_certificates_create.set_defaults(command=cmd_certificates_create)
    parser_certificates_create.add_argument('--csr', metavar='FQDN', nargs='*', help='Reserve a certificate and return the CSR, provide optional extra domain names')

    # m1-client certificates upload [-h] <address:port> <provisioning-session-id> <certificate-id> <PEM-file>
    parser_certificates_upload = certificates_subparsers.add_parser('upload', parents=[parent_addr_prov],
                                                                    help='Upload a public certificate')
    parser_certificates_upload.set_defaults(command=cmd_certificates_upload)
    parser_certificates_upload.add_argument('certificate_id', metavar='certificate-id', help='The certificate id to upload')
    parser_certificates_upload.add_argument('PEM_file', metavar='PEM-file', help='The public certificate PEM file to upload')

    # m1-client certificates show [-h] <address:port> <provisioning-session-id> <certificate-id> [--info]
    parser_certificates_show = certificates_subparsers.add_parser('show', parents=[parent_addr_prov],
                                                                  help='Display a public certificate')
    parser_certificates_show.set_defaults(command=cmd_certificates_show)
    parser_certificates_show.add_argument('certificate_id', metavar='certificate-id', help='The certificate id to upload')
    parser_certificates_show.add_argument('-i', '--info', action='store_true',
                                          help='Display certificate information instead of the PEM data')

    # m1-client certificates delete [-h] <address:port> <provisioning-session-id> <certificate-id>
    parser_certificates_delete = certificates_subparsers.add_parser('delete', parents=[parent_addr_prov],
                                                                    help='Delete a certificate')
    parser_certificates_delete.set_defaults(command=cmd_certificates_delete)
    parser_certificates_delete.add_argument('certificate_id', metavar='certificate-id', help='The certificate id to delete')

    # m1-client hosting <cmd> ...
    parser_hosting = subparsers.add_parser('hosting', help='ContentHostingProvisioing APIs')
    hosting_subparsers = parser_hosting.add_subparsers(required=True)

    # m1-client hosting create [-h] <address:port> <provisioning-session-id> <CHC-JSON-file>
    parser_hosting_create = hosting_subparsers.add_parser('create', parents=[parent_addr_prov],
                                                          help='Add a ContentHostingConfiguration to a provisioning session')
    parser_hosting_create.set_defaults(command=cmd_hosting_create)
    parser_hosting_create.add_argument('CHC_JSON_file', metavar='CHC-JSON-file',
                                       help='Path to a ContentHostingConfiguration JSON file')

    # m1-client hosting show [-h] <address:port> <provisioning-session-id>
    parser_hosting_show = hosting_subparsers.add_parser('show', parents=[parent_addr_prov],
                                                        help='Display the ContentHostingConfiguration for a provisioning session')
    parser_hosting_show.set_defaults(command=cmd_hosting_show)

    # m1-client hosting update [-h] <address:port> <provisioning-session-id> <CHC-JSON-file>
    parser_hosting_update = hosting_subparsers.add_parser('update', parents=[parent_addr_prov],
                                                  help='Update the existing ContentHostingConfiguration in a provisioning session')
    parser_hosting_update.set_defaults(command=cmd_hosting_update)
    parser_hosting_update.add_argument('CHC_JSON_file', metavar='CHC-JSON-file',
                                       help='Path to a ContentHostingConfiguration JSON file')

    # m1-client hosting delete [-h] <address:port> <provisioning-session-id>
    parser_hosting_delete = hosting_subparsers.add_parser('delete', parents=[parent_addr_prov],
                                                          help='Delete the ContentHostingConfiguration for a provisioning session')
    parser_hosting_delete.set_defaults(command=cmd_hosting_delete)

    # m1-client hosting purge [-h] <address:port> <provisioning-session-id> [<path-regex>]
    parser_hosting_purge = hosting_subparsers.add_parser('purge', parents=[parent_addr_prov],
                                                         help='Purge the cache for a provisioning session')
    parser_hosting_purge.set_defaults(command=cmd_hosting_purge)
    parser_hosting_purge.add_argument('path_regex', metavar='path-regex', nargs='?',
                                      help='Regular expression to match for entries to purge')

    # m1-client consumption ...
    parser_consumption = subparsers.add_parser('consumption', help='ConsumptionReportingProvisioing APIs')
    consumption_subparsers = parser_consumption.add_subparsers(required=True)

    # m1-client consumption create [-h] <address:port> <provisioning-session-id> [-i <interval>] [-p <percentage>] [-l] [-a]
    parser_consumption_create = consumption_subparsers.add_parser('create', parents=[parent_addr_prov],
                                                                  help='Activate Consumption Reporting for a provisioning session')
    parser_consumption_create.set_defaults(command=cmd_consumption_create)
    parser_consumption_create.add_argument('-i','--interval', type=int, nargs=1,
                                      help='The reporting interval for consumption reporting in whole seconds')
    parser_consumption_create.add_argument('-p','--percentage', type=float, nargs=1,
                                      help='The sample percentage to request for consumption reporting')
    parser_consumption_create.add_argument('-l', '--location-reporting', action='store_true', dest='location_reporting',
                                      help='Indicates that location reporting should be requested')
    parser_consumption_create.add_argument('-a', '--access-reporting', action='store_true', dest='access_reporting',
                                      help='Indicates that access reporting should be requested')

    # m1-client consumption show [-h] <address:port> <provisioning-session-id>
    parser_consumption_show = consumption_subparsers.add_parser('show', parents=[parent_addr_prov],
                                                    help='Retrieve a ConsumptionReportingConfiguration for a provisioning session')
    parser_consumption_show.set_defaults(command=cmd_consumption_show)

    # m1-client consumption update [-h] <address:port> <provisioning-session-id> [-i <interval>] [-p <percentage>] [-l] [-a]
    parser_consumption_update = consumption_subparsers.add_parser('update', parents=[parent_addr_prov],
                                                                  help='Update Consumption Reporting for a provisioning session')
    parser_consumption_update.set_defaults(command=cmd_consumption_update)
    parser_consumption_update.add_argument('-i','--interval', type=int, nargs=1,
                                      help='The reporting interval for consumption reporting in whole seconds')
    parser_consumption_update.add_argument('-p','--percentage', type=float, nargs=1,
                                      help='The sample percentage to request for consumption reporting')
    parser_consumption_update.add_argument('-l', '--location-reporting', action='store_true', dest='location_reporting',
                                      help='Indicates that location reporting should be requested')
    parser_consumption_update.add_argument('-a', '--access-reporting', action='store_true', dest='access_reporting',
                                      help='Indicates that access reporting should be requested')

    # m1-client consumption delete [-h] <address:port> <provisioning-session-id>
    parser_consumption_delete = consumption_subparsers.add_parser('delete', parents=[parent_addr_prov],
                                                                  help='Delete the Consumption Reporting for a provisioning session')
    parser_consumption_delete.set_defaults(command=cmd_consumption_delete)

    # m1-client policy ...
    parser_policy = subparsers.add_parser('policy', help='PolicyTemplateProvisioning APIs')
    policy_subparsers = parser_policy.add_subparsers(required=True)

    # m1-client policy create [-h] <address:port> <provisioning-session-id> <PolicyTemplate-JSON-file>
    parser_policy_create = policy_subparsers.add_parser('create', parents=[parent_addr_prov],
                                                        help='Create a Policy Template for a provisioning session')
    parser_policy_create.set_defaults(command=cmd_policy_create)
    parser_policy_create.add_argument('policy_template', metavar='PolicyTemplate-JSON-file',
                                       help='Path to a PolicyTemplate JSON file')

    # m1-client policy show [-h] <address:port> <provisioning-session-id> <policy-template-id>
    parser_policy_show = policy_subparsers.add_parser('show', parents=[parent_addr_prov],
                                                      help='Display a Policy Template from a provisioning session')
    parser_policy_show.set_defaults(command=cmd_policy_show)
    parser_policy_show.add_argument('policy_template_id', metavar='policy-template-id',
                                    help='Id of the Policy Template to display from the provisioning session')

    # m1-client policy update [-h] <address:port> <provisioning-session-id> <policy-template-id> <PolicyTemplate-JSON-file>
    parser_policy_update = policy_subparsers.add_parser('update', parents=[parent_addr_prov],
                                                        help='Update a Policy Template for a provisioning session')
    parser_policy_update.set_defaults(command=cmd_policy_update)
    parser_policy_update.add_argument('policy_template_id', metavar='policy-template-id',
                                      help='Id of the Policy Template to update from the provisioning session')
    parser_policy_update.add_argument('policy_template', metavar='PolicyTemplate-JSON-file',
                                      help='Path to a PolicyTemplate JSON file')

    # m1-client policy delete [-h] <address:port> <provisioning-session-id> <policy-template-id>
    parser_policy_delete = policy_subparsers.add_parser('delete', parents=[parent_addr_prov],
                                                        help='Delete a PolicyTemplate from a provisioning session')
    parser_policy_delete.set_defaults(command=cmd_policy_delete)
    parser_policy_delete.add_argument('policy_template_id', metavar='policy-template-id',
                                      help='Id of the Policy Template to delete from the provisioning session')

    return parser.parse_args()

async def getClient(args: argparse.Namespace) -> M1Client:
    if not hasattr(args, 'address'):
        raise RuntimeError('Attempt to connect to M1Client without an address')
    (addr,port) = args.address.split(':')
    port = int(port)
    return M1Client((addr,port))

async def main():
    '''
    Async application entry point
    '''
    try:
        args = await parse_args()
        if hasattr(args, 'command'):
            return await args.command(args)
        print('Command not understood')
        return 1
    except M1Error as err:
        print(f'Communication error: {err}')
        return 2
    return 0

def app():
    '''
    Application entry point
    '''
    return asyncio.run(main())

if __name__ == '__main__':
    sys.exit(app())
