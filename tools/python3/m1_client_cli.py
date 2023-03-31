#!/usr/bin/python3
#==============================================================================
# 5G-MAG Reference Tools: M1 Client CLI
#==============================================================================
#
# File: m1_client_cli.py
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
    m1-client certificates create [-h] <address:port> <provisioning-session-id> [--csr]
    m1-client certificates upload [-h] <address:port> <provisioning-session-id> <certificate-id> <PEM-file>
    m1-client certificates show [-h] <address:port> <provisioning-session-id> <certificate-id> [--info]
    m1-client certificates delete [-h] <address:port> <provisioning-session-id> <certificate-id>
    m1-client hosting create [-h] <address:port> <provisioning-session-id> <CHC-JSON-file>
    m1-client hosting show [-h] <address:port> <provisioning-session-id>
    m1-client hosting update [-h] <address:port> <provisioning-session-id> <CHC-JSON-file>
    m1-client hosting delete [-h] <address:port> <provisioning-session-id>
    m1-client hosting purge [-h] <address:port> <provisioning-session-id> [<path-regex>]
'''

import argparse
import asyncio
import sys
from typing import Optional

from rt_m1_client.client import M1Client, ProvisioningSessionResponse, ContentProtocolsResponse, ServerCertificateSigningRequestResponse, ServerCertificateResponse
from rt_m1_client.types import PROVISIONING_SESSION_TYPE_DOWNLINK
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
    csr = args.csr
    resp: Optional[ServerCertificateSigningRequestResponse] = await client.createOrReserveServerCertificate(provisioning_session_id, csr=csr)
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
** TODO: Use OpenSSL to print certificate details **
''')
    else:
        print(resp['ServerCertificate'])
    return 0

async def cmd_certificates_delete(args: argparse.Namespace) -> int:
    raise NotImplementedError(__name__ + ' has not been implemented yet')

async def cmd_hosting_create(args: argparse.Namespace) -> int:
    raise NotImplementedError(__name__ + ' has not been implemented yet')

async def cmd_hosting_show(args: argparse.Namespace) -> int:
    raise NotImplementedError(__name__ + ' has not been implemented yet')

async def cmd_hosting_update(args: argparse.Namespace) -> int:
    raise NotImplementedError(__name__ + ' has not been implemented yet')

async def cmd_hosting_delete(args: argparse.Namespace) -> int:
    raise NotImplementedError(__name__ + ' has not been implemented yet')

async def cmd_hosting_purge(args: argparse.Namespace) -> int:
    raise NotImplementedError(__name__ + ' has not been implemented yet')

async def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog='m1-client', description='M1 Client API tool')
    subparsers = parser.add_subparsers(required=True)

    # Parent parser for AF address
    parent_addr = argparse.ArgumentParser(add_help=False)
    parent_addr.add_argument('address', metavar='address:port', help='Address of the 5GMS AF')

    # Parent parser for AF address and provisioning session id
    parent_addr_prov = argparse.ArgumentParser(parents=[parent_addr], add_help=False)
    parent_addr_prov.add_argument('provisioning-session-id', help='The provisioning session id')

    # m1-client provisioning <cmd> ...
    parser_provisioning = subparsers.add_parser('provisioning', help='Provisioning Session Management')
    provisioning_subparsers = parser_provisioning.add_subparsers(required=True)

    # m1-client provisioning create [-h] <address:port> (-d|-u) <external-app-id> [<asp-id>]
    parser_provisioning_create = provisioning_subparsers.add_parser('create', parents=[parent_addr], help='Create a new provisioning session')
    parser_provisioning_create.set_defaults(command=cmd_provisioning_create)
    parser_provisioning_create_type = parser_provisioning_create.add_mutually_exclusive_group(required=True)
    parser_provisioning_create_type.add_argument('-d', '--downlink', help='Provisioning session is a downlink')
    parser_provisioning_create_type.add_argument('-u', '--uplink', help='Provisioning session is an uplink')
    parser_provisioning_create.add_argument('external-app-id', help='The external application id')
    parser_provisioning_create.add_argument('asp-id', nargs='?', help='The Application Service Provider id')

    # m1-client provisioning show [-h] <address:port> <provisioning-session-id>
    parser_provisioning_show = provisioning_subparsers.add_parser('show', parents=[parent_addr_prov], help='Retreive and display a provisioning session')
    parser_provisioning_show.set_defaults(command=cmd_provisioning_show)

    # m1-client provisioning delete [-h] <address:port> <provisioning-session-id>
    parser_provisioning_delete = provisioning_subparsers.add_parser('delete', parents=[parent_addr_prov], help='Delete a provisioning session')
    parser_provisioning_delete.set_defaults(command=cmd_provisioning_delete)

    # m1-client protocols [-h] <address:port> <provisioning-session-id>
    parser_protocols = subparsers.add_parser('protocols', parents=[parent_addr_prov], help='Get the ContentProtocols for a provisioning session')
    parser_protocols.set_defaults(command=cmd_protocols)

    # m1-client certificates <cmd> ...
    parser_certificates = subparsers.add_parser('certificates', help='ServerCertificatesProvisioning API')
    certificates_subparsers = parser_certificates.add_subparsers(required=True)

    # m1-client certificates create [-h] <address:port> <provisioning-session-id> [--csr]
    parser_certificates_create = certificates_subparsers.add_parser('create', parents=[parent_addr_prov], help='Create or reserve a new certificate')
    parser_certificates_create.set_defaults(command=cmd_certificates_create)
    parser_certificates_create.add_argument('--csr', action='store_true', help='Reserve a certificate and return the CSR')

    # m1-client certificates upload [-h] <address:port> <provisioning-session-id> <certificate-id> <PEM-file>
    parser_certificates_upload = certificates_subparsers.add_parser('upload', parents=[parent_addr_prov], help='Upload a public certificate')
    parser_certificates_upload.set_defaults(command=cmd_certificates_upload)
    parser_certificates_upload.add_argument('certificate-id', help='The certificate id to upload')
    parser_certificates_upload.add_argument('PEM-file', help='The public certificate PEM file to upload')

    # m1-client certificates show [-h] <address:port> <provisioning-session-id> <certificate-id> [--info]
    parser_certificates_show = certificates_subparsers.add_parser('show', parents=[parent_addr_prov], help='Display a public certificate')
    parser_certificates_show.add_argument('certificate-id', help='The certificate id to upload')
    parser_certificates_show.add_argument('-i', '--info', action='store_true', help='Display certificate information instead of the PEM data')

    # m1-client certificates delete [-h] <address:port> <provisioning-session-id> <certificate-id>
    parser_certificates_delete = certificates_subparsers.add_parser('delete', parents=[parent_addr_prov], help='Delete a certificate')
    parser_certificates_show.add_argument('certificate-id', help='The certificate id to delete')

    # m1-client hosting <cmd> ...
    parser_hosting = subparsers.add_parser('hosting', help='ContentHostingProvisioing APIs')
    hosting_subparsers = parser_hosting.add_subparsers(required=True)

    # m1-client hosting create [-h] <address:port> <provisioning-session-id> <CHC-JSON-file>
    parser_hosting_create = hosting_subparsers.add_parser('create', parents=[parent_addr_prov], help='Add a ContentHostingConfiguration to a provisioning session')
    parser_hosting_create.set_defaults(command=cmd_hosting_create)
    parser_hosting_create.add_argument('CHC-JSON-file', help='Path to a ContentHostingConfiguration JSON file')

    # m1-client hosting show [-h] <address:port> <provisioning-session-id>
    parser_hosting_show = hosting_subparsers.add_parser('show', parents=[parent_addr_prov], help='Display the ContentHostingConfiguration for a provisioning session')
    parser_hosting_show.set_defaults(command=cmd_hosting_show)

    # m1-client hosting update [-h] <address:port> <provisioning-session-id> <CHC-JSON-file>
    parser_hosting_update = hosting_subparsers.add_parser('update', parents=[parent_addr_prov], help='Update the existing ContentHostingConfiguration in a provisioning session')
    parser_hosting_update.set_defaults(command=cmd_hosting_update)
    parser_hosting_update.add_argument('CHC-JSON-file', help='Path to a ContentHostingConfiguration JSON file')

    # m1-client hosting delete [-h] <address:port> <provisioning-session-id>
    parser_hosting_delete = hosting_subparsers.add_parser('delete', parents=[parent_addr_prov], help='Delete the ContentHostingConfiguration for a provisioning session')
    parser_hosting_delete.set_defaults(command=cmd_hosting_delete)

    # m1-client hosting purge [-h] <address:port> <provisioning-session-id> [<path-regex>]
    parser_hosting_purge = hosting_subparsers.add_parser('purge', parents=[parent_addr_prov], help='Purge the cache for a provisioning session')
    parser_hosting_purge.set_defaults(command=cmd_hosting_purge)
    parser_hosting_purge.add_argument('path-regex', nargs='?', help='Regular expression to match for entries to purge')

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
