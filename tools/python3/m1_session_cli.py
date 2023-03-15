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
    m1-session-cli new-certificate -p <provisioning-session-id> [-d <domain-name> | --csr]
    m1-session-cli show-certificate -h
    m1-session-cli show-certificate -p <provisioning-session-id> -c <certificate-id>
    m1-session-cli set-certificate -h
    m1-session-cli set-certificate -p <provisioning-session-id> -c <certificate-id> [<certificate-PEM-file>]
    m1-session-cli check-certificates-renewal -h
    m1-session-cli check-certificates-renewal
    m1-session-cli renew-certificates -h
    m1-session-cli renew-certificates -p <provisioning-session-id>
    m1-session-cli renew-certificates <ingest-URL> [<entry-point-suffix-URL>]

Parameters:
    -a ID   --asp-id ID                   The application service provider id.
    -c ID   --certificate-id ID           The certificate id to operate on.
    -d FQDN --domain-name-alias FQDN      The alternate domain name to use.
    -e ID   --external-app-id ID          The external application id.
    -h      --help                        Display the help message.
    -n NAME --name NAME                   The hosting name.
    -p ID   --provisioning-session-id ID  The provisioning session id to use.
            --ssl-only                    Provide HTTPS only.
            --with-ssl                    Provide both HTTPS and HTTP.

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
import datetime
from io import StringIO
import logging
import os
import os.path
import sys
from typing import Tuple, List

import json
import OpenSSL

from rt_m1_client.session import M1Session
from rt_m1_client.exceptions import M1Error
from rt_m1_client.data_store import JSONFileDataStore
from rt_m1_client.types import ContentHostingConfiguration

class Configuration:
    '''Application configuration container

    This class handles the loading and saving of the application configuration
    '''

    DEFAULT_CONFIG='''[DEFAULT]
    log_dir = /var/log/rt-5gms
    state_dir = /var/cache/rt-5gms
    run_dir = /run/rt-5gms

    [m1-client]
    log_level = info
    data_store = %(state_dir)s/m1-client
    m1_address = localhost
    m1_port = 7777
    asp_id =
    external_app_id = please-change-this
    certificate_signing_class = rt_m1_client.certificates.DefaultCertificateSigner
    ''' #: The default configuration

    def __init__(self):
        '''Constructor

        Will load the previous configuration from ``/etc/rt-5gms/m1-client.conf`` if the command is run by root or
        ``~/.rt-5gms/m1-client.conf`` if run by any other user.
        '''
        self.__config_filename = None
        if os.getuid() != 0:
            self.__config_filename = os.path.expanduser(os.path.join('~', '.rt-5gms', 'm1-client.conf'))
        else:
            self.__config_filename = os.path.join(os.path.sep, 'etc', 'rt-5gms', 'm1-client.conf')
        self.__default_config = configparser.ConfigParser()
        self.__default_config.read_string(self.DEFAULT_CONFIG)
        self.__config = configparser.ConfigParser()
        self.__config.read_string(self.DEFAULT_CONFIG)
        if os.path.exists(self.__config_filename):
            self.__config.read(self.__config_filename)

    def isKey(self, key: str) -> str:
        '''Does a configuration field key exist?

        This tests *key* for being a valid configuration option field key name.

        :returns: The key string if it is a valid configuration field key.
        :raises: ValueError if the key string does not match a known configuration field key.
        '''
        if key in self.__default_config['m1-client']:
            return key
        raise ValueError('Not a valid configuration option')

    def get(self, key: str, default: str = None, raw: bool = False) -> str:
        '''Get a configuration value

        Retrieves the value for configuration option *key*. If the *key* does not exist the *default* will be returned. If *raw* is
        ``True`` and the *key* option exists then the raw configuration (without ``%()`` interpolation) value will be returned.

        :returns: The configuration option *key* value or *default* if key does not exist.
        '''
        return self.__config.get('m1-client', key, raw=raw, fallback=default)

    def set(self, key: str, value: str) -> bool:
        '''Set a configuration value

        Sets the raw *value* for configuration option *key*. If *key* is not a valid configuration option then ValueError exception
        will be raised.

        The configuration is saved once the *key* option has been set.
        '''
        self.isKey(key)
        if key in self.__default_config['DEFAULT']:
            section = 'DEFAULT'
        else:
            section = 'm1-client'
        self.__config.set(section, key, value)
        self.__saveConfig()
        return True

    def isDefault(self, key: str) -> bool:
        '''Checks if a key contains the default configuration value

        :returns: ``True`` if the configuration value for *key* is the default value, or ``False`` otherwise.
        '''
        return self.__config.get('m1-client', key) == self.__default_config.get('m1-client', key)

    def getKeys(self) -> List[str]:
        '''Get a list of configuration field name keys

        :returns: A list of configuration key names.
        '''
        return list(self.__default_config['m1-client'].keys())

    def resetValue(self, key: str) -> bool:
        '''Reset a configuration field to its default value

        :returns: ``True`` if the field was reset or ``False`` if the field already contained the default value.
        '''
        if self.isDefault(key):
            return False
        return self.set(key, self.__default_config.get('m1-client', key))

    def __saveConfig(self):
        '''Save the current configuration to local storage

        :meta private-method:

        Will save the current configuration to the relevant local file. Fields with the default value will be saved as a comment.
        '''
        cfgdir = os.path.dirname(self.__config_filename)
        if not os.path.exists(cfgdir):
            os.makedirs(cfgdir, mode=0o755)
        with open(self.__config_filename, 'w') as cfgout:
            for section in ['DEFAULT'] + self.__config.sections():
                cfgout.write(f'[{section}]\n')
                for key in self.__config[section]:
                    cfgvalue = self.__config.get(section, key, raw=True)
                    defvalue = self.__default_config.get(section, key, raw=True)
                    if (section == 'DEFAULT' or key not in self.__config['DEFAULT']):
                        if cfgvalue == defvalue:
                            cfgout.write('#')
                        cfgout.write(f'{key} = {cfgvalue}\n')
                cfgout.write('\n')

    def __str__(self):
        '''String representation of the configuration

        :returns: A ``str`` representing the configuration.
        '''
        buf = StringIO()
        self.__config.write(buf)
        return buf.getvalue()

    def __repr__(self):
        '''Textual represnetation of the Configuration object

        :returns: A ``str`` representation of the Configuration object.
        '''
        return f'Configuration(config="{self}")'

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
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
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
    for ext_num in range(x509.get_extension_count()):
        ext = x509.get_extension(ext_num)
        ext_name = ext.get_short_name().decode('utf-8')
        if ext_name == "subjectKeyIdentifier":
            subject_key = str(ext)
        elif ext_name == "authorityKeyIdentifier":
            issuer_key = str(ext)
    cert_info_prefix=' '*indent
    cert_desc=f'{cert_info_prefix}Serial = {serial}\n{cert_info_prefix}Not before = {start}\n{cert_info_prefix}Not after = {end}\n{cert_info_prefix}Subject = {__formatX509Name(subject)}\n'
    if subject_key is not None:
        cert_desc += f'{cert_info_prefix}          key={subject_key}\n'
    cert_desc += f'{cert_info_prefix}Issuer = {__formatX509Name(issuer)}'
    if issuer_key is not None:
        cert_desc += f'\n{cert_info_prefix}         key={issuer_key}'
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
    result = await session.contentHostingConfigurationCreate(provisioning_session_id, chc)
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
    provisioning_session_id = await session.createNewDownlinkPullStream(args.ingesturl, args.entrypoint, name=name, ssl=use_ssl, insecure=use_plain, app_id=app_id, asp_id=asp_id, domain_name_alias=domain_name_alias)
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
        ps_id = await session.provisioningSessionIdByIngestUrl(args.ingesturl, args.entrypointsuffix)
        if ps_id is None:
            print('No such hosting session found')
            return 1
    await session.provisioningSessionDestroy(ps_id)
    return 0

async def cmd_new_certificate(args: argparse.Namespace, config: Configuration) -> int:
    ''' Perform ``new-certificate`` operation

    This will create or reserve a new certificate in the provisioning session.
    '''
    session = await get_session(config)
    if args.csr:
        result = await session.certificateNewSigningRequest(args.provisioning_session)
        if result is None:
            print('Failed to reserve certificate')
            return 1
        cert_id, csr = result
        print(f'certificate_id={cert_id}')
        print(csr)
        return 0
    cert_id = await session.createNewCertificate(args.provisioning_session, domain_name_alias=args.domain_name_alias)
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
    await __prettyPrintCertificate(result)
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
    return 1

async def parse_args() -> Tuple[argparse.Namespace,Configuration]:
    '''Parse command line options and load app configuration

    :return: Tuple containing the command line arguments after validation and the app configuration
    :rtype: Tuple[argparse.Namespace,Configuration]
    '''
    cfg = Configuration()

    parser = argparse.ArgumentParser(prog='m1-session-cli', description='M1 Session Tool')
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
    #                           <ingest-URL> [<entry-point-path>]
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
    parser_newstream.add_argument('entrypoint', metavar='entry-point-path', nargs='?',
                                  help='The media player entry point path suffix.')

    # m1-session-cli del-stream -p <provisioning-session-id>
    # m1-session-cli del-stream <ingest-URL> [<entry-point-path>]
    parser_delstream = subparsers.add_parser('del-stream', help='Delete an ingest stream')
    parser_delstream.set_defaults(command=cmd_delete_stream)
    parser_delstream_filter = parser_delstream.add_mutually_exclusive_group(required=True)
    parser_delstream_filter.add_argument('-p', '--provisioning-session', help='Delete by provisioning session id')
    parser_delstream_filter.add_argument('ingesturl', metavar='ingest-URL', nargs='?', help='The ingest URL prefix to use')
    # The entry-point-path should go with ingest-URL, but argparser lacks the ability to do subgroups
    parser_delstream.add_argument('entrypoint', metavar='entry-point-path', nargs='?', help='The media player entry point suffix.')

    # m1-session-cli set-stream -p <provisioning-session-id> <CHC-JSON-FILE>
    parser_set_stream = subparsers.add_parser('set-stream', help='Set the hosting for a provisioning session from a JSON file')
    parser_set_stream.set_defaults(command=cmd_set_stream)
    parser_set_stream.add_argument('-p', '--provisioning-session', help='The provisioning session id to set the hosting for', required=True)
    parser_set_stream.add_argument('file', metavar='CHC-JSON-FILE', help='A filepath to a JSON encoded ContentHostingConfiguration')

    # m1-session-cli new-provisioning-session [-e <APPLICATION-ID>] [-a <PROVIDER-ID>]
    parser_new_provisioning_session = subparsers.add_parser('new-provisioning-session', help='Create a new provisioning session')
    parser_new_provisioning_session.set_defaults(command=cmd_new_provisioning_session)
    parser_new_provisioning_session.add_argument('-e', '--external-app-id', dest='app_id', metavar="APPLICATION-ID", help='The external application id to register the stream to', required=False)
    parser_new_provisioning_session.add_argument('-a','--asp-id', metavar="PROVIDER-ID", help="The Application Service Provider Id to use", required=False)

    # m1-session-cli new-certificate -p <provisioning-session-id> [-d <domain-name> | --csr]
    parser_new_certificate = subparsers.add_parser('new-certificate', help='Create a new certificate')
    parser_new_certificate.set_defaults(command=cmd_new_certificate)
    parser_new_certificate.add_argument('-p', '--provisioning-session',
                                        help='Provisioning session id to create the new certificate for')
    parser_new_certificate_extras = parser_new_certificate.add_mutually_exclusive_group(required=False)
    parser_new_certificate_extras.add_argument('-d', '--domain-name-alias', dest='domain_name_alias',
                                               help='FQDN to add as an extra domain name to the certificate')
    parser_new_certificate_extras.add_argument('--csr', action='store_true',
                                               help='Return a CSR to be signed externally and returned using set-certificate')

    # m1-session-cli show-certificate -p <provisioning-session-id> -c <certificate-id>
    parser_show_certificate = subparsers.add_parser('show-certificate', help='Retrieve a public certificate')
    parser_show_certificate.set_defaults(command=cmd_show_certificate)
    parser_show_certificate.add_argument('-p', '--provisioning-session', required=True,
                                         help='Provisioning session id to show the certificate for')
    parser_show_certificate.add_argument('-c', '--certificate-id', required=True,
                                         help='The certificate id of the certificate to show')

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
    parser_checkrenewal = subparsers.add_parser('check-certificate-renewal', help='Renew all certificates if close to expiry')
    parser_checkrenewal.set_defaults(command=cmd_check_all_renewal)

    # m1-session-cli renew-certificate -p <provisioning-session-id>
    # m1-session-cli renew-certificate <ingest-URL> [<entry-point-path>]
    parser_renewcert = subparsers.add_parser('renew-certificate', help='Force renewal of a specific certificate')
    parser_renewcert.set_defaults(command=cmd_renew_certs)
    parser_renewcert_filter = parser_renewcert.add_mutually_exclusive_group(required=True)
    parser_renewcert_filter.add_argument('-p', '--provisioning-session', help='Renew by provisioning session id')
    parser_renewcert_filter.add_argument('ingesturl', metavar='ingest-URL', nargs='?', help='The ingest URL prefix to use')
    # The entry-point-path should go with ingest-URL, but argparser lacks the ability to do subgroups
    parser_renewcert.add_argument('entrypoint', metavar='entry-point-path', nargs='?', help='The media player entry point suffix.')

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
        logging.basicConfig(level=log_levels[config.get('log_level')])
        log = logging.getLogger()
        if hasattr(args, 'command'):
            return await args.command(args, config)
        else:
            print(repr(parse_args()))
    except M1Error as err:
        print(f'Communication error: {err}')
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
