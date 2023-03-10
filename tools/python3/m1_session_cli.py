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
'''5G-MAG Reference Tools: M1 Session CLI

Perform operations on the 5GMS Application Function via the interface at
reference point M1.

Syntax:
    m1-session-cli -h
    m1-session-cli configure show
    m1-session-cli configure set <key> <value>
    m1-session-cli configure get <key>
    m1-session-cli list [-v]
    m1-session-cli new-stream <ingest-URL> [--with-ssl|--ssl-only] [<entry-point-suffix-URL>]
    m1-session-cli del-stream -p <provisioning-session-id>
    m1-session-cli del-stream <ingest-URL> [<entry-point-suffix-URL>]
    m1-session-cli check-certificate-renewal
    m1-session-cli renew-certificate -p <provisioning-session-id>
    m1-session-cli renew-certificate <ingest-URL> [<entry-point-suffix-URL>]
'''

import argparse
import asyncio
import configparser
from io import StringIO
import logging
import os
import os.path
import sys
from typing import Tuple, List

from rt_m1_client.session import M1Session
from rt_m1_client.exceptions import M1Error
from rt_m1_client.data_store import JSONFileDataStore
from rt_m1_client.types import ContentHostingConfiguration

class Configuration:
    '''App configuration
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
    '''

    def __init__(self):
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
        if key in self.__default_config['m1-client']:
            return key
        raise ValueError('Not a valid configuration option')

    def get(self, key: str, default: str = None, raw: bool = False) -> str:
        return self.__config.get('m1-client', key, raw=raw, fallback=default)

    def set(self, key: str, value: str) -> bool:
        self.isKey(key)
        if key in self.__default_config['DEFAULT']:
            section = 'DEFAULT'
        else:
            section = 'm1-client'
        self.__config.set(section, key, value)
        self.__saveConfig()
        return True

    def isDefault(self, key: str) -> bool:
        return self.__config.get('m1-client', key) == self.__default_config.get('m1-client', key)

    def getKeys(self) -> List[str]:
        return list(self.__default_config['m1-client'].keys())

    def resetValue(self, key: str) -> bool:
        if self.isDefault(key):
            return False
        return self.set(key, self.__default_config.get('m1-client', key))

    def __saveConfig(self):
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
        buf = StringIO()
        self.__config.write(buf)
        return buf.getvalue()

    def __repr__(self):
        return f'Configuration(config="{self}")'

async def cmd_configure_show(args: argparse.Namespace, config: Configuration) -> int:
    default_marker = {True: ' (default)', False: ''}
    print('Configuration settings:')
    print('\n'.join([f'{key} = {config.get(key, raw=True)}{default_marker[config.isDefault(key)]}' for key in config.getKeys()]))
    return 0

async def cmd_configure_reset(args: argparse.Namespace, config: Configuration) -> int:
    config.resetValue(args.key)
    return 0

async def cmd_configure_get(args: argparse.Namespace, config: Configuration) -> int:
    print(f'{args.key}={repr(config.get(args.key))}')
    return 0

async def cmd_configure_set(args: argparse.Namespace, config: Configuration) -> int:
    config.set(args.key, args.value)
    return 0

async def cmd_list_verbose(args: argparse.Namespace, config: Configuration) -> int:
    session = await get_session(config)
    for ps_id in await session.provisioningSessionIds():
        print(f'{ps_id}:')
        certs = await session.certificateIds(ps_id)
        print('  Certificates:')
        print('\n'.join(['    '+cert for cert in certs]))
        chc = await session.contentHostingConfigurationGet(ps_id)
        print('  ContentHostingConfiguration:')
        print('\n'.join(['    '+line for line in ContentHostingConfiguration.format(chc).split('\n')]))
    return 0

async def cmd_list(args: argparse.Namespace, config: Configuration) -> int:
    if args.verbose:
        return await cmd_list_verbose(args, config)
    session = await get_session(config)
    print('\n'.join(await session.provisioningSessionIds()))
    return 0

async def cmd_new_stream(args: argparse.Namespace, config: Configuration) -> int:
    session = await get_session(config)
    name = args.name
    use_ssl = args.with_ssl or args.ssl_only
    use_plain = not args.ssl_only
    app_id = args.app_id or config.get('external_app_id')
    asp_id = args.asp_id or config.get('asp_id')
    provisioning_session_id = await session.createNewDownlinkPullStream(args.ingesturl, args.entrypoint, name=name, ssl=use_ssl, insecure=use_plain, app_id=app_id, asp_id=asp_id)
    print(f'Hosting created as provisioning session {provisioning_session_id}')
    return 0

async def cmd_delete_stream(args: argparse.Namespace, config: Configuration) -> int:
    if args.provisioning_session_id is not None:
        ps_id = args.provisioning_session_id
    else:
        ps_id = await session.provisioningSessionIdByIngestUrl(args.ingesturl, args.entrypointsuffix)
        if ps_id is None:
            print('No such hosting session found')
            return 1
    await session.provisioningSessionDestroy(ps_id)
    return 0

async def cmd_check_all_renewal(args: argparse.Namespace, config: Configuration) -> int:
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
    session = await get_session(config)
    ps_id = args.provisioning_session_id
    chc = await session.getContentHostingConfiguration(ps_id)
    # get list of unique cert ids in chc
    # for each cert id in list
    #   request a new certificate
    #   change ids in chc for new cert id
    # upload replacement chc
    # delete old certs
    return 1

async def parse_args() -> Tuple[argparse.Namespace,Configuration]:
    cfg = Configuration()

    parser = argparse.ArgumentParser(prog='m1-session-cli', description='M1 Session Tool')
    subparsers = parser.add_subparsers(required=True)

    parser_configure = subparsers.add_parser('configure', help='Local configuration')
    configure_subparsers = parser_configure.add_subparsers(required=True)
    parser_configure_show = configure_subparsers.add_parser('show', help='Show local configuration')
    parser_configure_show.set_defaults(command=cmd_configure_show)
    parser_configure_get = configure_subparsers.add_parser('get', help='Get local configuration value')
    parser_configure_get.set_defaults(command=cmd_configure_get)
    parser_configure_get.add_argument('key', metavar='KEY', type=cfg.isKey)
    parser_configure_set = configure_subparsers.add_parser('set', help='Set local configuration value')
    parser_configure_set.set_defaults(command=cmd_configure_set)
    parser_configure_set.add_argument('key', metavar='KEY', type=cfg.isKey)
    parser_configure_set.add_argument('value', metavar='VALUE')
    parser_configure_reset = configure_subparsers.add_parser('reset', help='Reset configuration value to its default')
    parser_configure_reset.set_defaults(command=cmd_configure_reset)
    parser_configure_reset.add_argument('key', metavar='KEY', type=cfg.isKey)
    
    parser_list = subparsers.add_parser('list', help='List provisioning sessions')
    parser_list.set_defaults(command=cmd_list)
    parser_list.add_argument('-v', '--verbose', required=False, action='store_true')

    parser_newstream = subparsers.add_parser('new-stream', help='Create a new ingest stream')
    parser_newstream.set_defaults(command=cmd_new_stream)
    parser_newstream.add_argument('-n', '--name', metavar='NAME', help='The name of the new stream', required=False)
    parser_newstream.add_argument('-e', '--external-app-id', dest='app_id', metavar="APPLICATION-ID", help='The external application id to register the stream to', required=False)
    parser_newstream.add_argument('-a','--asp-id', metavar="PROVIDER-ID", help="The Application Service Provider Id to use", required=False)
    parser_newstream_ssl_options = parser_newstream.add_mutually_exclusive_group(required=False)
    parser_newstream_ssl_options.add_argument('--with-ssl', action='store_true')
    parser_newstream_ssl_options.add_argument('--ssl-only', action='store_true')
    parser_newstream.add_argument('ingesturl', metavar='ingest-URL', help='The ingest URL prefix to use')
    parser_newstream.add_argument('entrypoint', metavar='entry-point-URL', nargs='?',
                                  help='The media player entry point suffix.')

    parser_delstream = subparsers.add_parser('del-stream', help='Delete an ingest stream')
    parser_delstream.set_defaults(command=cmd_delete_stream)
    parser_delstream_filter = parser_delstream.add_mutually_exclusive_group(required=True)
    parser_delstream_filter.add_argument('-p', '--provisioning-session', help='Delete by provisioning session id')
    #parser_delstream_filter_byurl = parser_delstream_filter.add_argument_group()
    #parser_delstream_filter_byurl.add_argument('ingesturl', metavar='ingest-URL', nargs=1,
    #                                           help='The ingest URL prefix to use')
    #parser_delstream_filter_byurl.add_argument('entrypoint', metavar='entry-point-URL', nargs='?',
    #                                           help='The media player entry point suffix.')
    parser_delstream_filter.add_argument('ingesturl', metavar='ingest-URL', nargs='?', help='The ingest URL prefix to use')

    parser_checkrenewal = subparsers.add_parser('check-certificate-renewal', help='Renew all certificates if close to expiry')
    parser_checkrenewal.set_defaults(command=cmd_check_all_renewal)

    parser_renewcert = subparsers.add_parser('renew-certificate', help='Force renewal of a specific certificate')
    parser_renewcert.set_defaults(command=cmd_renew_certs)
    parser_renewcert_filter = parser_renewcert.add_mutually_exclusive_group(required=True)
    parser_renewcert_filter.add_argument('-p', '--provisioning-session', help='Renew by provisioning session id')
    #parser_renewcert_filter_byurl = parser_renewcert_filter.add_argument_group(required=False)
    #parser_renewcert_filter_byurl.add_argument('ingesturl', metavar='ingest-URL', nargs=1,
    #                                           help='The ingest URL prefix to use')
    #parser_renewcert_filter_byurl.add_argument('entrypoint', metavar='entry-point-URL', nargs='?',
    #                                           help='The media player entry point suffix.')
    parser_renewcert_filter.add_argument('ingesturl', metavar='ingest-URL', nargs='?', help='The ingest URL prefix to use')

    args = parser.parse_args()

    return (args,cfg)

_m1_session = None

async def get_session(config: Configuration) -> M1Session:
    global _m1_session
    if _m1_session is None:
        data_store_dir = config.get('data_store')
        if data_store_dir is not None:
            data_store = await JSONFileDataStore(config.get('data_store'))
        else:
            data_store = None
        _m1_session = await M1Session((config.get('m1_address', 'localhost'), config.get('m1_port',7777)), data_store)
    return _m1_session

async def main():
    '''
    Async application entry point
    '''
    try:
        (args, config) = await parse_args()
        logging.basicConfig(level={k.lower(): v for k,v in logging.getLevelNamesMapping().items()}[config.get('log_level')])
        log = logging.getLogger()
        if hasattr(args, 'command'):
            return await args.command(args, config)
        else:
            print(repr(parse_args()))
        return 0

        provisioning_session_id = await m1_session.createNewDownlinkPullStream('https://ftp.itec.aau.at/datasets/DASHDataset2014/BigBuckBunny/4sec/', 'BigBuckBunny_4s_onDemand_2014_05_09.mpd', name='Test CHC', ssl=True, insecure=False, app_id='myAppId', asp_id='myAspId')
        print(f'Created Provisioning Session: {provisioning_session_id}')
        prov_sess = m1_session.getProvisioningSession(provisioning_session_id)
        print(f'ProvisioningSession = {repr(prov_sess)}')
    except M1Error as err:
        print(f'Communication error: {err}')
        return 2
    return 0

def app():
    '''
    Application entry point
    '''
    logging.basicConfig(level=logging.INFO)
    return asyncio.run(main())

if __name__ == '__main__':
    sys.exit(app())
