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

import asyncio
import sys

from rt_m1_client.session import M1Session
from rt_m1_client.exceptions import M1Error
from rt_m1_client.data_store import JSONFileDataStore

async def main():
    '''
    Async application entry point
    '''
    try:
        data_store = JSONFileDataStore('m1-client-datastore')
        m1_session = M1Session(('127.0.0.22', 7778), data_store)
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
    return asyncio.run(main())

if __name__ == '__main__':
    sys.exit(app())
