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
'''

import asyncio
import sys

from rt_m1_client import client as m1_client
from rt_m1_client.types import PROVISIONING_SESSION_TYPE_DOWNLINK
from rt_m1_client.exceptions import M1Error

async def main():
    '''
    Async application entry point
    '''
    try:
        m1_session = m1_client.M1Client(('127.0.0.22', 7778))
        provisioning_session_response = await m1_session.createProvisioningSession(
                PROVISIONING_SESSION_TYPE_DOWNLINK, 'myAppId', 'myAspId')
        if provisioning_session_response is None:
            print('Failed to create a provisioning session!')
            return 1

        provisioning_session_id = provisioning_session_response['ProvisioningSessionId']
        print(f'Provisioning Session {provisioning_session_id} created')

        certificate_resp = await m1_session.createServerCertificate(provisioning_session_id)
        if certificate_resp is None:
            print('Failed to create a server certificate')
            return 1

        certificate_id = certificate_resp['ServerCertificateId']
        print(f'Created certificate {certificate_id}')

        chc = {
            'name': 'Test CHC',
            'entryPointPath': 'BigBuckBunny_4s_onDemand_2014_05_09.mpd',
            'ingestConfiguration': {
                'pull': True,
                'protocol': 'urn:3gpp:5gms:content-protocol:http-pull-ingest',
                'baseURL': 'https://ftp.itec.aau.at/datasets/DASHDataset2014/BigBuckBunny/4sec/',
                },
            'distributionConfigurations': [
                    {
                        'certificateId': certificate_id,
                    }
                ]
            }
        result = await m1_session.createContentHostingConfiguration(provisioning_session_id, chc)
        print(f'Created CHC: {repr(result)}')
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
