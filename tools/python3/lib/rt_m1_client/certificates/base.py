#!/usr/bin/python3
#==============================================================================
# 5G-MAG Reference Tools: M1 Client Certificate Signing base class
#==============================================================================
#
# File: rt_m1_client/certificates/base.py
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
# M1 Session Certificate Signing base class
# =========================================
#
# This module defines classes used by the M1 session classes to sign certificates
#
# CertificateSigner - Base class for certificate signing.
#
'''
=================================================================
5G-MAG Reference Tools: M1 Session Certificate Signing base class
=================================================================

This module defines some classes that can be used by the `M1Session` class to provide certificate signing services.

'''
from typing import Optional

from ..data_store import DataStore

class CertificateSigner:
    '''Base class for all CertificateSigner classes
    '''
    def __init__(self, *args, data_store: Optional[DataStore] = None, **kwargs):
        self.data_store = data_store

    def __await__(self):
        '''Await method

        This allows the class to be instantiated with asynchronous initialisation, e.g.::
            cert_signer = await MyCertificateSigner()

        This will call the async method `asyncInit` to perform the asynchronous initialisation operations.
        '''
        return self.asyncInit().__await__()

    async def asyncInit(self):
        '''Asynchronous object initialisation

        Derived classes should override this if they have object initialisation to do that requires async operations.

        This async method must return self.
        '''
        return self

    async def signCertificate(self, csr: str, *args, **kwargs) -> Optional[str]:
        '''Sign a CSR in PEM format and return the public X509 Certificate in PEM format

        :param str csr: A CSR in PEM format.

        :return: a public X509 certificate in PEM format.
        '''
        raise NotImplementedError('Class derived from CertificateSigner must implement this method')
