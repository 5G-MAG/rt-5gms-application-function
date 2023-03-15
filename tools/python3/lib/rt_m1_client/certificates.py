#!/usr/bin/python3
#==============================================================================
# 5G-MAG Reference Tools: M1 Client Certificate Signing
#==============================================================================
#
# File: rt_m1_client/certificates.py
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
# M1 Session Certificate Signing
# =============================
#
# This module defines classes used by the M1 session classes to sign certificates
#
# CertificateSigner - Base class for certificate signing.
#
# LocalCACertificateSigner - A CertificateSigner that uses a locally generated CA to generate X509 certificates from CSRs
#
# DefaultCertificateSigner - The default CertificateSigner used by the M1Session class, presently LocalCACertificateSigner.
#
'''
======================================================
5G-MAG Reference Tools: M1 Session Certificate Signing
======================================================

This module defines some classes that can be used by the `M1Session` class to provide certificate signing services.

'''
from typing import Optional

import OpenSSL

from .data_store import DataStore

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

    async def signCertificate(self, csr: str, *args, domain_name_alias: Optional[str] = None, **kwargs) -> str:
        '''Sign a CSR in PEM format and return the public X509 Certificate in PEM format

        :param str csr: A CSR in PEM format.
        :param str domain_name_alias: Optional domain name to add to the subjectAltNames in the final certificate.

        :return: a public X509 certificate in PEM format.
        '''
        raise NotImplementedError('Class derived from CertificateSigner must implement this method')

class LocalCACertificateSigner(CertificateSigner):
    '''CertificateSigner that uses a locally generated CA kept in the data store
    '''

    def __init__(self, *args, data_store: Optional[DataStore] = None, local_ca_days: int = 365, temp_ca_days: int = 1, local_cert_days: int = 30, **kwargs):
        super().__init__(self, data_store=data_store)
        self.__ca_key = None
        self.__ca = None
        self.__local_ca_days = local_ca_days
        self.__temp_ca_days = temp_ca_days
        self.__local_cert_days = local_cert_days

    async def signCertificate(self, csr: str, *args, domain_name_alias: Optional[str] = None, **kwargs) -> str:
        '''Sign a CSR in PEM format and return the public X509 Certificate in PEM format

        :param str csr: A CSR in PEM format.
        :param str domain_name_alias: Optional domain name to add to the subjectAltNames in the final certificate.

        :return: a public X509 certificate in PEM format.
        '''
        x509req: OpenSSL.crypto.X509Req = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr.encode('utf-8'))
        need_canonical_sans = True
        for ext in x509req.get_extensions():
            ext_name = ext.get_short_name().decode('utf-8')
            if ext_name == 'subjectAltName' and str(ext) == 'DNS:'+x509req.get_subject().commonName:
                need_canonical_sans = False
        sans: List[OpenSSL.crypto.X509Extension] = []
        if need_canonical_sans:
            sans += [OpenSSL.crypto.X509Extension(b'subjectAltName', False, b'DNS:'+x509req.get_subject().commonName)]
        if domain_name_alias is not None:
            sans += [OpenSSL.crypto.X509Extension(b'subjectAltName', False, b'DNS:'+domain_name_alias.encode('utf-8'))]
        x509req.add_extensions(sans)
        # Get local CA
        ca_key, ca = await self.__getLocalCA()
        # Convert CSR to X509 certificate
        x509 = OpenSSL.crypto.X509()
        x509.set_subject(x509req.get_subject())
        x509.set_serial_number(1)
        x509.gmtime_adj_notBefore(0)
        x509.gmtime_adj_notAfter(self.__local_cert_days * 24 * 60 * 60)
        x509.set_issuer(ca.get_subject())
        x509.set_pubkey(x509req.get_pubkey())
        for ext in x509req.get_extensions():
            if ext.get_short_name() != b'authorityKeyIdentifier' and ext.get_short_name() != b'basicConstraints':
                x509.add_extensions([ext])
        x509.add_extensions([
            OpenSSL.crypto.X509Extension(b'authorityKeyIdentifier', False, b'keyid, issuer', issuer=ca),
            OpenSSL.crypto.X509Extension(b'basicConstraints', True, b'CA:FALSE')
            ])
        x509.sign(ca_key, "sha256")
        return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, x509).decode('utf-8')

    async def __makeCACert(self, key: OpenSSL.crypto.PKey, cn: str, days: int = 365):
        ca = OpenSSL.crypto.X509()
        ca_name = ca.get_subject()
        # TODO: Get these values from configured values
        ca_name.organizationName = '5G-MAG'
        ca_name.commonName = cn
        ca.set_issuer(ca_name)
        # TODO: increment serial number from data-store
        ca.set_serial_number(1)
        ca.gmtime_adj_notBefore(0)
        ca.gmtime_adj_notAfter(days*24*60*60)
        ca.set_pubkey(key)
        ca.add_extensions([
            OpenSSL.crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE,pathlen:1'),
            OpenSSL.crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=ca),
            OpenSSL.crypto.X509Extension(b'authorityKeyIdentifier', False, b'keyid, issuer:always', issuer=ca),
            ])
        ca.sign(key, 'sha256')
        return ca

    async def __getLocalCA(self):
        if self.__ca_key is None or self.__ca is None:
            if self.data_store:
                ca_key_pem = await self.data_store.get('ca-private')
                if ca_key_pem is not None:
                    self.__ca_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, ca_key_pem)
                else:
                    self.__ca_key = OpenSSL.crypto.PKey()
                    self.__ca_key.generate_key(OpenSSL.crypto.TYPE_RSA, 4096)
                    await self.data_store.set('ca-private', OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, self.__ca_key).decode('utf-8'))
                ca_pem = await self.data_store.get('ca-public')
                if ca_pem is not None:
                    self.__ca = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, ca_pem)
                else:
                    self.__ca = await self.__makeCACert(self.__ca_key, '5G-MAG Reference Tools Local CA', days=self.__local_ca_days)
                    await self.data_store.set('ca-public', OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, self.__ca).decode('utf-8'))
            else:
                self.__ca_key = OpenSSL.crypto.PKey()
                self.__ca_key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
                self.__ca = await self.__makeCACert(self.__ca_key, 'Temporary Demo CA', days=self.__temp_ca_days)

        return self.__ca_key, self.__ca

DefaultCertificateSigner = LocalCACertificateSigner

__all__ = [
        "M1Error",
        "M1ClientError",
        "M1ServerError",
        ]
