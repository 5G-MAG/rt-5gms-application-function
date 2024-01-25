#!/usr/bin/python3
#==============================================================================
# 5G-MAG Reference Tools: M1 Client Local CA Certificate Signing
#==============================================================================
#
# File: rt_m1_client/certificates/local_ca_cert_signer.py
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
# M1 Session Certificate Signing using a local CA
# ===============================================
#
# This module defines classes used by the M1 session classes to sign certificates
#
# LocalCACertificateSigner - A CertificateSigner that uses a locally generated CA to generate X509 certificates from CSRs
#
'''
=======================================================================
5G-MAG Reference Tools: M1 Session Certificate Signing using a local CA
=======================================================================

This module defines some classes that can be used by the `M1Session` class to provide certificate signing services.

'''
from typing import Optional, Tuple, List

import OpenSSL

from .base import CertificateSigner
from ..data_store import DataStore

class LocalCACertificateSigner(CertificateSigner):
    '''CertificateSigner that uses a locally generated CA kept in the data store
    '''

    def __init__(self, *args, data_store: Optional[DataStore] = None, local_ca_days: int = 365, temp_ca_days: int = 1, local_cert_days: int = 30, **kwargs):
        '''Constructor

        Create a CertificateSigner that uses a locally generated CA to sign certificates.

        :param DataStore data_store: The DataStore to use to persist the CA key and certificate.
        :param int local_ca_days: The number of days before expiry of the local CA in the data store.
        :param int temp_ca_days: The number of days for the local CA if no DataStore is provided for persistence.
        :param int local_cert_days: The number of days before expiry of signed certificates.
        '''
        super().__init__(self, data_store=data_store)
        self.__ca_key: Optional[OpenSSL.crypto.PKey] = None
        self.__ca: Optional[OpenSSL.crypto.X509] = None
        self.__local_ca_days: int = local_ca_days
        self.__temp_ca_days: int = temp_ca_days
        self.__local_cert_days: int = local_cert_days

    async def signCertificate(self, csr: str, *args, **kwargs) -> Optional[str]:
        '''Sign a CSR in PEM format and return the public X509 Certificate in PEM format

        This will generate a public certificate from the *csr*, which is signed by the locally generated CA.
        The certificate will have subjectAltNames defined for the SANs in the *csr* and the commonName. The certificate will expire
        in the number of days indicated by the *local_cert_days* parameter when an instance of this class was created.

        :param str csr: A CSR in PEM format.

        :return: a public X509 certificate in PEM format, or None on error.
        '''
        x509req: OpenSSL.crypto.X509Req = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr.encode('utf-8'))
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
        # Copy any extensions we aren't replacing
        for ext in x509req.get_extensions():
            if ext.get_short_name() not in [b'subjectKeyIdentifier', b'authorityKeyIdentifier', b'basicConstraints']:
                x509.add_extensions([ext])
        x509.add_extensions([
            OpenSSL.crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=x509),
            OpenSSL.crypto.X509Extension(b'authorityKeyIdentifier', False, b'keyid, issuer', issuer=ca),
            OpenSSL.crypto.X509Extension(b'basicConstraints', True, b'CA:FALSE')
            ])
        x509.sign(ca_key, "sha256")
        return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, x509).decode('utf-8')

    async def __makeCACert(self, key: OpenSSL.crypto.PKey, cn: str, days: int = 365) -> OpenSSL.crypto.X509:
        '''Make a CA certificate

        The CA certificate will use the provided *key* for its public key (if a private key is provided the pubilc key will be
        extracted). The *cn* parameter defines the common name for the CA certificate. The *days* parameter is used to set the
        expiry date on the CA certificate.

        :meta private:
        :param OpenSSL.crypto.PKey key: A public or private key to use for the public key of the CA certificate.
        :param str cn: The commonName for the certificate subject and issuer.
        :param int days: The number of days the CA certificate will be valid for.

        :return: a self signed X509 CA certificate.
        :rtype: OpenSSL.crypto.X509
        '''
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

    async def __getLocalCA(self) -> Tuple[OpenSSL.crypto.PKey, OpenSSL.crypto.X509]:
        '''Get the locally generated CA

        This will create the locally generated CA if it doesn't already exist.

        :meta private:
        :return: the CA key and CA public certificate.
        :rtype: Tuple[OpenSSL.crypto.PKey, OpenSSL.crypto.X509]
        '''
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
