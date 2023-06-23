#!/usr/bin/python3
#==============================================================================
# 5G-MAG Reference Tools: ACME Certificate Signing
#==============================================================================
#
# File: rt_acme_cert_signer/certsigner.py
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
# ACME Certificate Signing
# ========================
#
# This module defines an rt_m1_client.certificates.CertificateSigner class that
# will use an ACME service, such as Let's Encrypt, to generate signed
# certificates.
#
# ACMECertificateSigner - ACME certificate signing class.
#
# LetsEncryptCertificateSigner - Helper function to create an ACMECertificateSigner for the live Let's Encrypt service.
# TestLetsEncryptCertificateSigner - Helper function to create an ACMECertificateSigner for the staging Let's Encrypt service.
#
'''
================================================
5G-MAG Reference Tools: ACME Certificate Signing
================================================

This module defines an ACME `rt_m1_client.certificates.CertificateSigner` class
that can be used by the `rt_m1_client.certificates.M1Session` class to provide
certificate signing services which use an ACME service such as Let's Encrypt.
'''

# Python system modules
import aiofiles
import asyncio
from cryptography.hazmat.primitives.serialization import Encoding as cryptography_Encoding, PublicFormat as cryptography_PublicFormat
import logging
import os.path
import re
from typing import Optional, List, Tuple

# 3rd party modules
import OpenSSL

# Local modules
from .base import CertificateSigner
from ..data_store import DataStore

LOGGER = logging.getLogger(__name__)

class ACMECertificateSigner(CertificateSigner):
    '''ACMECertificateSigner class

    Class to perform certificate signing using an ACME certificate signing service.

    Constants
    =========

    - LetsEncryptService         - URL of the Let's Encrypt live service
    - LetsEncryptStagingService  - URL of the Let's Encrypt staging (test) service
    '''

    LetsEncryptStagingService: str = 'https://acme-staging-v02.api.letsencrypt.org/directory'
    LetsEncryptService: str = 'https://acme-v02.api.letsencrypt.org/directory'

    def __init__(self, *args, acme_service: Optional[str] = None, docroots_dir: Optional[str] = None, default_docroot_dir: Optional[str] = None, data_store: Optional[DataStore] = None, **kwargs):
        '''Constructor

        :param acme_service: The URL of the ACME directory service to use for certificate signing.
        :param docroots_dir: The directory that contains all the document roots for the virtual hosts, each host has a directory
                             whose name is the FQDN of the virtual host.
        :param default_docroot_dir: The directory which is the docroot of the default virtual host.
        :param data_store: The persistent data store object to use for data persistence.
        '''
        errs=[]
        if acme_service is None:
            errs += ['acme_service is None']
        if docroots_dir is None:
            errs += ['docroots_dir is None']
        if default_docroot_dir is None:
            errs += ['default_docroot_dir is None']
        if len(errs) != 0:
            raise RuntimeError(f'{self.__class__.__name__} instantiated without needed parameters: {", ".join(errs)}')
        super().__init__(*args, data_store=data_store, **kwargs)
        self.__acme_service: str = acme_service
        self.__docroots: str = docroots_dir
        self.__default_docroot: str = default_docroot_dir

    async def asyncInit(self):
        '''Asynchronous object initialisation

        Derived classes should override this if they have object initialisation to do that requires async operations.

        This async method must return self.
        '''
        return self

    async def signCertificate(self, csr: str, *args, **kwargs) -> Optional[str]:
        '''Sign a CSR in PEM format and return the public X509 Certificate in PEM format

        :param str csr: A CSR in PEM format.
        :param str domain_name_alias: Optional domain name to add to the subjectAltNames in the final certificate.

        :return: a public X509 certificate in PEM format.

        This will use the *csr* as a guideline for talking to the ACME server. The *domain_name_alias* will be used for the common name and first SAN, if the common name or SANs from the *csr* are not private IPs or localhost references then they will also be included.
        '''
        x509req: OpenSSL.crypto.X509Req = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr.encode('utf-8'))

        # Send request to ACME server
        acmeReqBytes: bytes = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, x509req)
        async with aiofiles.tempfile.NamedTemporaryFile('wb', delete=False) as f:
            await f.write(acmeReqBytes)
        common_name = x509req.get_subject().commonName
        if isinstance(common_name,bytes):
            common_name = common_name.decode('utf-8')
        domain_docroot = os.path.join(self.__docroots, common_name)
        old_umask = os.umask(0)
        try:
            await aiofiles.os.makedirs(domain_docroot, mode=0o755, exist_ok=True)
            if not os.path.lexists(os.path.join(domain_docroot, '.well-known')):
                await aiofiles.os.symlink(os.path.join(self.__default_docroot, '.well-known'), os.path.join(domain_docroot, '.well-known'), target_is_directory=True)
        finally:
            os.umask(old_umask)
        async with aiofiles.tempfile.TemporaryDirectory() as d:
            result, output = await _run_certbot_app(['certonly', '--server', self.__acme_service, '--webroot', '--webroot-path', self.__default_docroot, '--csr', f.name, '--cert-path', os.path.join(d, 'certificate.pem'), '--fullchain-path', os.path.join(d, 'fullchain.pem'), '--chain-path', os.path.join(d, 'chain.pem')])
            certdata = None
            if result == 0:
                async with aiofiles.open(os.path.join(d, 'fullchain.pem'), 'r') as inpem:
                    certdata = await inpem.read()
            else:
                log_error(f'certbot failed with exit code {result}: {output}')
        await aiofiles.os.remove(f.name)
        return certdata

async def _run_certbot_app(cmd_args: List[str]) -> Tuple[int, bytes]:
    '''Run `certbot` using the given command line arguments

    :param cmd_args: The command line arguments for `certbot`.

    :return: A tuple of the `certbot` process exit code and STDOUT from `certbot`.
    '''
    LOGGER.debug('Executing: certbot %s', ' '.join(['\''+s+'\'' for s in cmd_args]))
    proc = await asyncio.create_subprocess_exec('certbot', *cmd_args, stdout=asyncio.subprocess.PIPE)
    await proc.wait()
    LOGGER.debug('Command exited with code %i', proc.returncode)
    data = await proc.stdout.read()
    return (proc.returncode, data)

async def LetsEncryptCertificateSigner(*args, docroots_dir: Optional[str] = None, default_docroot_dir: Optional[str] = None, data_store: Optional[DataStore] = None, **kwargs) -> ACMECertificateSigner:
    '''Let's Encrypt ACMECertificateSigner factory function

    Creates an ACMECertificateSigner with *acme_service* set to the Let's Encrypt live service URL and other parameters passed through.

    :return: a new ACMECertificateSigner which will use Let's Encrypt.
    '''
    return await ACMECertificateSigner(*args, acme_service=ACMECertificateSigner.LetsEncryptService, docroots_dir=docroots_dir, default_docroot_dir=default_docroot_dir, data_store=data_store, **kwargs)

async def TestLetsEncryptCertificateSigner(*args, docroots_dir: Optional[str] = None, default_docroot_dir: Optional[str] = None, data_store: Optional[DataStore] = None, **kwargs) -> ACMECertificateSigner:
    '''Let's Encrypt staging (test) service ACMECertificateSigner factory function

    Creates an ACMECertificateSigner with *acme_service* set to the Let's Encrypt staging service URL and other parameters passed through.

    :return: a new ACMECertificateSigner which will use Let's Encrypt staging service.
    '''
    return await ACMECertificateSigner(*args, acme_service=ACMECertificateSigner.LetsEncryptStagingService, docroots_dir=docroots_dir, default_docroot_dir=default_docroot_dir, data_store=data_store, **kwargs)

