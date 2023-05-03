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

__byteval_re_str = r'(?:[0-9]{1,2}|[01][0-9][0-9]|2(?:[0-4][0-9]|5[0-5]))'
__ipv4_re_str = fr'{__byteval_re_str}(?:\.{__byteval_re_str}){{3}}'
__hexdigits_re_str = r'[0-9a-fA-F]{1,4}'
__ipv6_8_re_str = fr'(?:{__hexdigits_re_str}:){{7}}{__hexdigits_re_str}'
__ipv6_dcoln_0_re_str = fr'(?:{__hexdigits_re_str}:){{1,7}}:'
__ipv6_dcoln_1_re_str = fr'(?:{__hexdigits_re_str}:){{1,6}}:{__hexdigits_re_str}'
__ipv6_dcoln_2_re_str = fr'(?:{__hexdigits_re_str}:){{1,5}}(?::{__hexdigits_re_str}){{2}}'
__ipv6_dcoln_3_re_str = fr'(?:{__hexdigits_re_str}:){{1,4}}(?::{__hexdigits_re_str}){{3}}'
__ipv6_dcoln_4_re_str = fr'(?:{__hexdigits_re_str}:){{1,3}}(?::{__hexdigits_re_str}){{4}}'
__ipv6_dcoln_5_re_str = fr'(?:{__hexdigits_re_str}:){{1,2}}(?::{__hexdigits_re_str}){{5}}'
__ipv6_dcoln_6_re_str = fr'{__hexdigits_re_str}:(?::{__hexdigits_re_str}){{6}}'
__ipv6_dcoln_7_re_str = fr':(?::{__hexdigits_re_str}){{7}}'
__ipv6_site_hw_re_str = fr'fe80::(?:{__hexdigits_re_str}(?::{__hexdigits_re_str}){{0,3}})?%[0-9a-zA-Z]{{1,}}'
__ipv6_enc_ipv4_re_str = fr'::(?:ffff(?::0{{1,4}})?:)?{__ipv4_re_str}'
__ipv6_emb_ipv4_re_str = fr'(?:{__hexdigits_re_str}:){{1,4}}:{__ipv4_re_str}'
__ipv6_re_str = fr'(?:{__ipv6_8_re_str}|{__ipv6_dcoln_0_re_str}|{__ipv6_dcoln_1_re_str}|{__ipv6_dcoln_2_re_str}|{__ipv6_dcoln_3_re_str}|{__ipv6_dcoln_4_re_str}|{__ipv6_dcoln_5_re_str}|{__ipv6_dcoln_6_re_str}|{__ipv6_dcoln_7_re_str}|{__ipv6_site_hw_re_str}|{__ipv6_enc_ipv4_re_str}|{__ipv6_emb_ipv4_re_str})'
_ip_address_re = re.compile(fr'^(?:{__ipv6_re_str}|{__ipv4_re_str})$')

class ACMECertificateSigner(CertificateSigner):
    '''ACMECertificateSigner class
    '''

    LetsEncryptStagingService: str = 'https://acme-staging-v02.api.letsencrypt.org/directory'
    LetsEncryptService: str = 'https://acme-staging-v02.api.letsencrypt.org/directory'

    def __init__(self, *args, acme_service: Optional[str] = None, docroots_dir: Optional[str] = None, default_docroot_dir: Optional[str] = None, private_keys_dir: Optional[str] = None, data_store: Optional[DataStore] = None, **kwargs):
        errs=[]
        if acme_service is None:
            errs += ['acme_service is None']
        if docroots_dir is None:
            errs += ['docroots_dir is None']
        if default_docroot_dir is None:
            errs += ['default_docroot_dir is None']
        if private_keys_dir is None:
            errs += ['private_keys_dir is None']
        if len(errs) != 0:
            raise RuntimeError(f'{self.__class__.__name__} instantiated without needed parameters: {", ".join(errs)}')
        super().__init__(*args, data_store=data_store, **kwargs)
        self.__acme_service: str = acme_service
        self.__docroots: str = docroots_dir
        self.__default_docroot: str = default_docroot_dir
        self.__private_keys_dir: str = private_keys_dir

    async def asyncInit(self):
        '''Asynchronous object initialisation

        Derived classes should override this if they have object initialisation to do that requires async operations.

        This async method must return self.
        '''
        return self

    async def signCertificate(self, csr: str, *args, domain_name_alias: Optional[str] = None, **kwargs) -> Optional[str]:
        '''Sign a CSR in PEM format and return the public X509 Certificate in PEM format

        :param str csr: A CSR in PEM format.
        :param str domain_name_alias: Optional domain name to add to the subjectAltNames in the final certificate.

        :return: a public X509 certificate in PEM format.

        This will use the *csr* as a guideline for talking to the ACME server. The *domain_name_alias* will be used for the common name and first SAN, if the common name or SANs from the *csr* are not private IPs or localhost references then they will also be included.
        '''
        x509req: OpenSSL.crypto.X509Req = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr.encode('utf-8'))
        acmeReq: OpenSSL.crypto.X509Req = OpenSSL.crypto.X509Req()
        # build SAN list
        sans: List[bytes] = []
        if domain_name_alias is not None:
            sans += [domain_name_alias.encode('utf-8')]
        common_name = x509req.get_subject().commonName
        if isinstance(common_name,str):
            common_name = common_name.encode('utf-8')
        if common_name != b'localhost' and _ip_address_re.match(common_name.decode('utf-8')) is None:
            sans += [common_name]

        if len(sans) == 0:
            return None

        # Copy the CSR version number
        acmeReq.set_version(x509req.get_version())

        # Copy across the public key
        pkey = await self.__get_private_key_for_public_key(x509req.get_pubkey())
        if pkey is None:
            return None
        acmeReq.set_pubkey(pkey)

        # Set the common name to first SAN
        self.__copy_X509Name(acmeReq.get_subject(), x509req.get_subject()).commonName = sans[0]

        # Add extensions
        acmeReq.add_extensions([
            OpenSSL.crypto.X509Extension(b'basicConstraints', True, b'CA:FALSE'),
            OpenSSL.crypto.X509Extension(b'subjectAltName', False, b','.join([b'DNS:'+san for san in sans]))
            ])

        # Sign the new CSR
        acmeReq.sign(pkey, "sha256")

        # Send request to ACME server
        acmeReqBytes: bytes = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, acmeReq)
        async with aiofiles.tempfile.NamedTemporaryFile('wb', delete=False) as f:
            await f.write(acmeReqBytes)
        domain_docroot = os.path.join(self.__docroots, sans[0].decode('utf-8'))
        await aiofiles.os.makedirs(domain_docroot, mode=0o755, exist_ok=True)
        if not os.path.lexists(os.path.join(domain_docroot, '.well-known')):
            await aiofiles.os.symlink(os.path.join(self.__default_docroot, '.well-known'), os.path.join(domain_docroot, '.well-known'), target_is_directory=True)
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

    @staticmethod
    def __copy_X509Name(dest: OpenSSL.crypto.X509Name, src: OpenSSL.crypto.X509Name) -> OpenSSL.crypto.X509Name:
        dest.__init__(src)
        return dest

    async def __get_private_key_for_public_key(self, pubkey: OpenSSL.crypto.PKey) -> Optional[OpenSSL.crypto.PKey]:
        # search self.__private_keys_dir directory for the private key that matches the public key we have and return it
        if self.__private_keys_dir is None:
            LOGGER.debug('No private keys directory configured, unable to match private key to public key')
            return None
        LOGGER.debug(f'Looking for private key in {self.__private_keys_dir}')
        try:
            for entry in await aiofiles.os.scandir(self.__private_keys_dir):
                #LOGGER.debug(f'Checking directory entry {entry.name}')
                if entry.is_file():
                    try:
                        async with aiofiles.open(os.path.join(self.__private_keys_dir,entry.name), mode='rb') as keyfile:
                            pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, await keyfile.read())
                            #LOGGER.debug(f'Loaded PKey {pkey}')
                            if pkey.to_cryptography_key().public_key().public_bytes(cryptography_Encoding.PEM, cryptography_PublicFormat.SubjectPublicKeyInfo) == pubkey.to_cryptography_key().public_bytes(cryptography_Encoding.PEM, cryptography_PublicFormat.SubjectPublicKeyInfo):
                                LOGGER.debug(f'{entry.name} matches public key')
                                return pkey
                    except OpenSSL.crypto.Error:
                        LOGGER.debug(f'{entry.name} bad key file, skipping')
                        pass
                    except FileNotFoundError:
                        LOGGER.warn(f'{entry.name} disappeared while scanning private keys')
                        pass
                    except PermissionError:
                        LOGGER.warn(f'{entry.name} not accessible')
                        pass
        except FileNotFoundError as err:
            LOGGER.warn(f'Configured private keys directory ({self.__private_keys_dir}) not found: {err}')
            pass
        return None

async def _run_certbot_app(cmd_args: List[str]) -> Tuple[int, bytes]:
    LOGGER.debug('Executing: certbot %s', ' '.join(['\''+s+'\'' for s in cmd_args]))
    proc = await asyncio.create_subprocess_exec('certbot', *cmd_args, stdout=asyncio.subprocess.PIPE)
    await proc.wait()
    LOGGER.debug('Command exited with code %i', proc.returncode)
    data = await proc.stdout.read()
    return (proc.returncode, data)

async def LetsEncryptCertificateSigner(*args, docroots_dir: Optional[str] = None, default_docroot_dir: Optional[str] = None, private_keys_dir: Optional[str] = None, data_store: Optional[DataStore] = None, **kwargs) -> ACMECertificateSigner:
    return await ACMECertificateSigner(*args, acme_service=ACMECertificateSigner.LetsEncryptService, docroots_dir=docroots_dir, default_docroot_dir=default_docroot_dir, private_keys_dir=private_keys_dir, data_store=data_store, **kwargs)

async def TestLetsEncryptCertificateSigner(*args, docroots_dir: Optional[str] = None, default_docroot_dir: Optional[str] = None, private_keys_dir: Optional[str] = None, data_store: Optional[DataStore] = None, **kwargs) -> ACMECertificateSigner:
    return await ACMECertificateSigner(*args, acme_service=ACMECertificateSigner.LetsEncryptStagingService, docroots_dir=docroots_dir, default_docroot_dir=default_docroot_dir, private_keys_dir=private_keys_dir, data_store=data_store, **kwargs)

