#!/usr/bin/python3
#==============================================================================
# 5G-MAG Reference Tools: M1 Client Certificate Signing
#==============================================================================
#
# File: rt_m1_client/certificates/__init__.py
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
# M1 Session Certificate Signing Module
# =====================================
#
# This module defines classes used by the M1 session classes to sign certificates
#
# CertificateSigner - Base class for certificate signing.
#
# LocalCACertificateSigner - A CertificateSigner that uses a locally generated CA to generate X509 certificates from CSRs
# ACMECertificateSigner - A CertificateSigner which uses an ACME service to sign the certificates
# LetsEncryptCertificateSigner - An ACMECertificateSigner preconfigured for Let's Encrypt service.
# TestLetsEncryptCertificateSigner - An ACMECertificateSigner preconfigured for Let's Encrypt staging service.
#
# DefaultCertificateSigner - The default CertificateSigner used by the M1Session class, presently LocalCACertificateSigner.
#
'''
======================================================
5G-MAG Reference Tools: M1 Session Certificate Signing
======================================================

This module defines some classes that can be used by the `M1Session` class to provide certificate signing services.

'''

from .base import CertificateSigner
from .local_ca_cert_signer import LocalCACertificateSigner
from .acme_cert_signer import ACMECertificateSigner, LetsEncryptCertificateSigner, TestLetsEncryptCertificateSigner

DefaultCertificateSigner = LocalCACertificateSigner

__all__ = [
        "CertificateSigner",
        "LocalCACertificateSigner",
        "ACMECertificateSigner",
        "LetsEncryptCertificateSigner",
        "TestLetsEncryptCertificateSigner",
        "DefaultCertificateSigner",
        ]
