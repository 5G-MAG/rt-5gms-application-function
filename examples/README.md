# 5G-MAG Reference Tools: 5GMS Application Function Example Configurations

This directory contains examples of configuration files for the 5GMS Application Function.

## `Certificates.json`

This file contains a mapping from certificate ID to certificate filename. The
certificate IDs in this file are used to find the matching certificate file
(containing a public certificate, private key and any intermediate CA
certificates) when referenced from a ContentHostingConfiguration file.

The `subprojects/rt-common-shared/5gms/scripts/make_self_signed_certs.py` script can be used, passing a ContentHostingConfiguration and this `Certificates.json` file as parameters, to create suitable self-signed certificate files for testing purposes.

For example:
```bash
cd ~/rt-5gms-application-function
subprojects/rt-common-shared/5gms/scripts/make_self_signed_certs.py examples/ContentHostingConfiguration_Big-Buck-Bunny_pull-ingest_https.json examples/Certificates.json
```

## `ContentHostingConfiguration_Big-Buck-Bunny_pull-ingest.json`

This file is used as a content hosting configuration for the rt-5gms-application-function.

It contains a ContentHostingConfiguration, based on 3GPP TS 26.512 Release 17.3.0, which points to a media origin host, suitable for use with pull-ingest, which holds the Big Buck Bunny short animated film.

The distribution side of the configurations tells the rt-5gms-application-function to configure a 5GMS Application Server to reverse proxy the media on its localhost (127.0.0.1) loopback interface.

## `ContentHostingConfiguration_Big-Buck-Bunny_pull-ingest_http_and_https.json`

This file is an alternative to `ContentHostingConfiguration_Big-Buck-Bunny_pull-ingest.json` (see above) and can be used along with the `Certificates.json` file to configure a rt-5gms-application-function to provision a 5GMS Application Server which will provide both HTTP and HTTPS distribution points.

## `ContentHostingConfiguration_Big-Buck-Bunny_pull-ingest_https.json`

This file is an alternative to `ContentHostingConfiguration_Big-Buck-Bunny_pull-ingest.json` (see above) and can be used along with the `Certificates.json` file to run a rt-5gms-application-function to provision a 5GMS Application Server which will provide an HTTP distribution point.