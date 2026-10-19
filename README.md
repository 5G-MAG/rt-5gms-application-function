<p align="center">
  <img src=".github/banner.svg" width="100%" alt="Reference Tools · 5G Media Streaming (5GMS) Architecture: 5GMS Application Function (AF)">
</p>

<p align="center">
  The downlink 5GMS Application Function (AF): the network function that handles provisioning,
  configuration and reporting in 5G Media Streaming, as defined in ETSI TS 126.501.
</p>

<p align="center">
  <img alt="Status" src="https://img.shields.io/endpoint?url=https%3A%2F%2Fwww.5g-mag.com%2Fbadges%2Fstatus%2Frt-5gms-application-function.json">
  <a href="https://github.com/5G-MAG/rt-5gms-application-function/releases"><img alt="Version"
    src="https://img.shields.io/github/v/release/5G-MAG/rt-5gms-application-function?label=Version"></a>
  <a href="LICENSE"><img alt="License: 5G-MAG Public License v1.0"
    src="https://img.shields.io/badge/License-5G--MAG%20PL%20v1.0-blue"></a>
</p>

<p align="center">
  <a href="https://www.5g-mag.com/reference-tools/5gms/">Project page</a> &nbsp;&middot;&nbsp;
  <a href="https://github.com/5G-MAG/rt-5gms-application-function/issues">Issues</a> &nbsp;&middot;&nbsp;
  <a href="https://www.5g-mag.com/contributing">Contributing</a>
</p>

---

## At a glance

|  |  |
|---|---|
| **Implements** | ETSI TS 126.501 (no version stated in the repository) |
| **Part of** | [5G Media Streaming (5GMS) Architecture](https://www.5g-mag.com/reference-tools/5gms/), alongside [cmcd-toolkit](https://github.com/5G-MAG/cmcd-toolkit), [rt-5gc-service-consumers](https://github.com/5G-MAG/rt-5gc-service-consumers), [rt-5gms-application](https://github.com/5G-MAG/rt-5gms-application), [rt-5gms-application-provider](https://github.com/5G-MAG/rt-5gms-application-provider), [rt-5gms-application-server](https://github.com/5G-MAG/rt-5gms-application-server), [rt-5gms-common-android-library](https://github.com/5G-MAG/rt-5gms-common-android-library), [rt-5gms-examples](https://github.com/5G-MAG/rt-5gms-examples), [rt-5gms-media-session-handler](https://github.com/5G-MAG/rt-5gms-media-session-handler), [rt-5gms-media-stream-handler](https://github.com/5G-MAG/rt-5gms-media-stream-handler), [rt-cmmf-encoder](https://github.com/5G-MAG/rt-cmmf-encoder), [rt-media-origin](https://github.com/5G-MAG/rt-media-origin) |

## Introduction

This repository is the downlink 5GMS Application Function (5GMSd AF), a logical network function
built on the [Open5GS](https://open5gs.org/) framework. It covers the provisioning, configuration
and reporting aspects of the downlink 5G Media Streaming system, among others, and can be deployed
in the Trusted Data Network or in an External Data Network. A 5GMSd Application Provider provisions
services through its M1d interface and UE-based 5GMSd Clients use its M5d interface for
configuration and reporting, both RESTful and HTTP-based; the AF in turn configures a
[5GMS Application Server](https://github.com/5G-MAG/rt-5gms-application-server), which it needs in
order to run.

More information is on the [project page](https://www.5g-mag.com/reference-tools/5gms/).

What the implementation covers is described on the project's
[implementation page](https://www.5g-mag.com/reference-tools/5gms/implementation).

## Specification

The repository names ETSI TS 126.501 but no version. The OpenAPI bindings are generated at build
time from the 3GPP 5G APIs, by default at tag `TSG109-Rel17` (meson options `fiveg_api_approval`
and `fiveg_api_release` in `meson_options.txt`).

Clause-by-clause coverage, and what is still absent, is recorded on the project page rather than
here: <https://www.5g-mag.com/reference-tools/5gms/>

## Install dependencies

```bash
sudo apt update
sudo apt install bison build-essential cmake curl default-jdk flex git libbson-dev libcurl4-gnutls-dev libgcrypt-dev libgnutls28-dev libidn11-dev libmicrohttpd-dev libmongoc-dev libnghttp2-dev libpcre2-dev libsctp-dev libssl-dev libtalloc-dev libtins-dev libyaml-dev meson ninja-build python3-aiofiles python3-build python3-h11 python3-h2 python3-httpx python3-openssl python3-pip python3-setuptools python3-venv python3-wheel python3-yaml wget
```

## Downloading

Release tar files are on the [releases page](https://github.com/5G-MAG/rt-5gms-application-function/releases).
To get the source, clone the repository with its submodules:

```bash
cd ~
git clone --recurse-submodules https://github.com/5G-MAG/rt-5gms-application-function.git
cd rt-5gms-application-function
git submodule update
```

## Building

The build needs an Internet connection, because the API files are retrieved at build time.

```bash
cd ~/rt-5gms-application-function
meson build
ninja -C build
```

Errors during `meson build` are usually caused by missing dependencies, or by a network problem
while retrieving the API files and the `openapi-generator` JAR file. The details are in
`~/rt-5gms-application-function/build/meson-logs/meson-log.txt`; search for `generator-5gmsaf` to
find the start of the API fetch sequence.

## Installing

To install the Application Function as a system process:

```bash
cd ~/rt-5gms-application-function
sudo meson install --no-rebuild -C build

sudo mkdir -p /usr/local/var/log/open5gs/reports
sudo chmod -R 777 /usr/local/var/log/open5gs/reports
```

## Running

The Application Function needs a running
[5GMS Application Server](https://github.com/5G-MAG/rt-5gms-application-server), release v1.1.2 or
later. Install and start it first, following its
[instructions](https://github.com/5G-MAG/rt-5gms-application-server/#readme).

Start the Application Function with:

```bash
/usr/local/bin/open5gs-msafd
```

### Docker setup

A Docker Compose setup with the 5GMSd AF and the 5GMSd AS is in the
[rt-5gms-examples](https://github.com/5G-MAG/rt-5gms-examples/tree/development/5gms-docker-setup) project.

## Configuration

By default the Application Function reads the installed configuration file
`/usr/local/etc/open5gs/msaf.yaml`. To use another file, give it with the `-c` command line
parameter:

```bash
/usr/local/bin/open5gs-msafd -c alternate-msaf.yaml
```

In the source tree the example configuration is the template `src/5gmsaf/msaf.yaml.in`, not
`~/rt-5gms-application-function/src/5gmsaf/msaf.yaml`; the build writes `msaf.yaml` from it into
the build directory.

The options are described on the
[Configuring the Application Function](https://www.5g-mag.com/reference-tools/5gms/tutorials/application-function/configuration-5GMSAF)
page.

## Development

This project follows the
[Gitflow workflow](https://www.atlassian.com/git/tutorials/comparing-workflows/gitflow-workflow).
The `development` branch is the integration branch for new features, so switch to it before starting
work on a new feature.

### Testing

To set up a test environment without a full system installation, follow
[Testing as a Local User](https://www.5g-mag.com/reference-tools/5gms/tutorials/application-function/installation-local-user-5GMSAF).

The tests for each interface differ between versions of the 5GMSd Application Function. Use the
guide for the version under test:

| Interface | AF version | Guide |
|---|---|---|
| M1 | v1.2.x | [Testing the M1 Interface on v1.2.0](https://www.5g-mag.com/reference-tools/5gms/tutorials/application-function/testing-m1-v120) |
| M1 | v1.3.0 to v1.4.0 | [Testing the M1 Interface on v1.3.0](https://www.5g-mag.com/reference-tools/5gms/tutorials/application-function/testing-m1-v130) |
| M1 | v1.4.1 or later | [Testing the M1 Interface on v1.4.1](https://www.5g-mag.com/reference-tools/5gms/tutorials/application-function/testing-m1-v141) |
| M3 | v1.1.x | [Testing the M3 Interface on v1.1.0](https://www.5g-mag.com/reference-tools/5gms/tutorials/application-function/testing-m3-v110) |
| M3 | v1.2.0 or later | [Testing the M3 Interface on v1.2.0](https://www.5g-mag.com/reference-tools/5gms/tutorials/application-function/testing-m3-v120) |
| M5 | up to v1.1.x | [Testing: M5 Interface on v1.0.0](https://www.5g-mag.com/reference-tools/5gms/tutorials/application-function/testing-m5-v100) |
| M5 | v1.2.x | [Testing the M5 Interface on v1.2.0](https://www.5g-mag.com/reference-tools/5gms/tutorials/application-function/testing-m5-v120) |
| M5 | v1.3.0 or later | [Testing the M5 Interface on v1.3.0](https://www.5g-mag.com/reference-tools/5gms/tutorials/application-function/testing-m5-v130) |

How to use the Postman Collection is described in
[Testing with Postman](https://www.5g-mag.com/reference-tools/5gms/tutorials/testing-postman).

## Acknowledgements

The reference implementation of the Network Assistance and Dynamic Policies features was funded by
the UK Government through the [REASON](https://reason-open-networks.ac.uk/) project.

## Contributing

Contributions are welcome. How to raise an issue, fork the repository and open a pull request, and
the Contributor License Agreement required before code can be merged, are described at
<https://www.5g-mag.com/contributing>.

## License

Distributed under the 5G-MAG Public License v1.0. See [LICENSE](LICENSE). Third-party
software the Application Function uses is listed in [ATTRIBUTION_NOTICE](ATTRIBUTION_NOTICE).
