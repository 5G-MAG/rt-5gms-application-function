# 5GMS Application Function

This repository holds the 5GMS Application Function implementation for the 5G-MAG Reference Tools.
Note that currently this implementation only supports downlink media streaming.

## Introduction

The 5GMS Application Function (AF) is a Network Function that forms part of the 5G Media Services framework as defined in ETSI TS 126.501.

### 5GMS Downlink Application Function
A 5GMSd Application Function (AF), which can be deployed in the 5G Core Network or in an External Data Network, is responsible for managing the 5GMSd System. The AF is a logical function which embodies the control plane aspects of the system, including provisioning, configuration, and reporting, among others. A 5GMSd Application Provider provisions 5GMS functions using a RESTful HTTP-based provisioning interface at reference point M1d. Another RESTful HTTP-based configuration and reporting interface is exposed to UE-based 5GMSd Clients at reference point M5d.

#### Specifications

A list of specification related to this repository is available in the [Standards Wiki](https://github.com/5G-MAG/Standards/wiki/5G-Downlink-Media-Streaming-Architecture-(5GMSd):-Relevant-Specifications).

#### About the implementation

This AF uses the [Open5GS](https://open5gs.org/) framework to implement the network function.

A list of currently supported features is available [here](https://github.com/5G-MAG/rt-5gms-application-function/wiki/Feature-Matrix).

## Install dependencies

```bash
sudo apt install git python3-pip python3-venv python3-setuptools python3-wheel ninja-build build-essential flex bison git libsctp-dev libgnutls28-dev libgcrypt-dev libssl-dev libidn11-dev libmongoc-dev libbson-dev libyaml-dev libnghttp2-dev libmicrohttpd-dev libcurl4-gnutls-dev libnghttp2-dev libtins-dev libtalloc-dev meson curl wget default-jdk cmake
python3 -m pip install build pyOpenSSL
```

## Downloading

Release tar files can be downloaded from <https://github.com/5G-MAG/rt-5gms-application-function/releases>.

The source can be obtained by cloning the github repository.

For example to download the latest release you can use:

```bash
cd ~
git clone --recurse-submodules https://github.com/5G-MAG/rt-5gms-application-function.git
cd rt-5gms-application-function
git submodule update
```

## Building

The build process requires a working Internet connection as the API files are retrieved at build time.

To build the 5GMS Application Function from the source:

```bash
cd ~/rt-5gms-application-function
meson build
ninja -C build
```

**Note:** Errors during the `meson build` command are often caused by missing dependancies or a network issue while trying to retrieve the API files and `openapi-generator` JAR file. See the `~/rt-5gms-application-function/build/meson-logs/meson-log.txt` log file for the errors in greater detail. Search for `generator-5gmsaf` to find the start of the API fetch sequence.

## Installing

To install the built Application Function as a system process:

```bash
cd ~/rt-5gms-application-function/build
sudo meson install --no-rebuild
```

## Running

The Application Function requires a [5GMS Application Server](https://github.com/5G-MAG/rt-5gms-application-server) (release v1.1.2 or above) to be running. Please follow the [instructions](https://github.com/5G-MAG/rt-5gms-application-server/#readme) for installing and running the 5GMS Application Server before starting the Application Function.

The Application Function can be executed with the command:

```bash
/usr/local/bin/open5gs-msafd
```

This uses the installed configuration file at `/usr/local/etc/open5gs/msaf.yaml`. You can use the `-c` command line parameter to
specify an alternative configuration file. For example:

```bash
/usr/local/bin/open5gs-msafd -c alternate-msaf.yaml
```

The source example configuration file can be found in `~/rt-5gms-application-function/src/5gmsaf/msaf.yaml`.

Also see the [Configuring the Application Function](https://github.com/5G-MAG/rt-5gms-application-function/wiki/Configuring-the-Application-Function) wiki page for details on configuration.

## Testing

See the section on [Testing](https://github.com/5G-MAG/rt-5gms-application-function/wiki/Developing-and-Contributing#testing) in the wiki.

## Development

This project follows
the [Gitflow workflow](https://www.atlassian.com/git/tutorials/comparing-workflows/gitflow-workflow). The
`development` branch of this project serves as an integration branch for new features. Consequently, please make sure to
switch to the `development` branch before starting the implementation of a new feature.

## Support

The reference implementation of the Network Assistance and Dynamic Policies features was funded by the UK Government through the [REASON](https://reason-open-networks.ac.uk/) project.
