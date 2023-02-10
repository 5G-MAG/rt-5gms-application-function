# 5G-MAG Reference Tools: 5GMS Application Function

This repository holds the 5GMS Application Function implementation for the 5G-MAG Reference Tools.

## Introduction

The 5GMS application function (AF) is a Network Function that forms part of the 5G Media Streaming framework as defined
in ETSI TS 126.501.

This AF uses the [Open5GS](https://open5gs.org/) framework to implement the network function.

## Specifications

* [ETSI TS 126 501](https://portal.etsi.org/webapp/workprogram/Report_WorkItem.asp?WKI_ID=67203) - 5G Media Streaming (
  5GMS): General description and architecture (3GPP TS 26.501 version 17.3.0 Release 17)
* [ETSI TS 126 512](https://portal.etsi.org/webapp/workprogram/Report_WorkItem.asp?WKI_ID=67679) - 5G Media Streaming (
  5GMS): Protocols (3GPP TS 26.512 version 17.3.0 Release 17)

## Install dependencies

```bash
sudo apt install git python3-pip python3-venv python3-setuptools python3-wheel ninja-build build-essential flex bison git libsctp-dev libgnutls28-dev libgcrypt-dev libssl-dev libidn11-dev libmongoc-dev libbson-dev libyaml-dev libnghttp2-dev libmicrohttpd-dev libcurl4-gnutls-dev libnghttp2-dev libtins-dev libtalloc-dev meson curl wget default-jdk
python3 -m pip install build
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

## Build the 5GMS Application Function

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

The Application Function requires a [5GMS Application Server](https://github.com/5G-MAG/rt-5gms-application-server) (release v1.1.0 or above) to be running. Please follow the [instructions](https://github.com/5G-MAG/rt-5gms-application-server/tree/development#readme) for installing and running the 5GMS Application Server before starting the Application Function.

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

## Testing

See the section on [Testing](https://github.com/5G-MAG/rt-5gms-application-function/wiki/Developing-and-Contributing#testing) in the wiki.

## Development

This project follows
the [Gitflow workflow](https://www.atlassian.com/git/tutorials/comparing-workflows/gitflow-workflow). The
`development` branch of this project serves as an integration branch for new features. Consequently, please make sure to
switch to the `development` branch before starting the implementation of a new feature.
