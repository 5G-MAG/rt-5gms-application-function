# 5G-MAG Reference Tools: 5GMS Application Function

This repository holds the 5GMS Application Function implementation for the 5G-MAG Reference Tools.

## Introduction

The 5GMS application function (AF) is a Network Function that forms part of the 5G Media Streaming framework as defined
in ETSI TS 126.501.

This AF uses the [Open5GS](https://open5gs.org/) framework to implement the network function.

## Specifications

A list of specification related to this repository is available [here](https://github.com/5G-MAG/Standards/blob/main/Specifications_5GMS.md).

## Install dependencies

```bash
sudo apt install git python3-pip python3-venv python3-setuptools python3-wheel ninja-build build-essential flex bison git libsctp-dev libgnutls28-dev libgcrypt-dev libssl-dev libidn11-dev libmongoc-dev libbson-dev libyaml-dev libnghttp2-dev libmicrohttpd-dev libcurl4-gnutls-dev libnghttp2-dev libtins-dev libtalloc-dev meson curl
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

To build the 5GMS Application Function from the source:

```bash
cd ~/rt-5gms-application-function
meson build --prefix=`pwd`/install
ninja -C build
```

## Installing

To install the built Application Function:

```bash
cd ~/rt-5gms-application-function/build
ninja install
```

## Running

The Application Function can be executed with the command:

```bash
cd ~/rt-5gms-application-function/src/5gmsaf
../../install/bin/open5gs-msafd -c msaf.yaml
```

Use `-c` to specify a configuration file. The example configuration file can
be `rt-5gms-application-function/src/5gmsaf/msaf.yaml`.

## Testing with the example configuration

If you started the 5GMS Application Function with the example configuration (`msaf.yaml`), you can test it by retrieving
http://127.0.0.22:7777/3gpp-m5/v2/service-access-information/d54a1fcc-d411-4e32-807b-2c60dbaeaf5f.

For example:

```bash
curl -v http://127.0.0.22:7777/3gpp-m5/v2/service-access-information/d54a1fcc-d411-4e32-807b-2c60dbaeaf5f
```

...would receive a response like:

```
< HTTP/1.1 200 OK
< Date: Fri, 28 Oct 2022 16:26:09 GMT
< Connection: close
< Content-Type: application/json
< Content-Length: 278
< 
{
	"provisioningSessionId":	"d54a1fcc-d411-4e32-807b-2c60dbaeaf5f",
	"provisioningSessionType":	"DOWNLINK",
	"streamingAccess":	{
		"mediaPlayerEntry":	"https://localhost/m4d/provisioning-session-d54a1fcc-d411-4e32-807b-2c60dbaeaf5f/BigBuckBunny_4s_onDemand_2014_05_09.mpd"
	}
}
```

The not found response can be tested using a different provisioningSessionId string to the value in the
provisioningSessionId key in the configuration YAML file. For example:

```bash
curl -v http://127.0.0.22:7777/3gpp-m5/v2/service-access-information/does_not_exist
```

...which would receive a response like:

```
< HTTP/1.1 404 Not Found
< Date: Fri, 28 Oct 2022 16:26:28 GMT
< Connection: close
< Content-Type: application/problem+json
< Content-Length: 218
< 
{
	"type":	"/3gpp-m5/v2",
	"title":	"Service Access Information not found",
	"status":	404,
	"detail":	"Service Access Information does_not_exist not found.",
	"instance":	"/service-access-information/does_not_exist"
}
```

## Development

This project follows
the [Gitflow workflow](https://www.atlassian.com/git/tutorials/comparing-workflows/gitflow-workflow). The
`development` branch of this project serves as an integration branch for new features. Consequently, please make sure to
switch to the `development` branch before starting the implementation of a new feature.
