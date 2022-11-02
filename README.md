# 5G-MAG Reference Tools: 5GMS Application Function

This repository holds the 5GMS Application Function implementation for the
5G-MAG Reference Tools.

## Introduction

The 5GMS application function (AF) is a Network Function that forms part of the
5G Media Services framework as defined in ETSI TS 126.501.

This AF uses the [Open5GS](https://open5gs.org/) framework to implement the
network function.

## Specifications

* [ETSI TS 126 501](https://portal.etsi.org/webapp/workprogram/Report_WorkItem.asp?WKI_ID=66447) - 5G Media Streaming (5GMS): General description and architecture (3GPP TS 26.501 version 17.2.0 Release 17)
* [ETSI TS 126 512](https://portal.etsi.org/webapp/workprogram/Report_WorkItem.asp?WKI_ID=66919) - 5G Media Streaming (5GMS): Protocols (3GPP TS 26.512 version 17.1.2 Release 17)

## Downloading

Release sdist tar files can be downloaded from _TBC_.

The source can be obtained by cloning the github repository.
```
cd ~
git clone --recurse-submodules https://github.com/5G-MAG/rt-5gms-application-function.git
cd rt-5gms-application-function
git submodule update
```

## Build the 5GMS Application Function

To build the 5GMS Application Function from the source: 

``` 
cd ~/rt-5gms-application-function
meson build --prefix=`pwd`/install
ninja -C build
```

## Installing

To install the built Application Function:
```
cd ~/rt-5gms-application-function/build
ninja install
```

## Running

The Application Function can be executed with the command:
```
cd ~/rt-5gms-application-function/src/5gmsaf
../../install/bin/open5gs-msafd -c msaf.yaml
```

## Testing with the example configuration

If you started the 5GMS Application Function with the example configuration, you can test it by retrieving { http://127.0.0.22:7777/3gpp-m5/v2/service-access-information/d54a1fcc-d411-4e32-807b-2c60dbaeaf5f }.

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

The not found response can be tested using a different provisioningSessionId string to the value in the provisioningSessionId key in the configuration YAML file. For example
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

_TODO_
