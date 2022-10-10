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
git clone --recurse-submodules https://github.com/5G-MAG/rt-5gms-application-function.git
```

## Build the 5GMS Application Function

To build the 5GMS Application Function from the source: 

``` 
rt-5gms-application-function$ meson build --prefix=`pwd`/install
rt-5gms-application-function$ ninja -C build
```

## Installing

To install the built Application Function:
```
rt-5gms-application-function$ cd build
rt-5gms-application-function/build$ ninja install
```

## Running

The Application Function can be executed with the command:
```
rt-5gms-application-function/src/5gmsaf$ ../../install/bin/open5gs-msafd -c msaf.yaml
```

## Development

_TODO_
