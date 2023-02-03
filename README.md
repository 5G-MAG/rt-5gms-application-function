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
meson build
ninja -C build
```

## Installing

To install the built Application Function:

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

## Testing with the example configuration

### Testing the M5 interface

If you started the 5GMS Application Function with the default configuration (`msaf.yaml`), you can test it by retrieving
`http://localhost:7778/3gpp-m5/v2/service-access-information/{provisioning-session-id}`. Where `{provisioning-session-id}`
is the provisioning session ID reported by the 5GMS Application Function in its log.

For example:

```bash
curl -v http://localhost:7778/3gpp-m5/v2/service-access-information/0f9e5e28-a3c5-41ed-8dd9-432c02738477
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
	"provisioningSessionId":	"0f9e5e28-a3c5-41ed-8dd9-432c02738477",
	"provisioningSessionType":	"DOWNLINK",
	"streamingAccess":	{
		"mediaPlayerEntry":	"http://localhost/m4d/provisioning-session-0f9e5e28-a3c5-41ed-8dd9-432c02738477/BigBuckBunny_4s_onDemand_2014_05_09.mpd"
	}
}
```

The not found response can be tested using a different provisioningSessionId string to the value in the
provisioningSessionId key in the configuration YAML file. For example:

```bash
curl -v http://localhost:7778/3gpp-m5/v2/service-access-information/does_not_exist
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

### Testing the M3 interface

To see the M3 operations taking place you will need to increase logging level to `debug` by setting the `logging.level` property in the `msaf.yaml` file. For example:

```yaml
logging:
    level: debug
    domain: msaf
```

With the logging at `debug` level, the Application Function will report significant communications with the Application Server in
its log output. For example:

```
Open5GS daemon v2.4.11-31-gf1c0b6d+
02/03 13:17:08.426: [app] INFO: Configuration: '/usr/local/etc/open5gs/msaf.yaml' (../subprojects/open5gs/lib/app/ogs-init.c:126)
02/03 13:17:08.427: [sbi] INFO: mhd_server() [0.0.0.0]:7778 (../subprojects/open5gs/lib/sbi/mhd-server.c:279)
02/03 13:17:08.427: [msaf] DEBUG: msaf_state_initial(): INIT (../src/5gmsaf/msaf-sm.c:20)
02/03 13:17:08.427: [msaf] DEBUG: msaf_state_functional(): ENTRY (../src/5gmsaf/msaf-sm.c:47)
02/03 13:17:08.427: [msaf] INFO: [0f9e57de-a3c5-41ed-8dd9-432c02738477] MSAF Running (../src/5gmsaf/msaf-sm.c:53)
02/03 13:17:08.427: [msaf] DEBUG: BigBuckBunny_4s_onDemand_2014_05_09.mpd matches the regular expression (../src/5gmsaf/provisioning-session.c:592)
02/03 13:17:08.427: [msaf] DEBUG: Distribution URL: http://msaf01.example.net/m4d/ (../src/5gmsaf/provisioning-session.c:540)
02/03 13:17:08.427: [app] INFO: 5GMSAF initialize...done (../src/5gmsaf/app.c:24)
02/03 13:17:08.427: [msaf] INFO: Provisioning session = 0f9e5e28-a3c5-41ed-8dd9-432c02738477 (../src/5gmsaf/msaf-sm.c:57)
02/03 13:17:08.473: [msaf] DEBUG: msaf_state_functional(): OGS_EVENT_NAME_SBI_CLIENT (../src/5gmsaf/msaf-sm.c:47)
02/03 13:17:08.473: [msaf] DEBUG: [certificates] Method [GET] with Response [200] received (../src/5gmsaf/msaf-sm.c:1111)
02/03 13:17:08.473: [msaf] DEBUG: Adding certificate [8578424e-9cae-41ed-9e7a-f3a3ae58dd9b:dn01] to Current certificates (../src/5gmsaf/msaf-sm.c:1139)
02/03 13:17:08.473: [msaf] DEBUG: Adding certificate [30d46048-a3c4-41ed-86b2-7b1b5377721f:dn01] to Current certificates (../src/5gmsaf/msaf-sm.c:1139)
02/03 13:17:08.473: [msaf] DEBUG: Adding certificate [bf5fc424-a3c4-41ed-be95-b7864fdc6a53:dn01] to Current certificates (../src/5gmsaf/msaf-sm.c:1139)
02/03 13:17:08.474: [msaf] DEBUG: msaf_state_functional(): OGS_EVENT_NAME_SBI_CLIENT (../src/5gmsaf/msaf-sm.c:47)
02/03 13:17:08.474: [msaf] DEBUG: [content-hosting-configurations] Method [GET] with Response [200] for Content Hosting Configuration operation [(null)] (../src/5gmsaf/msaf-sm.c:888)
02/03 13:17:08.474: [msaf] DEBUG: Adding [8578424e-9cae-41ed-9e7a-f3a3ae58dd9b] to the current Content Hosting Configuration list (../src/5gmsaf/msaf-sm.c:913)
02/03 13:17:08.474: [msaf] DEBUG: Adding [30d46048-a3c4-41ed-86b2-7b1b5377721f] to the current Content Hosting Configuration list (../src/5gmsaf/msaf-sm.c:913)
02/03 13:17:08.474: [msaf] DEBUG: Adding [bf5fc424-a3c4-41ed-be95-b7864fdc6a53] to the current Content Hosting Configuration list (../src/5gmsaf/msaf-sm.c:913)
02/03 13:17:08.474: [msaf] DEBUG: M3 client: Sending POST method to Application Server [localhost] for Content Hosting Configuration:  [0f9e5e28-a3c5-41ed-8dd9-432c02738477] (../src/5gmsaf/application-server-context.c:233)
02/03 13:17:08.517: [msaf] DEBUG: msaf_state_functional(): OGS_EVENT_NAME_SBI_CLIENT (../src/5gmsaf/msaf-sm.c:47)
02/03 13:17:08.517: [msaf] DEBUG: [content-hosting-configurations] Method [POST] with Response [201] recieved for Content Hosting Configuration [0f9e5e28-a3c5-41ed-8dd9-432c02738477] (../src/5gmsaf/msaf-sm.c:736)
02/03 13:17:08.517: [msaf] DEBUG: Removing 0f9e5e28-a3c5-41ed-8dd9-432c02738477 from upload_content_hosting_configurations (../src/5gmsaf/msaf-sm.c:745)
02/03 13:17:08.517: [msaf] DEBUG: Adding 0f9e5e28-a3c5-41ed-8dd9-432c02738477 to current_content_hosting_configurations (../src/5gmsaf/msaf-sm.c:747)
```

The above log shows the Application Function learning that the Application Server already knows about 3 certificates (`8578424e-9cae-41ed-9e7a-f3a3ae58dd9b:dn01`, `30d46048-a3c4-41ed-86b2-7b1b5377721f:dn01` and `bf5fc424-a3c4-41ed-be95-b7864fdc6a53:dn01`), it then learns that it has 3 content-hosting-configurations (`8578424e-9cae-41ed-9e7a-f3a3ae58dd9b`, `30d46048-a3c4-41ed-86b2-7b1b5377721f` and `bf5fc424-a3c4-41ed-be95-b7864fdc6a53`), and finally it uploads the new content hosting configuration to the AS (`0f9e5e28-a3c5-41ed-8dd9-432c02738477`).

The log of the Application Server can also be checked for communications with the AF:

```
INFO:rt-5gms-as:Getting list of certificates...
[2023-02-03 13:17:08 +0000] [28235] [INFO] 127.0.0.1:49538 - - [03/Feb/2023:13:17:08 +0000] "GET /3gpp-m3/v1/certificates 2" 200 208 "-" "-"
INFO:rt-5gms-as:Getting list of content hosting configurations...
[2023-02-03 13:17:08 +0000] [28235] [INFO] 127.0.0.1:49538 - - [03/Feb/2023:13:17:08 +0000] "GET /3gpp-m3/v1/content-hosting-configurations 2" 200 247 "-" "-"
INFO:rt-5gms-as:Adding content hosting configuration 0f9e5e28-a3c5-41ed-8dd9-432c02738477...
INFO:rt-5gms-as:Reloading proxy daemon...
[2023-02-03 13:17:08 +0000] [28235] [INFO] 127.0.0.1:49546 - - [03/Feb/2023:13:17:08 +0000] "POST /3gpp-m3/v1/content-hosting-configurations/0f9e5e28-a3c5-41ed-8dd9-432c02738477 2" 201 0 "-" "-"
```

These log lines from the Application Server can be seen to match the requests in the Application Function log.

## Development

This project follows
the [Gitflow workflow](https://www.atlassian.com/git/tutorials/comparing-workflows/gitflow-workflow). The
`development` branch of this project serves as an integration branch for new features. Consequently, please make sure to
switch to the `development` branch before starting the implementation of a new feature.
