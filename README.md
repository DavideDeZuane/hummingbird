# hummingbird
Implementation of proposed RFC 7815 Minimal IKE from scratch.
This is an academic project.

## Why?

IKEv2 is a general purpose protocol and in the years a lof of funcitonalities are been added to this protocol.
This implies for the software that want to be fully compliant to include a lot of RFC, this require a lot of code. But in most cases that functionalities will no te be used,

The implementation of IKEv2 strongswan in the init exchange has different optional payload someone can be removed in the configuration but othern cannot be removed.
The most significant are the payload that deal with nat detection that there are the most significant in terms of byte sended

|             Campo                | Dimensione (Byte) |    Opzione Strongswan      | Value |    RFC   |
|:---------------------------------|:-----------------:|---------------------------:|-------|:--------:|
| VENDOR\_ID                       |         20        |           send\_vendor\_id |    no |     7296 |
| MULTIPLE\_AUTH\_SUPPORTED        |         8         |   multiple\_authentication |    no |     4739 |
| SIGNATURE\_HASH\_ALGORITHMS      |         16        |  signature\_authentication |    no |     7427 |
| REDIRECT\_SUPPORTED              |         8         |            flow\_redirects |    no |     5685 |
| NAT\_DETECTION\_SOURCE\_IP       |         28        |                          - |     - |     4306 |
| NAT\_DETECTION\_DESTIONATION\_IP |         28        |                          - |     - |     4306 |
|                                  |                   |                            |       |          |
|        TOTALE OVERHEAD           |        108        |                            |       |          |

## Structure

The source code of the implementation is divided in `include` and`src` directory. 
Because the implementation provides only initiator role to correctly test if it is woking we have created a server running strongswan. This istance is running inside a docker container so anyone can test, the configuration can be found inside the `srv` directory.

```
.
├── README.md
├── Makefile
├── conf.ini
├── include
├── src
├── srv
└── start.sh
```

So if you want to test the implementation, please before remember to start the container with the following command:

```
sudo docker-compose -f srv/docker-compose.yml up -d
```

