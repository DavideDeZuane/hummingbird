# hummingbird
Implementation of proposed RFC 7815 Minimal IKE from scratch.
This is an academic project.

## Why?

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

The source code of the implementation is inside the `src` directory. During the implementation we use a strongswan server to check if the generated messaggess are corret, the configuration of strongswan can be found inside the directory `srv`. It is a version of strongswan dockerized.

```
.
├── conf.ini
├── Makefile
├── README.md
├── src
├── srv
└── start.sh
```
