# hummingbird
Implementation of proposed RFC 7815 Minimal IKE from scratch.
This is an academic project.

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
