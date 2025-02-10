#!/bin/bash

exec /usr/libexec/ipsec/charon &
sleep 3
swanctl --load-all
CHARON_PID=$!

tail -f /var/log/charon.log
#wait $CHARON_PID
