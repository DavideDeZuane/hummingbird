#!/bin/bash 

#sudo rm srv/log/charon.log
sudo rm srv/log/ikev2_decryption_table

./hummingbird

sleep 2

sudo python check.py
