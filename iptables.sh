#!/bin/bash
# 1) Regola che verifica se l'IP è già nella lista (ovvero se è il primo pacchetto)
sudo iptables -A INPUT -i lo -p udp --dport 500 -m recent --name isakmp --rcheck --hitcount 1 -j DROP

# 2) Regola che aggiunge l'IP alla lista (viene sempre aggiunto)
sudo iptables -A INPUT -i lo -p udp --dport 500 -m recent --name isakmp --set -j ACCEPT

