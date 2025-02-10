# ---------------------------------------------------------
# BASE IMAGE
# ---------------------------------------------------------
FROM ubuntu:latest

# ---------------------------------------------------------
# INSTALLING DEPENDENCIES
# ---------------------------------------------------------
# Update packages and install necessary build dependencies
ENV VERSION=6.0.0
RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y      \
    libgmp-dev              \
    libssl-dev              \    
    libcurl4-openssl-dev    \
    libsystemd-dev          \
    make                    \
    gcc                     \
    g++                     \
    flex                    \
    wget                    \
    bzip2                   \ 
    bison                   \
    libcap-ng-dev           \
    iproute2                \
    iptables                \
    autoconf                \
    automake                \
    libtool                 \
    pkg-config              

# ---------------------------------------------------------
# CLEAN UP PACKAGE LISTS
# ---------------------------------------------------------
# Remove cached package lists to reduce image size
RUN rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------
# INSTALLING STRONGSWAN
# ---------------------------------------------------------
# Download and extract StrongSwan source code next configure and compile StrongSwan
RUN wget https://download.strongswan.org/strongswan-${VERSION}.tar.bz2 && tar xjf strongswan-${VERSION}.tar.bz2 
WORKDIR /strongswan-${VERSION}
RUN ./configure --prefix=/usr --sysconfdir=/etc \
	--with-systemdsystemunitdir                 \
	--enable-save-keys                          \
	--enable-charon                             \
	--enable-systemd                            \
	--enable-ikev2                              \
	--enable-vici                               \
	--enable-swanctl                            \
    --enable-nonce                              \
	--enable-random                             \
	--enable-drbg                               \   
	--enable-openssl                            \    
	--enable-curl                               \
	--enable-pem                                \
	--enable-x509                               \
	--enable-constraints                        \
   	--enable-pubkey                             \   
	--enable-socket-default                     \
	--enable-kernel-netlink                     \
	--enable-resolve        
RUN make && make install

# ---------------------------------------------------------
# CLEAN UP THE SYSTEM
# ---------------------------------------------------------
WORKDIR /
RUN rm -rf strongswan-${VERSION} strongswan-${VERSION}.tar.bz2 

# ---------------------------------------------------------
# EXPOSE PORTS
# ---------------------------------------------------------
EXPOSE 500/udp 4500/udp

# ---------------------------------------------------------
# SECURITY CONSIDERATIONS
# ---------------------------------------------------------
# RUN rm -rf /var/lib/apt/lists/*
# questo comando serve per pulire la cache elimina tutti gli elenchi di pacchetti scaricati 
# qualsiasi altro install fallirà poichè la lista dei pacchetti disponibile non esiste più per fare in modo di aggiungerne altro occorre fare l'update
# Optionally, remove package manager for added security (if not needed)
# RUN apt-get remove -y --purge apt dpkg && apt-get autoremove -y
# un altra pratica di sicurezza che può tornare utile è bloccare il package manager in modo tale che questo non sia più disponibile nel container
#RUN apt remove -y apt oppure RUN apt-get purge -y apt dpkg
