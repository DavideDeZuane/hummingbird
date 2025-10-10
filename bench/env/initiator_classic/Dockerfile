# ---------------------------------------------------------
# BASE IMAGE
# ---------------------------------------------------------


    FROM archlinux:latest

# ---------------------------------------------------------
# ENVIRONMENT
# ---------------------------------------------------------
ENV VERSION=6.0.1

# ---------------------------------------------------------
# INSTALLING DEPENDENCIES
# ---------------------------------------------------------
# Aggiorna i pacchetti e installa le dipendenze necessarie
RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm \
        zsh \
        gmp \
        openssl \
        curl \
        systemd-libs \
        make \
        gcc \
        flex \
        bison \
        bzip2 \
        libcap-ng \
        iproute2 \
        iptables \
        autoconf \
        automake \
        m4 \
        gperf \
        perl \
        libtool \
        base-devel \
        pkgconf \
        wget

# ---------------------------------------------------------
# OPTIONAL: Set default shell to zsh
# ---------------------------------------------------------
SHELL ["/usr/bin/zsh", "-c"]

    # ---------------------------------------------------------
    # INSTALLING STRONGSWAN
    # ---------------------------------------------------------
    # Download and extract StrongSwan source code next configure and compile StrongSwan
    # invece che installarlo basta copiare la directory 
    
    # RUN wget https://download.strongswan.org/strongswan-${VERSION}.tar.bz2 && tar xjf strongswan-${VERSION}.tar.bz2 
    
    WORKDIR /strongswan
    COPY ModdedStrongswan /strongswan


    RUN autoreconf  -i
    RUN ./configure --prefix=/usr --sysconfdir=/etc 	\
        --with-systemdsystemunitdir                 	\
        --enable-save-keys                          	\
        --enable-ml                                     \
        --enable-charon                             	\
        --enable-systemd                            	\
        --enable-ikev2                              	\
        --enable-vici                               	\
        --enable-swanctl                            	\
        --enable-nonce                              	\
        --enable-random                             	\
        --enable-drbg                               	\  	 
        --enable-openssl                            	\  	  
        --enable-curl                               	\
        --enable-pem                                	\
        --enable-x509                               	\
        --enable-constraints                        	\
           --enable-pubkey                             	\  	 
        --enable-socket-default                     	\
        --enable-kernel-netlink                     	\
        --enable-resolve        

    SHELL ["/bin/zsh", "-c"]

    RUN make && make install

    
    # ---------------------------------------------------------
    # CLEAN UP THE SYSTEM
    # ---------------------------------------------------------
    WORKDIR /
    RUN rm -rf strongswan 
    
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
    
