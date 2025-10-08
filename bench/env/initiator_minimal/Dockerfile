FROM archlinux:latest

WORKDIR /app

RUN pacman -Syu --noconfirm \
    base-devel \
    neovim \
    gcc \
    make \
    openssl \
    libinih

COPY hummingbird .

# Compila il progetto
RUN make
CMD tail -f /dev/null
