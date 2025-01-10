# Nome del target eseguibile
TARGET = hummingbird

SRCS = src/main.c \
       src/config/config.c \
	   src/log/log.c \
	   src/network/network.c\
	   src/socket/peer.c

LIBS = -linih -lssl -lcrypto
CFLAGS = -Wall -I./src/config -I./src/log -I./src/network -I./src/socket
LDFLAGS = $(LIBS)

# Regola principale per costruire il target, diciamo quali sono tutti i file sorgenti di cui ha bisogno
# CC è il comando del compilatore
# o indica il nome dell'output $@ è una variabile automatica in Makefile che rappresenta il target della regola corrente, in questo caso, $(TARGET), quindi il nome dell'eseguibile.
# $^ Rappresenta tutti i prerequisiti della regola. In questo caso, tutti i file sorgenti $(SRCS) 
$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Regola per pulire i file generati
clean:
	rm -f $(TARGET)

# Regola predefinita
all: $(TARGET)