######################################################################
# Makefile
######################################################################

TARGET = hummingbird

SRCS = src/main.c 				\
       src/config.c 		\
	   src/log.c 			\
	   src/network.c	\
	   src/utils.c 		\
	   src/crypto.c 		\
	   src/ike/header.c 		\
	   src/ike/payload.c 		\
	   src/ike/packet.c			\
	   src/auth.c			\
	   src/ike/ike.c

LIBS =  -linih					\
		-lssl 					\
		-lcrypto 				\
		-g			 

CFLAGS = -DLOG_USE_COLOR -Wall 	\
		 -I include/ 			\

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

noconfig: clean
	$(MAKE) CFLAGS="$(CFLAGS) -DNO_INI_PARSING" $(TARGET)
