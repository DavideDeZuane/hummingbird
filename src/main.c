#include "common_include.h" // IWYU pragma: keep
#include <ini.h>
#include "./config/config.h"
#include "./socket/peer.h"
#include "./log/log.h"
#include "./ike/header.h"
#include "ike/constant.h"

#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>


uint64_t generate_spi() {
    uint8_t buffer[8];
    uint64_t spi_value = 0;
    for (int i = 0; i < sizeof(buffer); i++) spi_value = (spi_value << 8) | buffer[i];
    return spi_value;
}


void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}


int main(){

    //fare una funzione che fa il checking che il file di configurazione sia corretto
    /*
    *********************************************
    Loading configuration file
    ********************************************* 
    */
    config cfg = {0};
    log_set_level(LOG_INFO);
    int n;
    if ((n = ini_parse(DEFAULT_CONFIG, handler, &cfg)) < 0) {
        printf("Can't load %s\n", DEFAULT_CONFIG);
        log_error("Error on opening the configuration file %s\n", DEFAULT_CONFIG);
        return 1;
    }
    log_info("Configuration file %s loaded successfully", COLOR_TEXT(ANSI_COLOR_YELLOW,DEFAULT_CONFIG));

    /*
    *********************************************
    Setting initiator
    ********************************************* 
    */
    //fare un metodo per esempio exchange_setup() in cui si fa l'init sia di initiator che di responder
    ike_initiator initiator = {0};
    initiator_ini(&initiator);
    ike_responder responder = {0};
    responder_ini(&responder, &cfg.peer);


    char *buff = malloc(sizeof(ike_header_t));
    size_t buff_len = sizeof(ike_header_t);
    //modificare la sendto in modo tale che l'unico argomento da passare sia il messaggio

    // questa parte andrà spostata nella parte che si occupa di ike
    ike_header_t header = {0};
    header.initiator_spi = 0x12345678;
    header.responder_spi = SPI_NULL;

    memcpy(buff, &header, buff_len);

    printf("Spi generated: %lu \n", header.initiator_spi);

    int retval =  sendto(initiator.sockfd, buff, buff_len, 0, (struct sockaddr *) &responder.sk, sizeof(responder.sk));
    if(retval == -1){
        printf("Errore per la send");
        return -1;
    }

    /*
    EVP_PKEY *pkey1 = NULL;
    pkey1 = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    if(pkey1 == NULL) printf("Errore nella creazione della chiave");
    //la dimensione del buffer è 32 byte dato che x25519 produce sempre chiavi pubbliche di questa dimensione
    unsigned char buffer[32] = {0};
    size_t buffer_len = sizeof(buffer);
    if (EVP_PKEY_get_raw_private_key(pkey1, buffer, &buffer_len) <= 0) printf("Errore extracting the private key");
    printf("Chiave privata (X25519):\n");
    print_hex(buffer, buffer_len);
    // Estrai la chiave pubblica, quindi gli passiamo il contenitore e il buffer da popolare
    if (EVP_PKEY_get_raw_public_key(pkey1, buffer, &buffer_len) <= 0) printf("Errore extracting the public key");
    // Stampa la chiave pubblica in formato esadecimale
    printf("Chiave pubblica (X25519):\n");
    print_hex(buffer, buffer_len);
    */
    //la gestione della recv e del caso in cui il timeout scade va gestita nella parte network
    printf("Waiting...\n");
    retval = recv(initiator.sockfd, &buffer, 32, 0);
    if (retval < 0) {
        if (errno == EAGAIN ) {
            printf("Timeout scaduto: nessun dato ricevuto entro 1 secondo.\n");
        } else {
            perror("Errore durante la ricezione");
        }
    } 
    
    return 0;
}