#include "common_include.h" // IWYU pragma: keep
#include <endian.h>
#include <ini.h>
#include "./config/config.h"
#include "./socket/peer.h"
#include "./log/log.h"
#include "./ike/header.h"
#include "./utils/utils.h"
#include "./crypto/crypto.h"
#include "ike/constant.h"
#include "./network/network.h"
#include "./ike/header.h"
#include "ike/payload.h"

#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// questo andrà nella parte crypto
#include <sys/random.h>

/*
//questa define consente di fare l'overload di un metodo in c, queste sono da utilizzare per implementare il metodo di setup 
#define foo(X) _Generic((X), int: foo_int, char*: foo_char)(X)

void foo_int(int a){
    printf("%d\n", a);
}
 
void foo_char(char* d){
    printf("Print di un char\n");
}
*/

int main(int argc, char* argv[]){

    check_endian();
    //spostare questa parte del codice nella parte di utility (oppure trovare un altro nome )
    int opts;
    struct option long_opts[] = {
        {"version", no_argument, 0, 'v'},
        {"config", no_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0} // Terminatore
    };

    while((opts = getopt_long(argc, argv, "hvc", long_opts, NULL)) != -1){
        switch (opts) {
            case 'h': {
                printf("Usage of the command");
                return EXIT_SUCCESS;
            };
            case 'v': {
                printf("Version number..");
                return EXIT_SUCCESS;
            };
            case 'c': {
                char *cwd;
                cwd = getcwd(NULL, 0);
                cwd = realloc(cwd, strlen(cwd)+2);
                strcat(cwd, "/");
                printf("Path of the configuration file: %s%s\n", cwd, DEFAULT_CONFIG);
                return EXIT_SUCCESS;
            }
        
        }
    }  

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
    ike_responder responder = {0};
    responder_ini(&responder, &cfg.peer);
    initiator_ini(&initiator, &responder);
    //in questo modo facciamo si che il destinatario sia associato al socket, in questo modo possiamo usare direttamente la recv e la send 
    //inoltre  il socket rifiuterà di inviare e ricevere dati da qualsiasi altro indirizzo o porta (il socket è legato al server specifico)
    if (connect(initiator.sockfd, (struct sockaddr *)&responder.sk, sizeof(responder.sk)) < 0) {
        perror("connect failed");
        close(initiator.sockfd);
        return EXIT_FAILURE;
    } 

    char *buff = calloc(1500, sizeof(uint8_t));
    size_t buff_len = 1500;
    //modificare la sendto in modo tale che l'unico argomento da passare sia il messaggio

    // questa parte andrà spostata nella parte che si occupa di ike
    //dopo la send va aggiungo il SA payload, quindi la proposal dato che deve essere minimal definiamo solo una cipher suite

    ike_header_t header = init_header();
    print_header(&header);

    // quindi
    header.length = htobe32(header.length);
    header.message_id = htobe32(header.message_id);
    header.initiator_spi = htobe64(header.initiator_spi);
    header.responder_spi = htobe64(header.responder_spi);

    memcpy(buff, &header, sizeof(ike_header_t));
    //memcpy(buff+sizeof(ike_payload_header_t)+8, &sa_payload, sizeof(ike_payload_proposal));





    int retval =  send(initiator.sockfd, buff, buff_len, 0);
    if(retval == -1){
        printf("Errore per la send");
        return -1;
    }

    //la gestione della recv e del caso in cui il timeout scade va gestita nella parte network
    uint8_t* buffer = calloc(70, sizeof(uint8_t));
    printf("Waiting...\n");
    n = recv(initiator.sockfd, buffer, 70, 0);
    if (n < 0) {
        if (errno == EAGAIN ) {
            printf("Timeout scaduto: nessun dato ricevuto entro 1 secondo.\n");
        } else {
            perror("Errore durante la ricezione");
        }
    } 
    printf("Byte Ricevuti dal responder %d\n", n);
    buffer = realloc(buffer, n);
    buffer[n] = '\0'; 

    ike_header_t* hd = parse_header(buffer, n);

    
    printf("Initiator SPI: 0x%llx\n", (long long unsigned int) hd->initiator_spi);
    printf("Responder SPI: 0x%llx\n", (long long unsigned int) hd->responder_spi);
    printf("Next Payload: %d\n", hd->next_payload);
    printf("Message ID: %d\n", hd->message_id);
    printf("Length: %d\n", hd->length);
    

    //porcodio

    
    
    
    return 0;
}
