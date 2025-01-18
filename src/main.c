#include "common_include.h" // IWYU pragma: keep
#include <ini.h>
#include "./config/config.h"
#include "./socket/peer.h"
#include "./log/log.h"
#include "./ike/header.h"
#include "./utils/utils.h"
#include "ike/constant.h"

#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// questo andrà nella parte crypto
#include <sys/random.h>


//questa define consente di fare l'overload di un metodo in c, queste sono da utilizzare per implementare il metodo di setup 
#define foo(X) _Generic((X), int: foo_int, char*: foo_char)(X)

void foo_int(int a){
    printf("%d\n", a);
}
 
void foo_char(char* d){
    printf("Print di un char\n");
}


int main(int argc, char* argv[]){

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


    char *buff = malloc(sizeof(ike_header_t));
    size_t buff_len = sizeof(ike_header_t);
    //modificare la sendto in modo tale che l'unico argomento da passare sia il messaggio

    // questa parte andrà spostata nella parte che si occupa di ike
    ike_header_t header = {0};
    header.initiator_spi = 0x12345678;
    header.responder_spi = SPI_NULL;
    header.next_payload = NEXT_PAYLOAD_KE;
    header.message_id = MID_NULL;
    header.exchange_type = EXCHANGE_IKE_SA_INIT;
    header.version = 0x20;
    header.length = sizeof(ike_header_t);

    //prima di fare il memcopy fare la conversione

    memcpy(buff, &header, buff_len);
    
    //print_hex(buff, buff_len);

    int retval =  send(initiator.sockfd, buff, buff_len, 0);
    if(retval == -1){
        printf("Errore per la send");
        return -1;
    }
    //in questo caso il problema è che a questo punto anche se abbiamo fatto la send potrebbe non essere arrivata 

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
    char buffer[32] = {0};
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
