#include "common_include.h" // IWYU pragma: keep
#include <endian.h>
#include <ini.h>
#include "./config/config.h"
#include "./socket/peer.h"
#include "./log/log.h"
#include "./ike/header.h"
#include "crypto/crypto.h"
#include "ike/constant.h"
#include "./ike/header.h"
#include "ike/payload.h"
#include "utils/utils.h"

#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PAYLOAD 1444

    void print_file(const unsigned char *data, size_t length, FILE *file) {
        for (size_t i = 0; i < length; i++) {
            fprintf(file, "%02x", data[i]);
        }
    }
//spostare questo nel modulo packet, questa è quella parte che si occupa di creare il messaggio e il creeate message ritorna il buffer che poi verrò inviato tramite socket sulla rete 

typedef struct {
    void *next; // Puntatore generico al prossimo payload
    void *prev; // Puntatore generico al precedente payload
    void *data;                  // Puntatore generico ai dati del payload
    size_t length;
    MessageComponent type; 
} ike_message_component_t;

typedef struct {
    ike_message_component_t *head;
    ike_message_component_t *tail;
} ike_message_t;

void push_component(ike_message_t* list, MessageComponent type, void *data, size_t length){

    ike_message_component_t* new = malloc(sizeof(ike_message_component_t));
    if (new == NULL) printf("Error during malloc\n");
    
    new->prev = NULL; //dato che faccio il prepend l'elemento che aggiungo diventa il primo e quindi lo posso lasciare qui
    new->data = data;
    new->length = length;
    new->type = type;
    
    if(list->head == NULL){
        list->head = new;
        list->tail = new;
        return;
    }
    new->next = list->head;
    list->head->prev = new;
    list->head = new;
}

uint8_t* create_message(ike_message_t* list, size_t* len){

    size_t buffer_len = 0;
    size_t offset = 0;

    uint8_t* buffer = NULL;
    ike_message_component_t* scan = list->tail;

    while(scan != NULL){
        buffer_len += scan->length;
        buffer = realloc(buffer, buffer_len);
        offset += scan->length;
        //una volta allocato il buffer prima di scriverci sopra facciamo la conversione in big endian di quello che ci vogliamo scrivere
        if (buffer_len > scan->length) memmove(buffer + scan->length, buffer, buffer_len - scan->length);

        if(scan->type == GENERIC_PAYLOAD_HEADER) {
            //se il componente che andiamo a considerare è quello del generic payload allora vuol dire che il componente che lo precedeva 
            //ha questo come header e quindi dato che ci server conoscere la sua lunhgezza utilizziamo il campo offset per determinare la dimensione del 
            //payload precedente in modo da non dover scrivere a mano la lunghezza. Una volta aggiornato il compo del generic header resettiamo l'offset
            //dato che passiamo al prossimo payload
            ike_payload_header_t* hd = (ike_payload_header_t*) scan->data;
            hd->length = htobe16(offset);
            offset = 0;
        }
        if(scan->type == IKE_HEADER){
            ike_header_t * hdr = (ike_header_t *) scan->data;
            hdr->length = htobe32(buffer_len) ;
        }

        memcpy(buffer, scan->data, scan->length);
        scan = scan->prev;
    }

    *len = buffer_len;
    return buffer;



}

void pop_component(void **list){

}

// spostare fino a qua

int main(int argc, char* argv[]){

    /*
    *********************************************
    Command Line arguments
    ********************************************* 
    */
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

    // questa parte andrà spostata nella parte che si occupa di ike
    //dopo la send va aggiungo il SA payload, quindi la proposal dato che deve essere minimal definiamo solo una cipher suite

    ike_message_t packet_list = {NULL, NULL};

    ike_header_t header = init_header();

    header.next_payload = NEXT_PAYLOAD_SA;

    ike_payload_header_t pd = {0};
    pd.next_payload = NEXT_PAYLOAD_NONCE;
    
    ike_payload_kex_t kd = {0};
    kd.dh_group = htobe16(31);
    size_t prova = 0;
    uint8_t* buff1 = NULL;


    //questa parte di popolazione delle chiavi e del nonce va spostata nella parte dell'init dato che andranno a popolare quella che è la struct 
    //state che è presente nel reposnder
    initiator.sa.key_len = 32;
    initiator.sa.key = malloc(initiator.sa.key_len);
    memcpy(initiator.sa.key, "d09109773ea05e472104617cc4dda9642f7aa4af5e3651a82f920383f97e4e7d", initiator.sa.key_len);
    memcpy(&kd.ke_data, "00f9b203403fbbd98885d182c8629c675ac792de90208def138299dbf28c8c65", 32);
    
    initiator.sa.nonce_len = 16;
    initiator.sa.nonce = malloc(initiator.sa.nonce_len);
    uint8_t* nonce = malloc(initiator.sa.nonce_len);
    generate_nonce(nonce, 16);
    memcpy(initiator.sa.nonce, nonce, initiator.sa.nonce_len);

    ike_payload_header_t np = {0};
    np.next_payload = NEXT_PAYLOAD_NONE;

    ike_payload_proposal_t proposal = create_proposal();
    ike_payload_header_t header_1 = {0} ;
    header_1.next_payload = NEXT_PAYLOAD_KE;

    push_component(&packet_list, PAYLOAD_TYPE_NONCE, nonce, 16);
    push_component(&packet_list, GENERIC_PAYLOAD_HEADER, &np, sizeof(ike_payload_header_t));
    push_component(&packet_list, PAYLOAD_TYPE_KE, &kd, sizeof(ike_payload_kex_t));
    push_component(&packet_list, GENERIC_PAYLOAD_HEADER, &pd, sizeof(ike_payload_header_t));
    push_component(&packet_list, PAYLOAD_TYPE_SA, &proposal, sizeof(ike_payload_proposal_t));
    push_component(&packet_list, GENERIC_PAYLOAD_HEADER, &header_1, sizeof(ike_payload_header_t));
    push_component(&packet_list, IKE_HEADER, &header, sizeof(ike_header_t));
    
    uint8_t* buff;
    size_t len = 0;
    
    buff = create_message(&packet_list, &len);

    dump_memory(buff, len);

    //memcpy(buff, &header, sizeof(ike_header_t));
    //memcpy(buff+sizeof(ike_payload_header_t)+8, &sa_payload, sizeof(ike_payload_proposal));

    int retval =  send(initiator.sockfd, buff, len, 0);
    if(retval == -1){
        printf("Errore per la send");
        return -1;
    }
    //il free non azzera il contenuto dice solamente che la memoria ora è disponibile, quindi la rilascia al sistema operativo
    free(buff);

    //la gestione della recv e del caso in cui il timeout scade va gestita nella parte network
    uint8_t* buffer = calloc(MAX_PAYLOAD, sizeof(uint8_t));
    printf("Waiting...\n");
    n = recv(initiator.sockfd, buffer, MAX_PAYLOAD, 0);
    if (n < 0) {
        if (errno == EAGAIN ) {
            printf("Timeout scaduto: nessun dato ricevuto entro 1 secondo.\n");
        } else {
            perror("Errore durante la ricezione");
            return EXIT_FAILURE;
        }
    } 
    printf("Byte Ricevuti dal responder %d\n", n);
    buffer = realloc(buffer, n);
    buffer[n] = '\0'; 

    //qunado vado a fare il parsing dei vari elementi vorrei fare in modo di confrontare il payload dal buffer per aggiornare quello che ho inviato io 
    ike_header_t* hd = parse_header(buffer, n);
    /*
    printf("Initiator SPI: 0x%llx\n", (long long unsigned int) hd->initiator_spi);
    printf("Responder SPI: 0x%llx\n", (long long unsigned int) hd->responder_spi);
    printf("Next Payload: %d\n", hd->next_payload);
    printf("Message ID: %d\n", hd->message_id);
    printf("Length: %d\n", htobe32(hd->length));
    */
    dump_memory(buffer, n);
    //dump_memory(&header.initiator_spi, sizeof(uint64_t));
    //dump_memory(&hd->responder_spi, sizeof(uint64_t));
    
    //porcodio
    responder.sa.spi = hd->responder_spi;
    //printf("Next Payload nell'header: %s\n", next_payload_to_string(hd->next_payload));
    // funzione che fa il parsing, quello che fa è prendere la strucct del responder e il buffer che poi utilizzeremo per pooplarla
    uint8_t *ptr = buffer+28; 
    // 
    uint8_t next_payload = ptr[0];         
    uint8_t current_payload = hd->next_payload;

    while (next_payload != 0){
        current_payload = next_payload;
        //printf("Il payload corrente è %s\n", next_payload_to_string(current_payload));
        ike_payload_header_t *payload = (ike_payload_header_t *)ptr;

        if(current_payload == NEXT_PAYLOAD_KE){
            responder.sa.key_len = 32;
            responder.sa.key = malloc(responder.sa.key_len);
            memcpy(responder.sa.key, ptr+8, responder.sa.key_len);
        }
        
        if(current_payload == NEXT_PAYLOAD_NONCE){
            //printf("sono al payload nonce\n");
            responder.sa.nonce_len = be16toh(payload->length) -4;
            responder.sa.nonce = malloc(responder.sa.nonce_len);
            memcpy(responder.sa.nonce, ptr+4, 32);
        }

        //printf("Next payload di tipo %s, tra %d byte\n", next_payload_to_string(payload->next_payload), be16toh(payload->length));
        next_payload = payload->next_payload;
        ptr += be16toh(payload->length);
    }

    printf("Responder SPI \n");
    dump_memory(&responder.sa.spi, 8);
    printf("Initator SPI \n");
    dump_memory(&hd->initiator_spi, 8);

    printf("##################################################\n");
    printf("Initiator Nonce\n");
    printf("##################################################\n");
    dump_memory(initiator.sa.nonce, initiator.sa.nonce_len);
    printf("##################################################\n");
    printf("Initiator PriKey\n");
    printf("##################################################\n");
    dump_memory(initiator.sa.key, initiator.sa.key_len);

    printf("##################################################\n");
    printf("Responder Nonce\n");
    printf("##################################################\n");
    dump_memory(responder.sa.nonce, responder.sa.nonce_len);
    printf("##################################################\n");
    printf("Responder PubKey\n");
    printf("##################################################\n");
    dump_memory(responder.sa.key, responder.sa.key_len);

    FILE *file = fopen("key.txt", "w");
    if (file == NULL) {
        perror("Errore nell'aprire il file");
        return EXIT_FAILURE;
    }


    // Stampa i valori di Ni, Nr e g^ir in formato esadecimale nel file
    fprintf(file, "Ni: ");
    print_file(initiator.sa.nonce, initiator.sa.nonce_len, file);
    fprintf(file, "\n");

    fprintf(file, "Nr: ");
    print_file(responder.sa.nonce, responder.sa.nonce_len, file);
    fprintf(file, "\n");

    fprintf(file, "Publickey: ");
    print_file(responder.sa.key, responder.sa.key_len, file);
    fprintf(file, "\n");
    
    fprintf(file, "Privatekey: ");
    print_file(initiator.sa.key, initiator.sa.key_len, file);
    fprintf(file, "\n");
    //ora ho ottenuto il key material adesso vediamo se riesco a derivare il segreto condiviso corretto

    fprintf(file, "SPIr: ");
    print_file((const unsigned char *)&responder.sa.spi, 8, file);
    fprintf(file, "\n");

    hd->exchange_type = EXCHANGE_IKE_AUTH;
    hd->message_id = htobe32(1);
    uint8_t flags[] = {FLAG_I, 0};

    set_flags(hd, flags);
    memset(buff, 0, len);

    memcpy(buff, hd, 28);
    
    retval =  send(initiator.sockfd, buff, len, 0);
    return 0;
}
