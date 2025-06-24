#include "../include/common.h" // IWYU pragma: keep
#include <bits/time.h>
#include <ini.h>
#include "../include/config.h"
#include "../include/log.h"
#include "../include/crypto.h"
#include "../include/utils.h"
#include "../include/network.h"
#include "../include/ike/header.h"
#include "../include/ike/constant.h"
#include "../include//ike/header.h"
#include "../include/ike/ike.h"
#include "../include/ike/payload.h"

#include <openssl/hmac.h> 
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/random.h> 


typedef struct {
    ike_payload_t* items;
    size_t size;     
    size_t capacity; 
} payload_array;


int main(int argc, char* argv[]){
    /*---------------------------------------------
    Command Line arguments
    ---------------------------------------------*/
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
    struct timespec start, end;
    // tracking the total traffic between the hosts 
    int tot_traffic = 0;
    clock_gettime(CLOCK_MONOTONIC, &start);

    /*--------------------------------------------
    Loading configuration file
    --------------------------------------------*/
    config* cfg = malloc(sizeof(config));
    default_config(cfg);
    int n;
    
    #ifndef NO_INI_PARSING
    if ((n = ini_parse(DEFAULT_CONFIG, handler, cfg)) != 0) {
        if (n == -1) {
            log_error("Error on opening the configuration file %s", COLOR_TEXT(ANSI_COLOR_YELLOW, DEFAULT_CONFIG));
            log_error("The file %s not exists", COLOR_TEXT(ANSI_COLOR_RED, DEFAULT_CONFIG));
            return EXIT_FAILURE;
        }
        if (n > 0) {
            log_error(ANSI_COLOR_RED "Error on reading the configuration file " ANSI_COLOR_BOLD "%s" ANSI_COLOR_RESET ANSI_COLOR_RED", at line" ANSI_COLOR_BOLD " %d" ANSI_COLOR_RESET , DEFAULT_CONFIG, n);
            log_error(ANSI_COLOR_RED "Can't load " ANSI_COLOR_BOLD "%s" ANSI_COLOR_RESET ANSI_COLOR_RED " due to syntax error", DEFAULT_CONFIG);
            return EXIT_FAILURE;
        }
        return EXIT_FAILURE;
    }
    #endif

    log_set_quiet(cfg->log.quiet);
    log_set_level(cfg->log.level);
    log_info("Configuration file %s loaded successfully", DEFAULT_CONFIG);
    log_info("[CFG] module successfully setup", DEFAULT_CONFIG);

    ike_partecipant_t left = {0};
    ike_partecipant_t right = {0};
    ike_sa_t sa = {0};
    
    initiate_ike(&left, &right, &sa, cfg);

    ike_payload_t* ni_data = malloc(sizeof(ike_payload_t));
    ike_payload_t* kex_data = malloc(sizeof(ike_payload_t));
    ike_payload_t* sa_data = malloc(sizeof(ike_payload_t));
    ike_payload_t* header_p = malloc(sizeof(ike_payload_t));
    
    build_payload(ni_data,     PAYLOAD_TYPE_NONCE, left.ctx.nonce);
    build_payload(kex_data,    PAYLOAD_TYPE_KE,    &left.ctx);
    build_payload(sa_data,     PAYLOAD_TYPE_SA,    &sa.suite);

    ike_header_raw_t header = init_header_raw(left.ctx.spi,0);

    payload_array msg;
    msg.capacity = 4;
    msg.items = malloc(msg.capacity * sizeof(ike_payload_t));

    // questo andrà a far parte del metodo build_header
    header_p->body = &header;
    header_p->len = IKE_HDR_DIM;
    header_p->type = IKE_HEADER;

    msg.items[3] = *ni_data;
    msg.items[2] = *kex_data;
    msg.items[1] = *sa_data;
    msg.items[0] = *header_p;

    // conviene fare un'unica malloc totale che diverse malloc parziali dato che ha un pò di overhead
    size_t len = 0;
    for(int i=0; i<4; i++){ len += msg.items[i].len; }
    uint8_t* buff = malloc(len);

    int offset = 0;
    for(int i=0; i < 4; i++){
        if(msg.items[i].type == IKE_HEADER){
            ike_header_raw_t* tmp = msg.items[i].body;
            uint32_to_bytes_be(offset + IKE_HDR_DIM, tmp->length);
        }
        memcpy(buff + offset, msg.items[i].body, msg.items[i].len);
        offset += msg.items[i].len;
    }

    free(ni_data);
    free(kex_data);
    free(sa_data);
    free(header_p);

    /* 
    ##############################################################
    Questa parte di retry va messa nel modulo NET
    ##############################################################
    */
    int retries = 0;
    int exponent = INITIAL_EXPONENT;

    int retval = 0;
    uint8_t* buffer = calloc(MAX_PAYLOAD, sizeof(uint8_t));

    while(retries < MAX_RETRIES){

        int timeout_sec = 1 << exponent;
        struct timeval timeout = {timeout_sec, 0};
        setsockopt(left.node.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));


        retval =  send(left.node.fd, buff, len, 0);
        if(retval == -1){
            log_warn("Error during the send");
            break;
        }

        log_info("Sended INIT message with dimension %zu bytes. Attemp no. %d", len, retries +1);
        tot_traffic += len;

        n = recv(left.node.fd, buffer, MAX_PAYLOAD, 0);

        if (n < 0) {
            if (errno == EAGAIN ) {
                log_warn("Timeout exceeded.");
                retries++;
                exponent += 2;
                continue;
            } else {
                log_error("The peer is unreachable");
                log_fatal("Shutting down");
                return EXIT_FAILURE;
            }
    } 
    
    log_debug("Received INIT response with dimension %d bytes", n);
    tot_traffic += n;
    break;
    }

    if (retries == MAX_RETRIES) {
        log_error("No response after %d attemps", MAX_RETRIES);
        log_fatal("Shutting down...");
        return EXIT_FAILURE;
    }
    /*
    #########################################################################################
    # END
    #########################################################################################
    */

    // rimuovere questo header e utilizzare quello raw dappertutto
    ike_header_t* hd = parse_header(buffer, n);
    memcpy(right.ctx.spi, &hd->responder_spi , 8);

    // usare solo questa tipologia di header
    ike_header_raw_t* hdr = malloc(sizeof(ike_header_raw_t));
    parse_header_raw(buffer,  hdr);

    memcpy(right.ctx.spi, hdr->responder_spi , SPI_LENGTH_BYTE);
    /* 
    #########################################################################################
    # RESPONSE PARSING, to move in ike directory and use in the recv method
    #########################################################################################
    */
    uint8_t *ptr = buffer+28; 
    uint8_t next_payload = hd->next_payload;

    while (next_payload != 0){
        
        ike_payload_header_raw_t *payload = (ike_payload_header_raw_t *)ptr;

        switch (next_payload) {
            case NEXT_PAYLOAD_NOTIFIY: {
                log_debug("Notify Payload received");
                break;
            };
            case NEXT_PAYLOAD_KE: {
                log_debug("Parsing KEr payload");
                // forse è meglio suddividere il contesto in chiave, e in nonce 
                right.ctx.dh_group = bytes_to_uint16_be(ptr + 4);
                right.ctx.key_len = bytes_to_uint16_be(payload->length) - 8;
                right.ctx.public_key = malloc(right.ctx.key_len);
                memcpy(right.ctx.public_key, ptr+8, right.ctx.key_len);
                break;
            };
            case NEXT_PAYLOAD_NONCE: {
                log_debug("Parsing Nr payload");
                right.ctx.nonce_len = bytes_to_uint16_be(payload->length) - GEN_HDR_DIM;
                right.ctx.nonce = malloc(right.ctx.nonce_len);
                memcpy(right.ctx.nonce, ptr + GEN_HDR_DIM, right.ctx.nonce_len);
                break;
            };
            default: {

            };
        }

        next_payload = payload->next_payload;
        ptr += bytes_to_uint16_be(payload->length);
    }
    /*
    #########################################################################################
    # END
    #########################################################################################
    */


    /*
    #########################################################################################
    # DA QUI IN AVANTI FARE REFACTORING
    ##########################################################################################
    */
    
    ike_session_t ike_sa = {0};
    ike_sa.initiator = left;
    ike_sa.responder = right;
    derive_ike_sa(&ike_sa);


    // adesso devo fare un metodo che a partire dall'auth ctx mi genera il corrispondente payload
    ike_id_payload_t *id_in = malloc(sizeof(ike_id_payload_t) + 4);
    id_in->id_type = ID_TYPE_IPV4_ADDR;
    uint8_t ip_bin[4];
    inet_pton(AF_INET, left.aut.id_data, ip_bin);
    memcpy(id_in->data, ip_bin, sizeof(ip_bin));


    //il contenuto di id payload insieme a quello di auth e della proposal va messo all'interno di encrypted and authenticated
    uint8_t auth_i[4] = {0};
    auth_i[0] = 0x02;
    auth_i[1] = 0x00;   // Reserved
    auth_i[2] = 0x00;  
    auth_i[3] = 0x00;


    //una volta generate le chiavi mi basta prendere il pacchetto precedente, mettergli in append il nonce del responder e i dati del ID payload
    //l 'auth payload è composto dal primo messaggio, a cui si concatena il nonce del responder e l'hash dell'IDpayload
    uint8_t* auth_payload = malloc(len + right.ctx.nonce_len + SHA1_DIGEST_LENGTH);
    size_t auth_len =  len + right.ctx.nonce_len + SHA1_DIGEST_LENGTH;  // il seed me lo devo salvare da qualche parte

    //le variabili buff e len le ho prese da sopra, riformulare quella parte
    memcpy(auth_payload, buff,len);
    memcpy(auth_payload + len, right.ctx.nonce, right.ctx.nonce_len);
    //dopo questi che dipendeno uno dalla richiesta e uno dalla risposta ne serve uno che dipende dallo scambio che deve avvenire ovvero quello di autenticazione, quidni
    // si aggiunge l'hmac dell'id

    uint8_t* md = malloc(SHA1_DIGEST_LENGTH);
    unsigned int md_len = 0;

    // se si cambia l'identià devo cambiare anche questo
    HMAC(EVP_sha1(), ike_sa.association.sk_pi, SHA1_DIGEST_LENGTH, (uint8_t*)id_in, 8, md, &md_len);

    memcpy(auth_payload + len + right.ctx.nonce_len, md, md_len);

    // questo auth payload a questo punto deve essere dato in pasto ad un prf 
    // AUTH = prf( prf(Shared Secret, "Key Pad for IKEv2"), <InitiatorSignedOctets>)
    // LA PARTE SUL SEGRETO CONDIVISO E DI POPOLAMENTO DELL'AUTH PAYLAOD VA SPOSTATA NELLA PARTE DI AUTH

    char *secret = "padrepio";
    size_t secret_len = 8;

    const char *key_pad_str = "Key Pad for IKEv2";
    size_t key_pad_len = 17; // Senza \0

    HMAC(EVP_sha1(),secret, secret_len, (const unsigned char *)key_pad_str, key_pad_len, md, &md_len);
    //printf("Key expansion \n");
    //dump_memory(md, md_len);

    uint8_t* output = malloc(SHA1_DIGEST_LENGTH);
    unsigned int out_len = 0;
    //ora questo deve essere utilizzato pe firmare l'auth payload
    HMAC(EVP_sha1(), md, md_len, auth_payload, auth_len, output, &out_len);
    //printf("AUTH PAYLOAD \n");
    //dump_memory(output, out_len);

    ike_payload_header_t sk = {0};
    sk.next_payload = NEXT_PAYLOAD_IDi;

    ike_payload_header_t identity = {0};
    identity.next_payload = NEXT_PAYLOAD_AUTH;
    identity.length = htobe16(8+4);

    ike_payload_header_t authentication = {0};
    authentication.next_payload = NEXT_PAYLOAD_NONE;
    authentication.length = htobe16(SHA1_DIGEST_LENGTH + 4 + 4); // da convertire il parametro della lunghezza
    // la lunghezza è 20 per il digest + 4 per l'header + 4 per informazioni per specificare l'auth method


    int plaintext_len = 8 + SHA1_DIGEST_LENGTH + 8+ 4; //+ 8;
    uint8_t* enc_buffer = malloc(plaintext_len);

    mempcpy(enc_buffer ,&identity, GEN_HDR_DIM);
    memcpy(enc_buffer + GEN_HDR_DIM , id_in, 8);
    memcpy(enc_buffer + 12, &authentication, GEN_HDR_DIM);
    memcpy(enc_buffer +16 , &auth_i, 4);
    memcpy(enc_buffer +16+4, output, out_len);

    //questo è il payload che devo cifrare, quindi adesso mi creo un iv che deve essere di 16 byte
    //la dimensione dell'iv dipendende dalla lunghezza della chiave in cbc
    // ########################################################################################
    // DA SPOSTARE NELLA PARTE DI CREAZIONE DELL'ENCRYPTED PAYLOAD
    // ########################################################################################
    size_t iv_len = 16;
    uint8_t* iv = malloc(iv_len);
    getrandom(iv, iv_len, 0);

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, ike_sa.association.sk_ei, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    //per vedere quanto sarà il padding verificare la lunghezza del buffer di cifratura
    //anche la quantità di padding va cifrata, il padding va calcolateo considerando che un byte deve essere riservato alla pad length
    //quindi dal padd da aggiungere togliamo un byte

    int padd =  16 - (plaintext_len % 16); 

    enc_buffer = realloc(enc_buffer, plaintext_len + padd);
    memset(enc_buffer + plaintext_len, 0, padd-1);
    memset(enc_buffer + plaintext_len + padd -1, padd-1, 1);
    plaintext_len += padd;


    uint8_t ciphertext[256];
    int len_cip;
    int ciphertext_len;


    EVP_EncryptUpdate(ctx, ciphertext, &len_cip, enc_buffer, plaintext_len);
    ciphertext_len = len_cip;

    
    // ##########################################################################################
    // FINO A QUA
    // ##########################################################################################

    // la dimensione del checksum deve essere di 12 byte, dato che l'algoritmo che si utilizza per calcolarlo è
    // AUTH_HMAC_SHA1_96 bytes because the HMAC gets truncated from 160 to 96 bits 
    // se non vogliamo specificare questo possiamo utilizzare AUTH_HMAC_SHA1_160 che quindi non ha bisogno di troncamento
    size_t icv_len = 12; 

    size_t response_len = GEN_HDR_DIM+iv_len+ciphertext_len;
    uint8_t* response = malloc(response_len);
    sk.length = htobe16(response_len+icv_len); //nel generare la lunghezza del payload cifrato e autenticato aggiunto la dimensione del checksum

    memcpy(response, &sk, GEN_HDR_DIM);
    memcpy(response + GEN_HDR_DIM , iv, iv_len);
    memcpy(response + GEN_HDR_DIM + iv_len , ciphertext, ciphertext_len);
    
    hd->exchange_type = EXCHANGE_IKE_AUTH;
    hd->next_payload = NEXT_PAYLOAD_SK;
    hd->message_id = htobe32(1);
    hd->length = htobe32(28+response_len+icv_len);
    uint8_t flags[] = {FLAG_I, 0};
    set_flags(hd, flags);

    response_len +=28;
    response = realloc(response, response_len);
    memmove(response+28, response, response_len-28);
    memcpy(response, hd, 28);    

    uint8_t *checksum = malloc(icv_len);

    HMAC(EVP_sha1(), ike_sa.association.sk_ai, SHA1_DIGEST_LENGTH, response, response_len, checksum, &md_len);
    response = realloc(response, response_len+icv_len);
    mempcpy(response + 28 + 4 +iv_len + ciphertext_len, checksum, icv_len);

    retval =  send(left.node.fd, response, response_len+icv_len, 0);

    tot_traffic += response_len;
    tot_traffic += icv_len;

    log_info("Waiting for the IKE AUTH response");

    buffer = realloc(buffer, MAX_PAYLOAD);
    n = recv(left.node.fd, buffer, MAX_PAYLOAD, 0);
    if (n < 0) {
        if (errno == EAGAIN ) {
            printf("Timeout scaduto: nessun dato ricevuto entro 1 secondo.\n");
        } else {
            perror("Errore durante la ricezione");
            return EXIT_FAILURE;
        }
    } 
    tot_traffic += n;

    log_debug("Bytes received from the responder %d", n);

    ike_header_raw_t raw = {0};
    parse_header_raw(buffer, &raw);
    

    // quando tratto i dati siamo già nel mondo della CPU, ovvero non stiamo più trattando byte 
    // ma stiamo operando su una variabile che è nativa per la macchina, quindi il compilatore conosce l'endianess della CPU e come rappresentare il dato
    // l'endianess conta solo quando interpretiamo l'array di byte come interi o altri dati nativi 

    secure_free(response, response_len);

    
    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    log_info("Handshake time: %.6f seconds", elapsed);
    log_info("Total traffic exchanged: %d bytes", tot_traffic);

    
    return 0;
}
