#include <string.h>
#include "../include/config.h"

/*
###########################################################################################
MACRO SECTION to make the code more readable
###########################################################################################
*/
#define MATCH(s, n) ( strcmp(section, s) == 0 && strcmp(name, n) == 0 )
#define SET_DEFAUTL_FIELD(cfg, sub, field, val) strncpy((cfg)->sub.field, (val), sizeof((cfg)->sub.field))
#define HANDLE_FIELD(sec, field, src, dst, max_len)  if (MATCH(sec, field)) { secure_strncpy(dst, src, max_len); return 1; }

/**
* @brief This function is used to make a secure copy, it limits the maximum number of characters to be copied to avoid overflow
* @param[out] dest Pointer to the destination
* @param[in] src Pointer to the data to be copied
* @param[in] dest_size Maximum number of characters to copy 
*/
void secure_strncpy(char *dest, const char *src, size_t dest_size) {
    // importanza di limitare la copia per evitare overflow
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';

}

/**
* @brief This function set the default configuration options for each module
* @param[in] cfg Pointer to the configuration struct to be populated
*/
void default_config(config* cfg){

    // default configuration for the [NET] module
    SET_DEFAUTL_FIELD(cfg, peer, hostname, "localhost");
    SET_DEFAUTL_FIELD(cfg, peer, address,  "127.0.0.1");
    SET_DEFAUTL_FIELD(cfg, peer, port,     "500");
    
    // default configuration for the [AUT] module
    SET_DEFAUTL_FIELD(cfg, auth, id,       "padrepio");
    SET_DEFAUTL_FIELD(cfg, auth, method,   "psk");
    SET_DEFAUTL_FIELD(cfg, auth, data,     "padrepio");
    
    // default configuration for the [CRY] module
    SET_DEFAUTL_FIELD(cfg, suite, enc, "aes128");
    SET_DEFAUTL_FIELD(cfg, suite, aut, "sha1_96");
    SET_DEFAUTL_FIELD(cfg, suite, prf, "prfsha1");
    SET_DEFAUTL_FIELD(cfg, suite, kex, "x25519");

    cfg->log.quiet = false;

}

/**
* @brief Handler that deals with popular section dealing with authentication configurations, this will be used to initialize the [AUT] modue
* @param[in] opts Pointer to a substructure of the configuration structs, particularly one that has to do with authentication
* @param[in] section This is fixed and is "Authentication"
* @param[in] name Same as handler
* @param[in] value Same as handler 
*/
int auth_handler(auth_options_t* opts, const char* section, const char* name, const char* value){

    HANDLE_FIELD(section, "id",        value,  opts->id,       MAX_ID_LENGTH);
    HANDLE_FIELD(section, "method",    value,  opts->method,   MAX_AUTH_METHOD_LEN);
    HANDLE_FIELD(section, "data",      value,  opts->data,     MAX_AUTH_DATA_LEN);
    return 0;

}

/**
* @brief Handler that deals with popular section dealing with network configurations, this will be used to initialize the [NET] modue.
* The socket address where the responder is running
* @param[in] opts Pointer to a substructure of the configuration structs, particularly one that has to do with the remote peer
* @param[in] section This is fixed and is "Network"
* @param[in] name Same as handler
* @param[in] value Same as handler 
*/
int peer_handler(peer_options* opts, const char* section, const char* name, const char* value){

    HANDLE_FIELD(section, "hostname",  value,  opts->hostname,  INET_FQNLEN);
    HANDLE_FIELD(section, "address",   value,  opts->address,   INET_ADDRSTRLEN);
    HANDLE_FIELD(section, "port",      value,  opts->port,      MAX_PORT_LENGTH);

    return 0;

}

/**
* @brief Handler that deals with popular section dealing with cyrptography configurations, this will be used to initialize the [CRY] modue
* @param[in] opts Pointer to a substructure of the configuration structs, particularly one that has to do with cryptographyc functions
* @param[in] section This is fixed and is "Crypto"
* @param[in] name Same as handler
* @param[in] value Same as handler 
*/
int crypto_handler(cipher_options* opts, const char* section, const char* name, const char* value){
    
    HANDLE_FIELD(section, "encryption",        value,  opts->enc,  MAX_ID_LENGTH);
    HANDLE_FIELD(section, "authentication",    value,  opts->aut,  MAX_ID_LENGTH);
    HANDLE_FIELD(section, "pseudorandom",      value,  opts->prf,  MAX_ID_LENGTH);
    HANDLE_FIELD(section, "key-exchange",      value,  opts->kex,  MAX_ID_LENGTH);

    return 0;
}

/** 
* @brief Handler that deals with popular section dealing with logging configuration, this will be used to initialize the [LOG] module
* @param[in] opts Pointer to a substructure of the configuration structs, particularly one that has to do with cryptographyc functions
* @param[in] section This is fixed and is "Logging"
* @param[in] name Same as handler
* @param[in] value Same as handler 
*/
int log_handler(logging_options* opts, const char* section, const char* name, const char* value){

    if(MATCH("Logging", "quiet")){
        if(strcmp(value, "true") == 0) opts->quiet = true;
        else opts->quiet = false;
    } 
    return 0;
}

/**
* @brief This function is called every time a line within the configuration file is parsed. 
* Each time a line is read, this callback is invoked
* @param[in] cfg Pointer to the configuration struct to be populated
* @param[in] section The name of the current section, the field name inside the square brakets
* @param[in] name The parameter name read 
* @param[in] value the value associated with parameter
*/
int handler(void* cfg, const char* section, const char* name, const char* value){

    config* conf = (config *) cfg;

    if (strcmp(section, "Network") == 0){
        peer_handler(&conf->peer, section, name, value);
    }
    if (strcmp(section, "Authentication") == 0){
        auth_handler(&conf->auth, section, name, value);
    } 
    if (strcmp(section, "Crypto") == 0){
        crypto_handler(&conf->suite, section, name, value);
    } 

    if (strcmp(section, "Logging") == 0){
        log_handler(&conf->log, section, name, value);
    } 

    return 1;

}