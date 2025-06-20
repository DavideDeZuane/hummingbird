#ifndef CONFIG_H
#define CONFIG_H

#include <arpa/inet.h>
#include <ini.h>
#include <stdint.h>
#include <netinet/in.h>
#include <stdbool.h>

#define DEFAULT_CONFIG "conf.ini"
#define INET_FQNLEN 255
#define MAX_PORT_LENGTH 6
#define MAX_ALGR_LENGTH 10
#define MAX_ID_LENGTH 10

#define MAX_AUTH_ID_LEN 20
#define MAX_AUTH_METHOD_LEN 6
#define MAX_AUTH_DATA_LEN 256  

typedef struct {
    bool quiet;
    int level;
    char file_name[30];
} logging_options;

typedef struct {
    char id[MAX_AUTH_ID_LEN];
    char method[MAX_AUTH_METHOD_LEN];
    char data[MAX_AUTH_DATA_LEN];
} auth_options_t;

typedef struct {
    char hostname[INET_FQNLEN];
    char address[INET6_ADDRSTRLEN];
    char port[MAX_PORT_LENGTH];
} peer_options;


typedef struct {
    char enc[MAX_ALGR_LENGTH];
    char aut[MAX_ALGR_LENGTH];
    char prf[MAX_ALGR_LENGTH];
    char kex[MAX_ALGR_LENGTH];
} cipher_options;

typedef struct {
    peer_options peer;
    cipher_options suite;
    auth_options_t auth;
    logging_options log;
} config;

/**
* @brief Function to parse the config file
* @param[in] cfg Data Structure to populate
* @param[in] section Section of the config file, name inside the square brakets
* @param[in] name Name of the configuration inside the section
* @param[in] value Value of the specified name
*/
int handler(void* cfg, const char* section, const char* name, const char* value);

/**
* @brief This function set the default configuration options for each module
* @param[in] cfg Pointer to the configuration struct to be populated
*/
void default_config(config* cfg);

#endif