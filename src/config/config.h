#ifndef CONFIG_H
#define CONFIG_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <ini.h>
#include <stdint.h>

#define DEFAULT_CONFIG "conf.ini"
#define INET_FQNLEN 255
#define MAX_PORT_LENGTH 6

typedef struct {
    char hostname[INET_FQNLEN];
    char address[INET_ADDRSTRLEN];
    char port[MAX_PORT_LENGTH];
} peer_options;


typedef struct {
    int enc;
    int aut;
    int prf;
    int kex;
} cipher_options;

typedef struct {
    peer_options peer;
    cipher_options suite;
} config;

/**
 * @brief Function to parse the config file
 * @param[in] cfg Data Structure to populate
 * @param[in] section Section of the config file, name inside the square brakets
 * @param[in] name Name of the configuration inside the section
 * @param[in] value Value of the specified name
 */
int handler(void* cfg, const char* section, const char* name, const char* value);



#endif