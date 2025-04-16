#include "ike.h"
#include "../log/log.h"
#include "../network/network.h"
#include <stdlib.h>


void initiate_ike(ike_partecipant_t* left, ike_partecipant_t* right, config* cfg){


    log_info(ANSI_COLOR_GREEN "Starting the init process of hummingbird..." ANSI_COLOR_RESET);
    int retv = initiate_netwok(&left->node, &right->node, &cfg->peer);
    // function that handle the module if not started successfully
    if(retv != 0){
        log_error(ANSI_COLOR_RED "Could not initiate the [NET] module" ANSI_COLOR_RESET);
        log_fatal(ANSI_COLOR_RED "Shutting down.." ANSI_COLOR_RESET);
        exit(EXIT_FAILURE);
    }
    log_info(ANSI_COLOR_GREEN "[NET] module successfully setup" ANSI_COLOR_RESET);


    //the initiate crypto function has to return a int 
    //aggiungere le opzioni da verificare nella parte crypto quindi la lunghezza del nonce e le varie informazioni che riguardano le cipher suite da utilizzare
    initiate_crypto(&left->ctx);
    (retv == 0) ? log_info(ANSI_COLOR_GREEN "[CRY] module successfully setup" ANSI_COLOR_RESET) : log_error("Could not initiate the [CRY] module") ;

}

