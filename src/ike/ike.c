#include "ike.h"
#include "../log/log.h"
#include "../network/network.h"


void initiate_ike(ike_partecipant_t* left, ike_partecipant_t* right, config* cfg){


    log_info("Starting the init process...");
    int retv = initiate_netwok(&left->node, &right->node, &cfg->peer);
    // function that handle the module if not started successfully
    (retv == 0) ? log_info("Network Module successfully setup") : log_error("Could not initiate the [NET] module") ;
    //the initiate crypto function has to return a int 
    initiate_crypto(&left->ctx);
    (retv == 0) ? log_info("Network Module successfully setup") : log_error("Could not initiate the [NET] module") ;
    
    


}