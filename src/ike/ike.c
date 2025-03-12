#include "ike.h"
#include "../log/log.h"


void initiate_ike(ike_partecipant_t* left, ike_partecipant_t* rigth){
    log_info("Function for initiate the ike exchange");
    initiate_crypto(&left->ctx);
    //initiate_network() questa è la funzione che deve configurare gli endpoint
    
    
    


}