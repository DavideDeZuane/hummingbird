#ifndef IKE_PACKET_H
#define IKE_PACKET_H

#include "ike.h"


void parse_response(uint8_t* req, uint8_t* res, ike_partecipant_t* right);

#endif