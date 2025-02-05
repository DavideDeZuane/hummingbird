#ifndef IKE_PACKET_H
#define IKE_PACKET_H

#include "ike.h"
#include "../socket/peer.h"


void parse_response(ike_responder responder, uint8_t* buff);


#endif