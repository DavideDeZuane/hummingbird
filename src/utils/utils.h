#ifndef UTILITY_H
#define UTILITY_H

#include "../common_include.h"
#include "../ike/constant.h"
#include <stdio.h>

void print_hex(char *data, size_t len);
field_descriptor_t* fields_to_convert(MessageComponent type, size_t* num);

#endif