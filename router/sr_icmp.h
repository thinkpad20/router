
#ifndef SR_ICMP_H
#define SR_ICMP_H

#include "sr_protocol.h"

int is_icmp_cksum_valid(uint8_t *, int);
int send_icmp(int, int, uint8_t *, int);
int is_icmp(uint8_t *, int);

#endif
