
#ifndef SR_ICMP_H
#define SR_ICMP_H

#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_arpcache.h"

int is_icmp_cksum_valid(uint8_t *, int);
void send_icmp(struct sr_instance *t, struct sr_packet *packet, int type, int code);
void send_icmp_host_unreachable(struct sr_instance *t, struct sr_packet *p);
void send_icmp_port_unreachable(struct sr_instance *t, uint8_t * buff, struct sr_if * interface);
int is_icmp(uint8_t *);

#endif
