
#ifndef SR_ICMP_H
#define SR_ICMP_H

#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_arpcache.h"

int is_icmp_cksum_valid(uint8_t *, int);
int is_icmp_echo(uint8_t *);
void send_icmp(struct sr_instance *t, struct sr_packet *packet, int type, int code);
void send_icmp_host_unreachable(struct sr_instance *t, struct sr_packet *p, int);
void send_icmp_port_unreachable(struct sr_instance *t, 
                                uint8_t * buff, 
                                struct sr_if * interface, int);

void send_icmp_timeout(struct sr_instance *t, 
                       uint8_t * buff, 
                       struct sr_if * interface, int);

void send_icmp_echo(struct sr_instance *t, uint8_t * packet, struct sr_if * interface, int);

int is_icmp(uint8_t *, int);

#endif
