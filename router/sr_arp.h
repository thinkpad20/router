
#ifndef SR_ARP_H
#define SR_ARP_H

#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_if.h"


/* prototype */
void handle_arp_request(sr_instance_t *,  sr_arp_hdr_t *, int, uint8_t *);
void handle_arp_reply(sr_instance_t *, sr_arp_hdr_t *);
void send_arp_reply(sr_instance_t *, sr_if *, sr_arp_hdr_t *); 
void process_arp(sr_instance_t *, uint8_t *, int, int);
int check_arp_packet(int len, int min_length);
#endif /* -- SR_ARP_H -- */
