
#ifndef SR_ARP_H
#define SR_ARP_H

#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_if.h"


/* prototype */
void handle_arp_reply(struct sr_instance *, sr_arp_hdr_t *);
void sr_arpcache_sweepreqs(struct sr_instance *sr);
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req);
void send_arp_reply(struct sr_instance *, struct sr_if *, sr_arp_hdr_t *); 
void process_arp(struct sr_instance *, uint8_t *, int, int);
int check_arp_packet(int len, int min_length);
void handle_arp_op_request(struct sr_instance *  sr, 
                           sr_arp_hdr_t * arp_hdr, 
                           int len, 
                           uint8_t * packet);
#endif /* -- SR_ARP_H -- */
