
#ifndef SR_ARP_H
#define SR_ARP_H

#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_if.h"


/* prototype */
void handle_arp_reply(struct sr_instance *sr, sr_arp_hdr_t *arp_packet, struct sr_arpreq *req);
void sr_arpcache_sweepreqs(struct sr_instance *sr);
int handle_queued_arp_req(struct sr_instance *sr, struct sr_arpreq *req); 
void process_arp_packet(struct sr_instance *, uint8_t *, int, int, struct sr_if *incoming_iface);
int check_arp_packet(int len, int min_length);
void handle_arp_request(struct sr_instance *  sr, 
                           sr_arp_hdr_t * arp_hdr, 
                           int len, 
                           uint8_t * packet,
                           struct sr_if *incoming_iface);
void send_arp_req(struct sr_instance *sr, uint32_t ip, struct sr_if *iface);
void send_arp_reply(struct sr_instance *, struct sr_if *, sr_arp_hdr_t *, struct sr_if *incoming_iface); 
#endif /* -- SR_ARP_H -- */
