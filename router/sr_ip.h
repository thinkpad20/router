#ifndef SR_IP_H
#define SR_IP_H

#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_if.h"
#include "sr_arpcache.h"

void process_ip_packet(struct sr_instance *, uint8_t *, unsigned int);
int is_udp_or_tcp(uint8_t * packet, int len);
sr_ip_hdr_t * sanity_check(uint8_t * packet, size_t len);

#endif /* -- SR_IP_H -- */

