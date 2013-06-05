

#ifndef SR_HELPERS_H
#define SR_HELPERS_H

#include "sr_router.h"
#include "sr_protocol.h"

/* forward declare */
struct sr_instance;
/* protocols */

int check_eth_packet(int len, int min_length);
struct sr_rt * find_longest_prefix_match(struct sr_instance * instance, uint32_t dest);
int longest_match(char * x, char * dest);
struct sr_if * get_router_interface_by_ip(struct sr_instance * sr, uint32_t tip);
struct sr_if * get_foreign_interface_by_ip(struct sr_instance * sr, uint32_t tip);

#endif 
