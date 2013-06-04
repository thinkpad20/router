

#ifndef SR_HELPERS_H
#define SR_HELPERS_H

#include "sr_router.h"
#include "sr_protocol.h"

/* protocols */
typedef struct sr_it sr_it;
typedef struct sr_if sr_if;
typedef struct sr_instance sr_instance_t;

int check_eth_packet(int len, int min_length);
struct sr_rt * find_longest_prefix_match(sr_instance_t * instance, uint32_t dest);
int longest_match(char * x, char * dest);
struct sr_if * get_router_interface_by_ip(struct sr_instance * sr, uint32_t tip);
struct sr_if * get_foreign_interface_by_ip(struct sr_instance * sr, uint32_t tip);

#endif 
