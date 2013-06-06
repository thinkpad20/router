#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_ip.h"
#include "sr_arp.h"
#include "sr_icmp.h"
#include "sr_helpers.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);
    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));
    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;
    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

void sr_handlepacket(struct sr_instance* sr,
		     uint8_t * packet    /* lent */,
		     unsigned int len,
		     char* interface     /* lent */)
{
   /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);
    printf("***********************************************************\n"
           "**               HANDLING A NEW PACKET                   **\n"
           "***********************************************************\n");
    print_hdrs(packet, len);

    /* sanity check on eth packet */
    int min_length = sizeof(sr_ethernet_hdr_t);

    if (!check_eth_packet(len, min_length))
        return;

    struct sr_if *iface = sr_get_interface(sr, interface);

    switch (ethertype(packet)){
    case ethertype_arp:
        if (!check_arp_packet(len, min_length)) return;
        printf("processing arp packet\n");
	    process_arp_packet(sr, packet, len, min_length, iface); 
    	break;
    case ethertype_ip:
        process_ip_packet(sr, packet, len, iface);
    	break;
    default: /* if unknow, this is an error, send ICMP of 'unreachable' */
    	break;
    }
}


/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

