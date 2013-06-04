
#include "sr_ip.h"

int is_udp_or_tcp(uint8_t * packet, int len){
    uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
    if (ip_proto == ip_protocol_tcp || ip_proto == ip_protocol_udp)  /* ICMP */
        return 1;
    return 0;
}

/* function to process ip requests and replies */
void process_ip_packet(struct sr_instance * sr, 
                       uint8_t * eth_packet, 
                       unsigned int len){

    sr_ip_hdr_t * ip_header = sanity_check(eth_packet, len); 
    size_t         eth_size = sizeof(sr_ethernet_hdr_t);
    print_hdr_ip(eth_packet+eth_size);

    /* passes sanity check */
    if (ip_header) {
	sr_if * interface = get_foreign_interface_by_ip(sr, ip_header->ip_dst);
	if (interface){
	    ip_header->ip_ttl--; /* decr ttl */
            printf("calculating new checksum\n");

	    /* recompute packet checksum over modified header */
	    ip_header->ip_sum = cksum(eth_packet+eth_size, sizeof(sr_ip_hdr_t));
	    
            /* find which entry in the routing table has the longest 
               prefix match with the destination IP address */
            
	    struct sr_rt * match = find_longest_prefix_match(sr, ip_header->ip_dst);

            printf("found match\n");

            sr_print_routing_entry(match);

            /* forward packet ip packet */
            printf("forward packet here\n");

            /*Check the ARP cache for the next-hop MAC 
              address corresponding to the next-hop IP */                 

            sr_arpcache_dump(&sr->cache);

            struct sr_arpentry * entry = sr_arpcache_lookup(&sr->cache, match->dest.s_addr);

            printf("does entry exist?\n");

            sr_ethernet_hdr_t * eth_header = (sr_ethernet_hdr_t *)eth_packet;

            if (entry) {

               /*use next_hop_ip->mac mapping in entry to send the packet*/



                memcpy(eth_header->ether_dhost,
                           entry->mac, 
                           ETHER_ADDR_LEN);

                printf("printing headers before send\n");

                print_hdrs(eth_packet, len);

                sr_send_packet(sr, eth_packet, len, interface->name);

                free(entry);

            } else {
           
               printf("entry is null\n");

/*   else:
       req = arpcache_queuereq(next_hop_ip, packet, len)
       handle_arpreq(req)
*/
               struct sr_ip_hdr_t * ip_hdr = 
                   (sr_ip_hdr_t *)(eth_header + (sizeof(sr_ethernet_hdr_t)));

                   struct arq_req * req = arpcache_queuereq(ip_hdr->ip_dst,
                                               packet, 
                                               len);
           
                

                /*                generate and send an ARP request,
                                  then free it */
                
                /*add to queue of reqs, free packet?*/

                /* struct arp_req * req = sr_arpcache_queuereq(sr->cache, */
                /*                      match->dest.s_addr, */
                /*                      eth_packet, */
                /*                      len - eth_size, */
                /*                      interface->name); */


                /* uint8_t new_packet = malloc(sizeof(sr_ethernet_hdr_t) + */
                /*                             sizeof(sr_arp_hdr_t)); */

                /*handle_arpreq(req);*/

             /* free(arp_req); */
            }

   /* if entry: */
   /*     use next_hop_ip->mac mapping in entry to send the packet */
   /*     free entry */
   /* else: */
   /*     req = arpcache_queuereq(next_hop_ip, packet, len) */
   /*     handle_arpreq(req) */



            /*If it's there, send it*/

            /*Otherwise, send an ARP request for the next-hop IP (if
              one hasn't been sent within the last second), and add
              the packet to the queue of packets waiting on this ARP request.*/

            /*            sr_send_packet(sr, new_packet, size,
                          interface->name); */

	} else {

            /* is it a router address? */
            sr_if * interface = get_router_interface_by_ip(sr, ip_header->ip_dst);
            
            if (interface){

                /* If the packet is an ICMP echo request and its checksum
               is valid, send an ICMP echo reply to the sending host. */
                if (is_icmp(eth_packet, len) && is_icmp_cksum_valid(eth_packet,len)) {
                    printf("icmp message w/ valid cksum to one of our interfaces\n");
                    send_icmp(echo_type, echo_reply, eth_packet, len);
                }

                /* If the packet contains a TCP or UDP payload, send an
                   ICMP port unreachable to the sending host. */
                if (is_udp_or_tcp(eth_packet, len)) 
                    send_icmp(unreachable_type, port_unreachable, eth_packet, len);

                /* Otherwise, ignore the packet. */

            } else {
                printf("couldn't find interface to send to\n");
            }
        }
	
    } else {
	/* packet does not pass sanity check, send icmp error? */
        printf("failed sanity check\n");
    }


    /* if the frame contains an IP packet that is not destined towards one of our interfaces */
      /* process ip */
      return;
  }




sr_ip_hdr_t * sanity_check(uint8_t * packet, size_t len){

    /* Sanity-check the packet (meets minimum length and has correct checksum). */
    /* uint16_t cksum (const void *_data, int len) */

    printf("performin sanity check\n");

    sr_ip_hdr_t * ip_header       = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    size_t eth_size = sizeof(sr_ethernet_hdr_t);
    unsigned int ip_packet_length = sizeof(sr_ip_hdr_t);

    printf("ip packet len: %d, sizeof(sr_ip_hdr_t): %lu\n", ip_packet_length, sizeof(sr_ip_hdr_t));

    uint16_t temp = ip_header->ip_sum;
    ip_header->ip_sum = 0;

    if (ip_packet_length < sizeof(sr_ip_hdr_t)) {
        printf("length failure\n");
	return NULL;
    }

    printf("ip packet cksum: %d, ip_header->ip_sum: %d\n", 
           cksum(packet + eth_size, ip_packet_length), temp);

    if (cksum(packet + eth_size, ip_packet_length) != temp){
        printf("cksum is false\n");
	return NULL;
    }

    return ip_header;
}

