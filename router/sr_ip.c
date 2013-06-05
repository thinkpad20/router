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
                       unsigned int len) {

    sr_ip_hdr_t * ip_header = sanity_check(eth_packet, len); 
    size_t         eth_size = sizeof(sr_ethernet_hdr_t);
    print_hdr_ip(eth_packet+eth_size);

    /* passes sanity check */
    if (!ip_header) { printf("failed sanity check\n"); return; }
    
    /* check if this packet is destined for us */
    struct sr_if * interface = get_router_interface_by_ip(sr, ip_header->ip_dst);
    if (interface) {
        /* If the packet is an ICMP echo request and its checksum
           is valid, send an ICMP echo reply to the sending host. */
        if (is_icmp(eth_packet, len) && is_icmp_cksum_valid(eth_packet,len)) {
            printf("icmp message w/ valid cksum to one of our interfaces\n");
            /*send_icmp(echo_type, echo_reply, eth_packet, len);*/
        }

        /* If the packet contains a TCP or UDP payload, send an
           ICMP port unreachable to the sending host. */
        if (is_udp_or_tcp(eth_packet, len)) {}
            /*send_icmp(unreachable_type, port_unreachable, eth_packet, len);*/

        /* Otherwise, ignore the packet. */
        return;
    }
    
    /* packet is not destined for us. Do we know where to forward it? */
    printf("couldn't find interface to send to\n");

    /* find interface and routing table entry that best match input IP */
    interface = find_longest_prefix_match_interface(sr, ip_header->ip_dst);
    struct sr_rt *match = find_longest_prefix_match(sr, ip_header->ip_dst);

    /* if this is null, we have absolutely no match, and send an error */
    if (!match) {
        /* send an error here */
        return;
    }

    /* OK, so now we get to forward a packet. Yay! */
    printf("here's the matching routing entry we found:\n");
    sr_print_routing_entry(match);

    /* set up the ethernet header */
    sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t *)eth_packet;

    /* decrement time to live -- we should check if ttl is 0 after this */
    ip_header->ip_ttl--;

    if (!ip_header->ip_ttl) { /* do something */ return; }

    /* recompute packet checksum over modified header */
    ip_header->ip_sum = cksum(eth_packet+eth_size, sizeof(sr_ip_hdr_t));

    /* Check the ARP cache for the next-hop MAC 
      address corresponding to the next-hop IP */
    struct sr_arpentry * entry = sr_arpcache_lookup(&sr->cache, 
                                                    match->dest.s_addr);

    if (entry) {
       /*use next_hop_ip->mac mapping in entry to send the packet*/
        memcpy(eth_header->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        printf("printing headers before send\n");
        print_hdrs(eth_packet, len);
        sr_send_packet(sr, eth_packet, len, interface->name);
        free(entry);
    } else {
        /* mac address was not found in our lookup table */
        printf("entry is null\n");

        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(eth_header + (sizeof(sr_ethernet_hdr_t)));

        printf("got ip hdr\n");

        printf("ip: %u,\n", ip_hdr->ip_dst);

        /* create an arp request and add it to the queue */
        struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, 
                                                     ip_hdr->ip_dst, 
                                                     eth_packet, 
                                                     len,
                                                     interface->name);

        
        printf("got arp request, ip: %u\n", req->ip);
        /* calling handle_arp_req with a non-null interface will cause it
           to send the request immediately */

        handle_arp_req(sr, req, interface);
    }
}




sr_ip_hdr_t * sanity_check(uint8_t * packet, size_t len){

    /* Sanity-check the packet (meets minimum length and has correct checksum). */
    /* uint16_t cksum (const void *_data, int len) */

    printf("performin sanity check\n");

    sr_ip_hdr_t * ip_header       = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    size_t eth_size = sizeof(sr_ethernet_hdr_t);
    unsigned int ip_packet_length = sizeof(sr_ip_hdr_t);

    printf("ip packet len: %d, sizeof(sr_ip_hdr_t): %lu\n", ip_packet_length, 
                                                            sizeof(sr_ip_hdr_t));

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

