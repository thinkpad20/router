
#include "sr_arp.h"
#include "sr_protocol.h"

/* function to process arp requests and replies */
void process_arp(struct sr_instance * sr, 
                 uint8_t * packet, 
                 int packet_len, 
                 int min_length) {
    sr_arp_hdr_t * arp_packet = (sr_arp_hdr_t *)(packet + min_length);
    struct sr_if *iface = get_router_interface_by_ip(sr, arp_packet->ar_tip);
    if (!iface) {
        /* then packet was not meant for us */
        return;
    }

    /* we now have an IP/MAC mapping. We can save ARP requests by adding it 
        to our cache. If it was already in our cache, we'll now be able
        to send some data that was waiting. */
    struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_packet->ar_sha, 
                                                           arp_packet->ar_sip);

    switch (ntohs(arp_packet->ar_op)) {
        case arp_op_request:
            printf("we've received an ARP request\n");
    	    handle_arp_op_request(sr, arp_packet, packet_len, packet);
    	    break;
        case arp_op_reply:
            printf("we've received an ARP reply\n");
            handle_arp_reply(sr, req);
    	    break;
        default:
            /* we don't support this op code */
            break;
    }
    return;
}

void handle_arp_reply(struct sr_instance *sr, struct sr_arpreq *req) {
    /* make sure req exists */
    struct sr_packet *packet = (req) ? req->packets : NULL;

    /* if packet != NULL, we have some packets waiting to be sent, 
        and now we can send them! */
    while (packet) {
        sr_send_packet(sr, packet->buf, packet->len, packet->iface);
        packet = packet->next;
    }
}


void send_arp_reply(struct sr_instance * sr, 
                    struct sr_if * interface, 
                    sr_arp_hdr_t * arp_packet){

    /* send arp packet */
    printf("sending arp packet\n");

    /* construct packet, malloc memory for packet */
    /* fill packet with relevant arp and ethernet data */
    size_t size                  = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t * new_packet         = malloc(size);
    sr_ethernet_hdr_t * eth_head = (sr_ethernet_hdr_t *)new_packet;
    sr_arp_hdr_t * arp_head      = (sr_arp_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));

    /* ------------ Populate ethernet header----------- */

    /* copy source hw addr to eth head dhost */
    memcpy(eth_head->ether_dhost, arp_packet->ar_sha, ETHER_ADDR_LEN);

    /* copy interface mac addr to ether_shost*/
    memcpy(eth_head->ether_shost, interface->addr, ETHER_ADDR_LEN);

    /* set ethernet type to arp req */
    eth_head->ether_type = htons(ethertype_arp);

    /* ------------- Populate arp header -------------- */
    memcpy(arp_head, arp_packet, sizeof(sr_arp_hdr_t));

    /* set op code */
    arp_head->ar_op = htons(arp_op_reply);

    /* Set target IP address. Take it from source IP address */
    arp_head->ar_tip = arp_packet->ar_sip;

    /* Set target MAC address. Take from source hwa of arp */
    memcpy(arp_head->ar_tha, arp_packet->ar_sha, ETHER_ADDR_LEN);

    /* take source hw addr, put into thw addr */
    memcpy(arp_head->ar_sha, interface->addr, ETHER_ADDR_LEN);

    /* set source ip to be target ip */
    arp_head->ar_sip = arp_packet->ar_tip;

    printf("printing ethernet header of new packet\n");
    print_hdr_eth(new_packet);

    printf("printing arp header of new packet\n");
    print_hdr_arp(new_packet + sizeof(sr_ethernet_hdr_t));

    /*** send him on his way ***/
    sr_send_packet(sr, new_packet, size, interface->name);
    printf("sent\n");
    free(new_packet); 
}

void handle_arp_op_request(struct sr_instance *  sr, 
                           sr_arp_hdr_t * arp_hdr, 
                           int len, 
                           uint8_t * packet) {
    /* In the case of an ARP request, you should only send an ARP reply
       if the target IP address is one of your router's IP addresses. */
    /* ARP replies are sent directly to the requester's MAC address. */
    struct sr_if * interface;
    if ((interface = get_router_interface_by_ip(sr, arp_hdr->ar_tip)) != NULL) {
        printf("router interface\n");
        sr_print_if(interface);
        send_arp_reply(sr, interface, arp_hdr);
    } else if ((interface = get_foreign_interface_by_ip(sr, arp_hdr->ar_tip)) != NULL){
        printf("foreign interface ignore\n");
        sr_print_if(interface);        
    }
    else {
        printf("NOT FOUND: INTERFACE\n");
        /* how to handle this? */
        /* not meant for us (target ip not in interface list, 
           therefore, no ARP reply sent */
    }
    

    /*    if (interface) 

     else... what do I do if arp req is not in router interface list? */
}

int check_arp_packet(int len, int min_length){
    /* sanity check on arp packet */
    if (min_length + sizeof(sr_arp_hdr_t) < len){
        printf("too small to be a valid arp packet\n");
        return 0;
    }
    return 1;
}

void send_arp_req(struct sr_instance *sr, uint32_t ip, struct sr_if *iface) {
    /* allocate space for packet */
    uint32_t size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *new_packet = (uint8_t *)calloc(1, size);
    /* point eth header at beginning */
    sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t *)new_packet;
    /* point arp header to start right after eth header */
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)(new_packet + 
                                                sizeof(sr_ethernet_hdr_t));
    /* set up Ethernet header */
    /* set destination address to broadcast */
    memset(&eth_header->ether_dhost, -1, ETHER_ADDR_LEN);
    /* set source address to this interface's address */
    memcpy(&eth_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
    /* set ethernet type to ARP */
    eth_header->ether_type = htons(ethertype_arp);

    /* set the ARP packet */
    /* set target hardware address to all 0's */
    memset(&arp_header->ar_tha, 0, ETHER_ADDR_LEN);
    /* set source hardware address to this interface's */
    memcpy(&arp_header->ar_sha, iface->addr, ETHER_ADDR_LEN);
    /* set the target IP to input IP */
    arp_header->ar_tip = ip; /* note: already in network byte order */
    /* set the source IP to this interface's */
    arp_header->ar_sip = iface->ip;

    /* misc other values */
    arp_header->ar_op = htons(arp_op_request);
    arp_header->ar_hrd = htons(arp_hrd_ethernet);
    arp_header->ar_hln = ETHER_ADDR_LEN; /* single char so no hton */
    arp_header->ar_pro = htons(0x0800);
    arp_header->ar_pln = 

    /* and, ship it! */
    printf("printing arp req new packet deets\n");
    print_hdr_eth(new_packet);
    print_hdr_arp(new_packet + (sizeof(sr_ethernet_hdr_t)));
    
    printf("shippin new arp req to inteface %s\n", iface->name);
    sr_send_packet(sr, new_packet, size, iface->name);
}

int handle_arp_req(struct sr_instance *sr, struct sr_arpreq *req, struct sr_if *iface) {
    time_t now; time(&now);

    if (iface) {
        printf("new arp req, sending immediately\n");
        send_arp_req(sr, req->ip, iface);
        return 0;
    }

    /* otherwise, we're dealing with old packets */
    if (now - req->sent < 1) 
        printf("now - req->sent < 1\n");
        return 0; /* do nothing if less than 1s has passed */

    if (req->times_sent > 4) {
        printf("req->times_sent > 4\n");
        /* send ICMP host unreachable to all waiting */
        /* note that iface is just the first iface in the list */
        struct sr_packet *packet = req->packets;
        while (packet) {
            send_icmp_host_unreachable(sr, packet);
            packet = packet->next;
        }
        /* destroy arp req */
        return 1;
    } else {
        printf("req->times_sent < 5, send arp req\n");                    
        send_arp_req(sr, req->ip, find_longest_prefix_match_interface(sr, req->ip));
        /* update sent time and times_sent */
        time(&req->sent);
        req->times_sent++;
        return 0;
    }
}
