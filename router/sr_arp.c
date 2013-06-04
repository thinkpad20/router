
#include "sr_arp.h"

/* function to process arp requests and replies */
void process_arp(struct sr_instance * sr, uint8_t * packet, int packet_len, int min_length){
    sr_arp_hdr_t * arp_packet = (sr_arp_hdr_t *)(packet + min_length);
    switch (ntohs(arp_packet->ar_op)){
    case arp_op_request:
        printf("this is an op request\n");
	handle_arp_request(sr, arp_packet, packet_len, packet);
	break;
    case arp_op_reply:
        printf("this is an op reply\n");
	break;
    }
    return;
}


void send_arp_reply(sr_instance_t *  sr, 
                    sr_if * interface, 
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

void handle_arp_request(struct sr_instance *  sr, sr_arp_hdr_t * arp_hdr, int len, uint8_t * packet){
    /* In the case of an ARP request, you should only send an ARP reply
       if the target IP address is one of your router's IP addresses. */
    /* ARP replies are sent directly to the requester's MAC address. */
    sr_if * interface;
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
