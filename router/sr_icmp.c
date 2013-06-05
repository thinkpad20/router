
#include "sr_icmp.h"

int is_icmp_cksum_valid(uint8_t * packet, int len){
    return 1;
}

void send_icmp_host_unreachable(struct sr_instance *sr, struct sr_packet *p) {
	size_t len = sizeof(sr_ethernet_hdr_t) 
				+ sizeof(sr_ip_hdr_t)
				+ sizeof(sr_icmp_t3_hdr_t);
	uint8_t *packet;
	sr_ethernet_hdr_t *eth_header, 
            *old_eth_header = (sr_ethernet_hdr_t *)p->buf;

	sr_ip_hdr_t *ip_header, * old_ip_header;
	sr_icmp_t3_hdr_t *icmp_header;

	/* allocate memory for packet */
	packet = (uint8_t *)calloc(1, len);
        struct sr_if * interface = sr_get_interface(sr, p->iface);

	/* point the header structs */
	eth_header = (sr_ethernet_hdr_t *)packet;
	ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	icmp_header = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /* populate source / dest ip addresses, copy previous info */
        old_ip_header = (sr_ip_hdr_t *)(p->buf + 
                                        sizeof(sr_ethernet_hdr_t));

        memcpy(ip_header, old_ip_header, sizeof(sr_ip_hdr_t));
        
        ip_header->ip_dst = old_ip_header->ip_src;
        ip_header->ip_src = interface->ip;


        /* populate icmp headers */
        icmp_header->icmp_type = unreachable_type;
        icmp_header->icmp_code = host_code;
        icmp_header->icmp_sum = cksum(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), sizeof(sr_icmp_t3_hdr_t));

	/* set up ethernet frame */
	eth_header->ether_type = htons(ethertype_ip);
	memcpy(eth_header->ether_shost, interface->addr, ETHER_ADDR_LEN);
	memcpy(eth_header->ether_dhost, old_eth_header->ether_dhost, ETHER_ADDR_LEN);

        /* send */
        sr_send_packet(sr, packet, len, p->iface);  
        printf("Sent host unreachable icmp packet\n");
}

void send_icmp_port_unreachable(struct sr_instance *sr, uint8_t * buff, struct sr_if * interface) {
        sr_ethernet_hdr_t * old_eth_header = (sr_ethernet_hdr_t *)buff;
	size_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(struct sr_icmp_t3_hdr);
        uint8_t * packet;
	sr_ip_hdr_t *ip_header;
	sr_icmp_t3_hdr_t *icmp_header;

	/* allocate memory for packet */
	packet = (uint8_t *)calloc(1, len);

	/* point the header structs */
	sr_ethernet_hdr_t * eth_header = (sr_ethernet_hdr_t *)packet;
	ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	icmp_header = (struct sr_icmp_t3_hdr *)(packet + sizeof(sr_ethernet_hdr_t) 
                                                + sizeof(sr_ip_hdr_t));


        /* populate source / dest ip addresses, copy previous info */
        sr_ip_hdr_t * old_ip_header = (sr_ip_hdr_t *)(buff + 
                                        sizeof(sr_ethernet_hdr_t));

        memcpy(ip_header, old_ip_header, sizeof(sr_ip_hdr_t));
        
        ip_header->ip_dst = old_ip_header->ip_src;
        ip_header->ip_src = interface->ip;



        /* populate icmp headers */
        icmp_header->icmp_type = unreachable_type;
        icmp_header->icmp_code   = port_code;
        icmp_header->icmp_sum  = cksum(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), sizeof(sr_icmp_t3_hdr_t));

	/* set up ethernet frame */
	eth_header->ether_type = htons(ethertype_ip);
	memcpy(eth_header->ether_shost, old_eth_header->ether_dhost, ETHER_ADDR_LEN);
	memcpy(eth_header->ether_dhost, old_eth_header->ether_shost, ETHER_ADDR_LEN);
        
        sr_send_packet(sr, packet, len, interface->name);  
        printf("Sent host unreachable icmp packet\n");
}

int is_icmp(uint8_t * buf){
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));
    return ip_proto == ip_protocol_icmp;
}
