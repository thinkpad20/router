
#include "sr_icmp.h"

int is_icmp_cksum_valid(uint8_t * packet, int len){
    return 1;
}

void send_icmp_host_unreachable(struct sr_instance *t, struct sr_packet *p) {
	size_t len = sizeof(sr_ethernet_hdr_t) 
				+ sizeof(sr_ip_hdr_t)
				+ sizeof(struct sr_icmp_t3_hdr);
	uint8_t *packet;
	sr_ethernet_hdr_t *eth_header, 
					  *old_eth_header = (sr_ethernet_hdr_t *)p->buf;
	sr_ip_hdr_t *ip_header;
	struct sr_icmp_t3_hdr *icmp_header;

	/* allocate memory for packet */
	packet = (uint8_t *)calloc(1, len);

	/* point the header structs */
	eth_header = (sr_ethernet_hdr_t *)packet;
	ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	icmp_header = (struct sr_icmp_t3_hdr *)(packet + sizeof(sr_ethernet_hdr_t) 
										   + sizeof(sr_ip_hdr_t));

	/* set up ethernet frame */
	eth_header->ether_type = htons(ethertype_ip);
	/*memcpy(eth_header->ether_shost, p->iface->addr, ETHER_ADDR_LEN);*/
	memcpy(eth_header->ether_dhost, old_eth_header->ether_dhost, ETHER_ADDR_LEN);

}

int is_icmp(uint8_t * packet, int len){
    return 1;
}
