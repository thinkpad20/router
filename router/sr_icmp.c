
#include "sr_icmp.h"

int is_icmp_cksum_valid(uint8_t * packet, uint32_t len) {

    /* size helpers */
    size_t eth_size  = sizeof(sr_ethernet_hdr_t);
    size_t ip_size   = sizeof(sr_ip_hdr_t);

    /* get icmp packet  */
    sr_icmp_hdr_t * icmp_packet = (sr_icmp_hdr_t * )(packet + eth_size + ip_size);

    /* set temp variable to current icmp sum */
    uint16_t temp = icmp_packet->icmp_sum;

    /* zero out icmp_sum */
    icmp_packet->icmp_sum = 0;

    /* get length of icmp packet */
   /* validity check */
    uint16_t newcksum = 
        cksum(packet + eth_size + ip_size, len - (eth_size + ip_size));
    uint16_t other    = 
        cksum(packet + eth_size + ip_size, len - (eth_size + ip_size));

    /* new checksum */
    printf("temp: %d\n",                 temp);
    printf("new checksum t3 %d\n",       newcksum);
    printf("new checksum t-normal %d\n", other);

   if (cksum(packet + eth_size + ip_size, len - (eth_size + ip_size)) == temp){
       icmp_packet->icmp_sum = cksum(packet + eth_size + ip_size, len - (eth_size+ip_size));
       return 1;
   }

    printf("ICMP checksum is invalid\n");
    return 0;
}

void send_icmp_timeout(struct sr_instance * sr, uint8_t * packet, struct sr_if * interface) {
	uint32_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
	uint8_t *new_packet;

	sr_ethernet_hdr_t *eth_header, 
            *old_eth_header = (sr_ethernet_hdr_t *)packet;

	sr_ip_hdr_t *ip_header, * old_ip_header;
	sr_icmp_t3_hdr_t *icmp_header;

	/* allocate memory for packet */
	new_packet = (uint8_t *)calloc(1, len);
 
	/* point the header structs */
	eth_header = (sr_ethernet_hdr_t *)new_packet;
	ip_header = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
	icmp_header = (sr_icmp_t3_hdr_t *)
            (new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /* populate source / dest ip addresses, copy previous info */
        old_ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

        memcpy(ip_header, old_ip_header, sizeof(sr_ip_hdr_t));
        
        ip_header->ip_dst = old_ip_header->ip_src;
        ip_header->ip_src = interface->ip;
        ip_header->ip_ttl = 64;

        /* populate icmp headers */
        icmp_header->icmp_type = 11; /* reply */
        icmp_header->icmp_code = 0;  /* reply */

        icmp_header->icmp_sum = cksum(new_packet + 
                                      sizeof(sr_ethernet_hdr_t) + 
                                      sizeof(sr_ip_hdr_t), len -
                                      (sizeof(sr_ethernet_hdr_t) + 
                                       sizeof(sr_ip_hdr_t)));
        
	/* set up ethernet frame */
	eth_header->ether_type = htons(ethertype_ip);
	memcpy(eth_header->ether_shost, interface->addr, ETHER_ADDR_LEN);
	memcpy(eth_header->ether_dhost, 
               old_eth_header->ether_dhost, 
               ETHER_ADDR_LEN);

        /* send */
        sr_send_packet(sr, new_packet, len, interface->name);  
        printf("Sent icmp timeout\n");

        free(new_packet);
}


void send_icmp_echo(struct sr_instance * sr, uint8_t * packet, struct sr_if * interface){
	size_t len = sizeof(sr_ethernet_hdr_t) 
				+ sizeof(sr_ip_hdr_t)
				+ sizeof(sr_icmp_t3_hdr_t);
	uint8_t * new_packet;
	sr_ethernet_hdr_t *eth_header, 
        *old_eth_header = (sr_ethernet_hdr_t *)packet;

	sr_ip_hdr_t *ip_header, * old_ip_header;
	sr_icmp_t3_hdr_t *icmp_header;

	/* allocate memory for packet */
	new_packet = (uint8_t *)calloc(1, len);
 
	/* point the header structs */
	eth_header = (sr_ethernet_hdr_t *)new_packet;
	ip_header = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
	icmp_header = (sr_icmp_t3_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* populate source / dest ip addresses, copy previous info */
    old_ip_header = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));

    memcpy(ip_header, old_ip_header, sizeof(sr_ip_hdr_t));
    
    ip_header->ip_dst = old_ip_header->ip_src;
    ip_header->ip_src = interface->ip;
    ip_header->ip_ttl = 64;


    /* populate icmp headers */
    /* http://www.networksorcery.com/enp/protocol/icmp/msg0.htm */
    icmp_header->icmp_type = 0; /* reply */
    icmp_header->icmp_code = 0; /* reply */

    icmp_header->icmp_sum = cksum(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), sizeof(sr_icmp_t3_hdr_t));
    
	/* set up ethernet frame */
	eth_header->ether_type = htons(ethertype_ip);
	memcpy(eth_header->ether_shost, interface->addr, ETHER_ADDR_LEN);
	memcpy(eth_header->ether_dhost, old_eth_header->ether_dhost, ETHER_ADDR_LEN);

    /* send */
    sr_send_packet(sr, new_packet, len, interface->name);  
    printf("Sent icmp echo reply\n");

    free(new_packet);
}


int is_icmp_echo(uint8_t * packet) {

   /* size helpers */
    size_t eth_size = sizeof(sr_ethernet_hdr_t);
    size_t ip_size = sizeof(sr_ip_hdr_t);

    /* get icmp packet  */
    sr_icmp_t3_hdr_t * icmp_packet = (sr_icmp_t3_hdr_t * )
        (packet + eth_size + ip_size);

    /*http://www.networksorcery.com/enp/protocol/icmp/msg8.htm*/
    /* good info on what an icmp echo request really is */

    printf("checking if is icmp echo and printing icmp packet\n");
    /* icmp echo request is code 0 and type 8 */
    
    print_hdr_icmp(packet + eth_size + ip_size);

    if (icmp_packet->icmp_code == 0 && icmp_packet->icmp_type == 8){
        printf("This is an ICMP echo request\n");
        print_hdr_icmp(packet + eth_size + ip_size);
        return 1;
    }
    return 0;
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
        ip_header->ip_ttl = 64;        

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

        free(packet);
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

        /* ip header */
        ip_header->ip_dst = old_ip_header->ip_src;
        ip_header->ip_src = interface->ip;
        ip_header->ip_ttl = 64;

        /* populate icmp headers */
        icmp_header->icmp_type   = unreachable_type;
        icmp_header->icmp_code   = port_code;
        icmp_header->icmp_sum  = cksum(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), sizeof(sr_icmp_t3_hdr_t));

	/* set up ethernet frame */
	eth_header->ether_type = htons(ethertype_ip);
	memcpy(eth_header->ether_shost, old_eth_header->ether_dhost, ETHER_ADDR_LEN);
	memcpy(eth_header->ether_dhost, old_eth_header->ether_shost, ETHER_ADDR_LEN);
        
        sr_send_packet(sr, packet, len, interface->name);  
        printf("Sent host unreachable icmp packet\n");
        /* freeing this packet */
        free(packet);
}

int is_icmp(uint8_t * buf){
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));
    return ip_proto == ip_protocol_icmp;
}
