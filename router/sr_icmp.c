
#include "sr_icmp.h"
#include "sr_protocol.h"

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

void send_icmp_timeout(struct sr_instance * sr, 
                       uint8_t * buff, 
                       struct sr_if * requested_iface,
                       struct sr_if * incoming_iface) {

    sr_ethernet_hdr_t * old_eth_header = (sr_ethernet_hdr_t *)buff;

    size_t len = sizeof(sr_ethernet_hdr_t) + 
        sizeof(sr_ip_hdr_t) + 
        sizeof(struct sr_icmp_t3_hdr);

    uint8_t * packet;
    sr_ip_hdr_t *ip_header;
    sr_icmp_t3_hdr_t *icmp_header;
    
    /* allocate memory for packet */
    packet = (uint8_t *)calloc(1, len);
    
    /* point the header structs */
    sr_ethernet_hdr_t * eth_header = (sr_ethernet_hdr_t *)packet;
    ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    icmp_header = (struct sr_icmp_t3_hdr *)
        (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    
    /* populate source / dest ip addresses, copy previous info */
    sr_ip_hdr_t * old_ip_header = (sr_ip_hdr_t *)(buff + sizeof(sr_ethernet_hdr_t));

    /* memcpy(ip_header, old_ip_header, sizeof(sr_ip_hdr_t)); */
    printf("ip header length: %lu\n", sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    printf("ip header length icmp: %lu\n", sizeof(sr_icmp_t3_hdr_t));

    /* ip header */
    ip_header->ip_dst = old_ip_header->ip_src;
    ip_header->ip_src = incoming_iface->ip;
    ip_header->ip_ttl = 64;
    ip_header->ip_sum = 0; 
    ip_header->ip_id  = 0;
    ip_header->ip_tos = 0;
    ip_header->ip_hl  = 5;
    ip_header->ip_v   = 4;
    ip_header->ip_off = htons(IP_DF);
    ip_header->ip_p   = ip_protocol_icmp;
    ip_header->ip_len = htons(sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t));
    
    /* populate icmp headers */
    printf("old ip header\n");

    memcpy(icmp_header->data, old_ip_header, ICMP_DATA_SIZE);
    icmp_header->icmp_type   = 11; /* unreachable */
    icmp_header->icmp_code   = 0;  /* ttl exceeded */
    icmp_header->unused      = 0;
    icmp_header->next_mtu    = 0;
    icmp_header->icmp_sum    = 0;

    ip_header->ip_sum        = cksum(packet + 
                                 sizeof(sr_ethernet_hdr_t),  
                                 sizeof(sr_ip_hdr_t));
    
    icmp_header->icmp_sum    = cksum(packet + 
                                     sizeof(sr_ethernet_hdr_t) + 
                                     sizeof(sr_ip_hdr_t), 
                                     sizeof(sr_icmp_t3_hdr_t));
 
    /* set up ethernet frame */
    eth_header->ether_type = htons(ethertype_ip);
    memcpy(eth_header->ether_shost, old_eth_header->ether_dhost, ETHER_ADDR_LEN);
    memcpy(eth_header->ether_dhost, old_eth_header->ether_shost,    ETHER_ADDR_LEN);

    print_hdrs(packet, len);

    sr_print_if(incoming_iface);

    sr_send_packet(sr, packet, len, incoming_iface->name);  

    printf("Sent timeout icmp message\n");

    /* freeing this packet */
    free(packet);
}

void send_icmp_echo(struct sr_instance * sr, 
                    uint8_t * packet, 
                    struct sr_if *requested_iface,
                    struct sr_if *incoming_iface) {

    /* size_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t); */

    uint8_t *          new_packet;
    sr_ethernet_hdr_t *eth_header,  *old_eth_header = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t       *ip_header, * old_ip_header;
    sr_icmp_t3_hdr_t  *icmp_header;

    printf("this is global: %d", globalLength);

    new_packet = (uint8_t *)calloc(1, globalLength);      /* allocate memory for packet */
    memcpy(new_packet, packet, globalLength);             /* new packet */
        
    /* point the header structs */
    eth_header = (sr_ethernet_hdr_t *)new_packet;
    ip_header = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
    icmp_header = (sr_icmp_t3_hdr_t *) (new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    printf("printing old ip header\n");
    print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));

    old_ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    printf("checksum before %d\n", old_ip_header->ip_sum);

    /* http://www.ietf.org/rfc/rfc792.txt */
    ip_header->ip_dst = old_ip_header->ip_src;
    ip_header->ip_src = old_ip_header->ip_dst;
    /* ip_header->ip_sum = 0; */
    /* ip_header->ip_sum = cksum(new_packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t)); */

    printf("checksum after %d\n", ip_header->ip_sum);

    /* populate icmp headers */
    /* http://www.networksorcery.com/enp/protocol/icmp/msg0.htm */

    icmp_header->icmp_type = 0; /* reply */
    icmp_header->icmp_code = 0; /* reply */
    /* icmp_header->unused = 0; /\* reply *\/ */
    icmp_header->icmp_sum = cksum(new_packet 
                                  + sizeof(sr_ethernet_hdr_t) 
                                  + sizeof(sr_ip_hdr_t), 
                                  globalLength - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
    
    /* set up ethernet frame */
    eth_header->ether_type = htons(ethertype_ip);
    printf("printing incoming interface\n");
    sr_print_if(incoming_iface);
    memcpy(eth_header->ether_shost, incoming_iface->addr, ETHER_ADDR_LEN);
    memcpy(eth_header->ether_dhost, old_eth_header->ether_shost, ETHER_ADDR_LEN);

    /* print before send */
    printf("ECHO!!!\n");
    print_hdrs(new_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

    /* send */
    sr_send_packet(sr, new_packet, globalLength, incoming_iface->name);  
    
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

void send_icmp_host_unreachable(struct sr_instance *sr, 
                                struct sr_packet *p) {

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
	icmp_header = (sr_icmp_t3_hdr_t *)
            (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /* populate source / dest ip addresses, copy previous info */
        old_ip_header = (sr_ip_hdr_t *)(p->buf + sizeof(sr_ethernet_hdr_t));
        
        memcpy(ip_header, old_ip_header, sizeof(sr_ip_hdr_t));
        
        ip_header->ip_dst = old_ip_header->ip_src;
        ip_header->ip_src = interface->ip;
        ip_header->ip_ttl = 64;        
        
        /* populate icmp headers */
        ip_header->ip_sum = 0; 
        ip_header->ip_id  = 0;
        ip_header->ip_tos = 0;
        ip_header->ip_hl  = 5;
        ip_header->ip_v   = 4;
        ip_header->ip_off = htons(IP_DF);
        ip_header->ip_p   = ip_protocol_icmp;
        ip_header->ip_len = htons(sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t));

        memcpy(icmp_header->data, old_ip_header, ICMP_DATA_SIZE);
        icmp_header->icmp_type   = 3; 
        icmp_header->icmp_code   = 1;
        icmp_header->unused      = 0;
        icmp_header->next_mtu    = 0;
        icmp_header->icmp_sum    = 0;
        
        ip_header->ip_sum        = cksum(packet + 
                                         sizeof(sr_ethernet_hdr_t),  
                                         sizeof(sr_ip_hdr_t));
        
        icmp_header->icmp_sum    = cksum(packet + 
                                     sizeof(sr_ethernet_hdr_t) + 
                                     sizeof(sr_ip_hdr_t), 
                                     sizeof(sr_icmp_t3_hdr_t));

        /* set up ethernet frame */
        eth_header->ether_type = htons(ethertype_ip);
        memcpy(eth_header->ether_shost, interface->addr, ETHER_ADDR_LEN);
        memcpy(eth_header->ether_dhost, old_eth_header->ether_dhost, 
               ETHER_ADDR_LEN);
    
        /* send */
        sr_send_packet(sr, packet, len, p->iface);  
        printf("Sent host unreachable icmp packet\n");

        free(packet);
}

void send_icmp_net_unreachable(struct sr_instance *sr, 
                               uint8_t * buff,
                               struct sr_if *requested_iface, 
                               struct sr_if *incoming_iface) {

    sr_ethernet_hdr_t * old_eth_header = (sr_ethernet_hdr_t *)buff;

    size_t len = sizeof(sr_ethernet_hdr_t) + 
        sizeof(sr_ip_hdr_t) + 
        sizeof(struct sr_icmp_t3_hdr);

    uint8_t * packet;
    sr_ip_hdr_t *ip_header;
    sr_icmp_t3_hdr_t *icmp_header;
    
    /* allocate memory for packet */
    packet = (uint8_t *)calloc(1, len);
    
    /* point the header structs */
    sr_ethernet_hdr_t * eth_header = (sr_ethernet_hdr_t *)packet;
    ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    icmp_header = (struct sr_icmp_t3_hdr *)
        (packet + sizeof(sr_ethernet_hdr_t) +
         sizeof(sr_ip_hdr_t));
    
    /* populate source / dest ip addresses, copy previous info */
    sr_ip_hdr_t * old_ip_header = (sr_ip_hdr_t *)(buff + sizeof(sr_ethernet_hdr_t));

    /* memcpy(ip_header, old_ip_header, sizeof(sr_ip_hdr_t)); */
    printf("ip header length: %lu\n", sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    printf("ip header length icmp: %lu\n", sizeof(sr_icmp_t3_hdr_t));

    /* ip header */
    ip_header->ip_dst = old_ip_header->ip_src;
    ip_header->ip_src = incoming_iface->ip;
    ip_header->ip_ttl = 64;
    ip_header->ip_sum = 0; 
    ip_header->ip_id  = 0;
    ip_header->ip_tos = 0;
    ip_header->ip_hl  = 5;
    ip_header->ip_v   = 4;
    ip_header->ip_off = htons(IP_DF);
    ip_header->ip_p   = ip_protocol_icmp;
    ip_header->ip_len = htons(sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t));
    
    /* populate icmp headers */
    printf("old ip header\n");

    memcpy(icmp_header->data, old_ip_header, ICMP_DATA_SIZE);
    icmp_header->icmp_type   = 3; /* unreachable */
    icmp_header->icmp_code   = 0; /* net unreachable */
    icmp_header->unused      = 0;
    icmp_header->next_mtu    = 0;
    icmp_header->icmp_sum    = 0;

    ip_header->ip_sum        = cksum(packet + 
                                 sizeof(sr_ethernet_hdr_t),  
                                 sizeof(sr_ip_hdr_t));
    
    icmp_header->icmp_sum    = cksum(packet + 
                                     sizeof(sr_ethernet_hdr_t) + 
                                     sizeof(sr_ip_hdr_t), 
                                     sizeof(sr_icmp_t3_hdr_t));
 
    /* set up ethernet frame */
    eth_header->ether_type = htons(ethertype_ip);
    memcpy(eth_header->ether_shost, old_eth_header->ether_dhost, ETHER_ADDR_LEN);
    memcpy(eth_header->ether_dhost, old_eth_header->ether_shost,    ETHER_ADDR_LEN);

    print_hdrs(packet, len);

    sr_print_if(incoming_iface);

    sr_send_packet(sr, packet, len, incoming_iface->name);  

    printf("Sent net unreachable icmp packet\n");

    /* freeing this packet */
    free(packet);
}

void send_icmp_port_unreachable(struct sr_instance *sr, 
                                uint8_t * buff, 
                                struct sr_if *requested_iface, 
                                struct sr_if *incoming_iface) {

    sr_ethernet_hdr_t * old_eth_header = (sr_ethernet_hdr_t *)buff;

    size_t len = sizeof(sr_ethernet_hdr_t) + 
        sizeof(sr_ip_hdr_t) + 
        sizeof(struct sr_icmp_t3_hdr);

    uint8_t * packet;
    sr_ip_hdr_t *ip_header;
    sr_icmp_t3_hdr_t *icmp_header;
    
    /* allocate memory for packet */
    packet = (uint8_t *)calloc(1, len);
    
    /* point the header structs */
    sr_ethernet_hdr_t * eth_header = (sr_ethernet_hdr_t *)packet;
    ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    icmp_header = (struct sr_icmp_t3_hdr *)
        (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    
    /* populate source / dest ip addresses, copy previous info */
    sr_ip_hdr_t * old_ip_header = (sr_ip_hdr_t *)(buff + sizeof(sr_ethernet_hdr_t));

    /* ip header */
    ip_header->ip_dst = old_ip_header->ip_src;
    ip_header->ip_src = incoming_iface->ip;
    ip_header->ip_ttl = 64;
    ip_header->ip_sum = 0; 
    ip_header->ip_id  = 0;
    ip_header->ip_tos = 0;
    ip_header->ip_hl  = 5;
    ip_header->ip_v   = 4;
    ip_header->ip_off = htons(IP_DF);
    ip_header->ip_p   = ip_protocol_icmp;
    ip_header->ip_len = htons(sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t));
    

    memcpy(icmp_header->data, old_ip_header, ICMP_DATA_SIZE);
    icmp_header->icmp_type   = 3; /* unreachable */
    icmp_header->icmp_code   = 3; /* port unreachable */
    icmp_header->unused      = 0;
    icmp_header->next_mtu    = 0;
    icmp_header->icmp_sum    = 0;

    ip_header->ip_sum        = cksum(packet + 
                                 sizeof(sr_ethernet_hdr_t),  
                                 sizeof(sr_ip_hdr_t));
    
    icmp_header->icmp_sum    = cksum(packet + 
                                     sizeof(sr_ethernet_hdr_t) + 
                                     sizeof(sr_ip_hdr_t), 
                                     sizeof(sr_icmp_t3_hdr_t));
 
    /* set up ethernet frame */
    eth_header->ether_type = htons(ethertype_ip);
    memcpy(eth_header->ether_shost, old_eth_header->ether_dhost, ETHER_ADDR_LEN);
    memcpy(eth_header->ether_dhost, old_eth_header->ether_shost, ETHER_ADDR_LEN);

    print_hdrs(packet, len);

    sr_print_if(incoming_iface);

    sr_send_packet(sr, packet, len, incoming_iface->name);  

    printf("Sent port unreachable icmp packet\n");

    /* freeing this packet */
    free(packet);
}

int is_icmp(uint8_t * buf){
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));
    return ip_proto == ip_protocol_icmp;
}
