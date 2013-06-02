
/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

/* typedefs */
typedef struct sr_if sr_if;
typedef struct sr_instance sr_instance_t;

/* prototype */
void process_arp(sr_instance_t *, uint8_t *, int, int);
void process_ip_packet(sr_instance_t *, char *, unsigned int);
sr_if * get_interface_by_ip(sr_instance_t *, uint32_t);
void handle_arp_request(sr_instance_t *,  sr_arp_hdr_t *, int, uint8_t *);
int is_icmp(uint8_t * packet, int len);
void handle_arp_reply(sr_instance_t *, sr_arp_hdr_t *);
int check_eth_packet(int, int);
int check_arp_packet(int, int);
void send_arp_reply(sr_instance_t *, sr_if *, sr_arp_hdr_t *); 
int check_ip_packet(int len, int min_length);

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

int check_eth_packet(int len, int min_length){
    if (len < min_length) {
        printf("error eth packet too small\n");
        return 0;
    }
    return 1;
}

int check_arp_packet(int len, int min_length){
    /* sanity check on arp packet */
    if (min_length + sizeof(sr_arp_hdr_t) < len){
        printf("too small to be a valid arp packet\n");
        return 0;
    }
    return 1;
}


int check_ip_packet(int len, int min_length){
    /* sanity check on arp packet */
    if (min_length + sizeof(sr_ip_hdr_t) < len){
        printf("too small to be a valid ip packet\n");
        return 0;
    }
    return 1;
}


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
           "*                                                         *\n"
           "**               HANDLING A NEW PACKET                   **\n"
           "*                                                         *\n"
           "***********************************************************\n");
    print_hdrs(packet, len);

    /* sanity check on eth packet */
    int min_length = sizeof(sr_ethernet_hdr_t);
    if (!check_eth_packet(len, min_length))
        return;

    /* switch on eth type if passes sanity check */
    switch (ethertype(packet)){

    case ethertype_arp:

        /* sanity chck on arp packet */
        if (!check_arp_packet(len, min_length))
            return;

        /* if passes process */
        printf("processing arp packet\n");
	process_arp(sr, packet, len, min_length); 

    	break;
    case ethertype_ip:

        /* sanity check on ip packet */

        if (is_icmp(packet, len)){
            printf("this is an icmp\n");
        } else {
            printf("this is not an icmp packet\n");
            /*            process_ip_packet(sr, packet, len); */
        }
    	break;
    default: /* if unknow, this is an error, send ICMP of 'unreachable' */
    	break;
    }
}

int is_icmp(uint8_t * packet, int len){
    uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
    if (ip_proto == ip_protocol_icmp)  /* ICMP */
        return 1;
    return 0;
    /*   minlength += sizeof(sr_icmp_hdr_t); */
    /*   if (length < minlength) */
    /*     fprintf(stderr, "Failed to print ICMP header, insufficient length\n"); */
    /*   else */
    /*     print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)); */
    /* } */
}


struct sr_if * get_router_interface_by_ip(struct sr_instance * sr, uint32_t tip){
    struct sr_if * runner = sr->if_list;
    while (runner != NULL){
        if (runner->ip == tip)
            return runner;
        runner = runner->next;
    }
    return NULL;
}

struct sr_if * get_foreign_interface_by_ip(struct sr_instance * sr, uint32_t tip){
    struct sr_rt * runner = sr->routing_table;
    char buff[INET_ADDRSTRLEN];
    printf("ip is %u (%s) \n", tip, inet_ntop(AF_INET, &tip, buff, INET_ADDRSTRLEN));

    while (runner != NULL) {
        sr_print_routing_entry(runner);
	if (runner->dest.s_addr == tip) {
            printf("found a matching entry in the routing table\n"
                   "entry interface is %s\n", runner->interface);
	    return sr_get_interface(sr, runner->interface);
        }
        runner = runner->next;
    }
    printf("did not match any entry in our routing table\n");
    return NULL;
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

/****************************************************************/
/* int sr_send_packet(struct sr_instance* sr /\* borrowed *\/,  */
/*                          uint8_t* buf /\* borrowed *\/ ,     */
/*                          unsigned int len,                   */
/*                          const char* iface /\* borrowed *\/) */
/****************************************************************/

    sr_send_packet(sr, new_packet, size, interface->name);
    printf("sent\n");
    free(new_packet); /* lookup freeing? */
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
        printf("foreign interface\n");
        sr_print_if(interface);        
        send_arp_reply(sr, interface, arp_hdr);
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

/* void handle_arp_reply(sr_arp_hdr_t * arp_header){ */
/*     char * payload = arp_packet + sizeof(sr_arp_hdr_t); */
/*     /\* if we get a arp reply not meant for us, throw away *\/ */
/* } */

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
        /*	handle_arp_reply(sr, arp_packet); */
	break;
    }
    return;
  }

/* /\* struct sr_ip_hdr *\/ */
/* /\*   { *\/ */
/* /\* #if __BYTE_ORDER == __LITTLE_ENDIAN *\/ */
/* /\*     unsigned int ip_hl:4;		/\\* header length *\\/ *\/ */
/* /\*     unsigned int ip_v:4;		/\\* version *\\/ *\/ */
/* /\* #elif __BYTE_ORDER == __BIG_ENDIAN *\/ */
/* /\*     unsigned int ip_v:4;		/\\* version *\\/ *\/ */
/* /\*     unsigned int ip_hl:4;		/\\* header length *\\/ *\/ */
/* /\* #else *\/ */
/* /\* #error "Byte ordering ot specified "  *\/ */
/* /\* #endif  *\/ */
/* /\*     uint8_t ip_tos;			/\\* type of service *\\/ *\/ */
/* /\*     uint16_t ip_len;			/\\* total length *\\/ *\/ */
/* /\*     uint16_t ip_id;			/\\* identification *\\/ *\/ */
/* /\*     uint16_t ip_off;			/\\* fragment offset field *\\/ *\/ */
/* /\* #define	IP_RF 0x8000			/\\* reserved fragment flag *\\/ *\/ */
/* /\* #define	IP_DF 0x4000			/\\* dont fragment flag *\\/ *\/ */
/* /\* #define	IP_MF 0x2000			/\\* more fragments flag *\\/ *\/ */
/* /\* #define	IP_OFFMASK 0x1fff		/\\* mask for fragmenting bits *\\/ *\/ */
/* /\*     uint8_t ip_ttl;			/\\* time to live *\\/ *\/ */
/* /\*     uint8_t ip_p;			/\\* protocol *\\/ *\/ */
/* /\*     uint16_t ip_sum;			/\\* checksum *\\/ *\/ */
/* /\*     uint32_t ip_src, ip_dst;	/\\* source and dest address *\\/ *\/ */
/* /\*   } __attribute__ ((packed)) ; *\/ */
/* /\* typedef struct sr_ip_hdr sr_ip_hdr_t; *\/ */

/* sr_ip_hdr_t * sanity_check(char * ip_packet_str, size_t len){ */

/*     /\* Sanity-check the packet (meets minimum length and has correct checksum). *\/ */
/*     /\* uint16_t cksum (const void *_data, int len) *\/ */

/*     sr_ip_hdr_t * ip_header       = (sr_ip_hdr_t *)ip_packet_str;	 */
/*     unsigned int ip_packet_length = len - sizeof(ether_addr_len); */

/*     if (ip_packet_length < sizeof(sr_ip_hdr_t))  */
/* 	return NULL; */

/*     if (cksum(ip_packet_str, ip_packet_length) != ip_hdr->ip_sum) */
/* 	return NULL; */
	

/*     return ip_header;	 */
/* } */

/* int longest_match(char * x, char * dest){ */
/*     int i = 0; */
/*     while (x[i] == dest[i]) */
/* 	i++; */
/*     return i; */
/* } */

/* sr_rt * find_longest_prefix_match(struct sr_instance * instance, uint32_t dest){ */
/*     sr_rt * runner        = instance->routing_table,  */
/*             longest       = NULL; */
/*     int     longest_match = 0; */

/*     while (runner){ */
/* 	int current_match_size = longest_match((char *)&runner->dest->s_addr, (char *)&dest); */
/*         if (longest_match < curent_match_size) */
/* 	    longest        = runner; */
/* 	    longest_match  = current_match_size; */
/* 	} */
/* 	runner = runner->next; */
/*     } */
/*     return longest; */
/* } */


/* function to process ip requests and replies */
void process_ip_packet(struct sr_instance * instance, char * ip_packet_str, unsigned int len){
    sr_ip_hdr_t * ip_header = sanity_check(ip_packet_str, len);
    if (ip_header) {
	if_sr * interface = in_foreign_interface_list(instance, ip_header->ip_dst);
        /* if the frame contains an IP packet that is not destined towards one of our interfaces */
	if (interface){

	    /* decrement ttl by 1*/
	    ip_header->ip_ttl--;

	    /* recompute packet checksum over modified header */
	    ip_header->ip_sum = cksum(ip_packet_str, ip_packet_length);
	    
	    /* find which entry in the routing table has the longest prefix match with the destination IP address */
	    /* struct sr_rt* routing_table; -- routing table */
	    sr_rt * match = find_longest_prefix_match(instance, ip_header->ip_dst);


	}

	
    } else {
	// packet does not pass sanity check, send icmp error?
    }


    /* if the frame contains an IP packet that is not destined towards one of our interfaces */
    if (interface == NULL){
	/* sanity check */

    }

      /* process ip */
      
      return;
  }




/*   /\* fill in code here *\/ */
/*   // Is this an IP Requst? */
/*      // CASE: ARP Request, Find all packets waiting on this request, update their dest. addr, send them out. */
/*      // CASE: TCP/UDP packet, drop packet, send back ICMP "HOST UNREACHABLE MESSAGE" */
/*   // If this is an ICMP ping */
/*      //If this is a PING (respond appropriately) */
/*      //If this is a ECHO (respond appropriately) */
/*   // If this is a  */




/* end sr_ForwardPacket */

