
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

void sr_handlepacket(struct sr_instance* sr,
		     uint8_t * packet    /* lent */,
		     unsigned int len,
		     char* interface     /* lent */)
{
    /* payload */
    char * payload = packet + sizeof(sr_ethernet_hdr_t);

  /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);

    switch (ethertype(packet)){
    case ethertype_arp:
	process_arp(payload);
	break;
    case ethertype_ip:
	process_ip_packet(sr, payload, len);
	break;
    default: /* if unknow, this is an error, send ICMP of 'unreachable' */
	break;
    }
}

sr_if * in_interface_list(struct sr_instance * sr, uint32_t tip){
    sr_if * runner = sr->if_list;
    while (runner != NULL){
	if (runner->ip == tip)
	    return runner;
	runner = runner->next;
    }
    return NULL;
}

void send_arp_reply(struct sr_instance *  sr,  sr_if * interface, sr_arp_hdr_t * arp_packet){
    
    /* send arp packet */
    /* construct packet, malloc memory for packet */
    /* fill packet with relevant arp and ethernet data */
    size_t                   len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    char              *   packet = malloc(len);
    sr_ethernet_hdr_t * eth_head = (sr_ethernet_hdr_t *)packet;
    sr_arp_hdr_t      * arp_head = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* ------------ Populate ethernet header----------- */
    /* copy source hw addr to eth head dhost */
    memcpy(eth_head->ether_dhost, arp_packet->ar_sha, ETHER_ADDR_LEN);    

    /* copy interface mac addr to ether_shost*/
    memcpy(eth_head->ether_shost, interface->name,    ETHER_ADDR_LEN);    

    /* set ethernet type to arp req */
    eth_head->eth_type = ethertype_arp;                                   

    /* ------------- Populate arp header -------------- */
    memcpy(arp_head, arp_packet); 

    /* make arp reply */
    arp_head->ar_op  = arp_op_reply;                             

    /* take source ip from request and put it into target ip reply */
    arp_head->ar_tip = arp_packet->ar_sip;

    /* take source from request put in reply to target */
    memcpy(arp_head->ar_tha, arp_packet->ar_sha, ETHER_ADDR_LEN); 

    /* take source hw addr, put into thw addr */
    memcpy(arp_head->ar_sha, interface->name,    ETHER_ADDR_LEN);

    /* set source ip to be target ip */
    arp_head->ar_sip = arp_packet->tip;

    /*** send him on his way ***/
    sr_send_packet(sr, packet, len, sr_if->name);
    free(packet); /* lookup freeing? */
}

void handle_arp_request(struct sr_instance *  sr,  sr_arp_hdr_t * arp_packet){
    /* In the case of an ARP request, you should only send an ARP reply 
       if the target IP address is one of your router's IP addresses. */
    /* ARP replies are sent directly to the requester's MAC address. */
    
    sr_if * interface = interface_list(sr, arp_packet->tip);
    if (interface)
	send_arp_reply(sr, interface, arp_packet);
    /* else... what do I do if arp req is not in router interface list? */
}

void handle_arp_reply(sr_arp_hdr_t * arp_header){
    char * payload = arp_packet + sizeof(sr_arp_hdr_t);
    /* if we get a arp reply not meant for us, throw away */
}


  /* function to process arp requests and replies */
  void process_arp(char * arp_packet_str){
      sr_arp_hdr_t * arp_packet = (sr_arp_hdr_t *)arp_packet_str;
      switch (arp_packet->op_code){
      case arp_op_request:
	  handle_arp_request(arp_packet);
	  break;
      case arp_op_reply:
	  handle_arp_reply(arp_packet);
	  break;
      }
      return;
  }

/* struct sr_ip_hdr */
/*   { */
/* #if __BYTE_ORDER == __LITTLE_ENDIAN */
/*     unsigned int ip_hl:4;		/\* header length *\/ */
/*     unsigned int ip_v:4;		/\* version *\/ */
/* #elif __BYTE_ORDER == __BIG_ENDIAN */
/*     unsigned int ip_v:4;		/\* version *\/ */
/*     unsigned int ip_hl:4;		/\* header length *\/ */
/* #else */
/* #error "Byte ordering ot specified "  */
/* #endif  */
/*     uint8_t ip_tos;			/\* type of service *\/ */
/*     uint16_t ip_len;			/\* total length *\/ */
/*     uint16_t ip_id;			/\* identification *\/ */
/*     uint16_t ip_off;			/\* fragment offset field *\/ */
/* #define	IP_RF 0x8000			/\* reserved fragment flag *\/ */
/* #define	IP_DF 0x4000			/\* dont fragment flag *\/ */
/* #define	IP_MF 0x2000			/\* more fragments flag *\/ */
/* #define	IP_OFFMASK 0x1fff		/\* mask for fragmenting bits *\/ */
/*     uint8_t ip_ttl;			/\* time to live *\/ */
/*     uint8_t ip_p;			/\* protocol *\/ */
/*     uint16_t ip_sum;			/\* checksum *\/ */
/*     uint32_t ip_src, ip_dst;	/\* source and dest address *\/ */
/*   } __attribute__ ((packed)) ; */
/* typedef struct sr_ip_hdr sr_ip_hdr_t; */

sr_ip_hdr_t * sanity_check(char * ip_packet_str, len){

    /* Sanity-check the packet (meets minimum length and has correct checksum). */
    /* uint16_t cksum (const void *_data, int len) */

    sr_ip_hdr_t * ip_header       = (sr_ip_hdr_t *)ip_packet_str;	
    unsigned int ip_packet_length = len - sizeof(ether_addr_len);

    if (ip_packet_length < sizeof(sr_ip_hdr_t)) 
	return NULL;

    if (cksum(ip_packet_str, ip_packet_length) != ip_hdr->ip_sum)
	return NULL;
	

    return ip_header;	
}

int longest_match(char * x, char * dest){
    int i = 0;
    while (x[i] == dest[i])
	i++;
    return i;
}

sr_rt * find_longest_prefix_match(struct sr_instance * instance, uint32_t dest){
    sr_rt * runner        = instance->routing_table, 
            longest       = NULL;
    int     longest_match = 0;

    while (runner){
	int current_match_size = longest_match((char *)&runner->dest->s_addr, (char *)&dest);
        if (longest_match < curent_match_size)
	    longest        = runner;
	    longest_match  = current_match_size;
	}
	runner = runner->next;
    }
    return longest;
}


/* function to process arp requests and replies */
void process_ip_packet(struct sr_instance * instance, char * ip_packet_str, unsigned int len){
    sr_ip_hdr_t * ip_header = sanity_check(ip_packet_str, len);
    if (ip_header) {
	if_sr * interface = in_interface_list(instance, ip_header->ip_dst);
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




  /* fill in code here */
  // Is this an IP Requst?
     // CASE: ARP Request, Find all packets waiting on this request, update their dest. addr, send them out.
     // CASE: TCP/UDP packet, drop packet, send back ICMP "HOST UNREACHABLE MESSAGE"
  // If this is an ICMP ping
     //If this is a PING (respond appropriately)
     //If this is a ECHO (respond appropriately)
  // If this is a 




}/* end sr_ForwardPacket */

