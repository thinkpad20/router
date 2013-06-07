
#include "sr_helpers.h"

int check_eth_packet(int len, int min_length){
    if (len < min_length) { printf("error eth packet too small\n");  return 0;   }
    return 1;
}

int longest_match(char * x, char * dest){
    int i = 0;
    while (x[i] == dest[i])
        i++;
    return i;
}

struct sr_if *find_longest_prefix_match_interface(struct sr_instance * instance, 
                                                  uint32_t dest) {
    struct sr_if * runner          = instance->if_list,                                                                                                         
                 * longest         = NULL;                                                                                                                      
    size_t  long_match             = 0,                                                                                                                                   
            current_match_size     = 0;                                                                                                                                   
                                                                                                                                                             
    while (runner) {                                                                                                                                           
        current_match_size = longest_match((char *)&runner->ip, (char *)&dest);                                                                               
        if (long_match < current_match_size){                                                                                                                 
            longest        = runner;                                                                                                                          
            long_match  = current_match_size;                                                                                                                 
        }                                                                                                                                                     
        runner = runner->next;
    }
    return longest;
}

struct sr_rt * find_longest_prefix_match(struct sr_instance * instance, uint32_t dest){
    struct sr_rt * runner        = instance->routing_table,
                 * longest       = NULL;
    int     long_match = 0,
    current_match_size = 0;

    while (runner) {
    	current_match_size = longest_match((char *)&runner->dest.s_addr, (char *)&dest);
        if (long_match < current_match_size) {
    	    longest        = runner;
    	    long_match     = current_match_size;
        }
    	runner = runner->next;
    }
    return longest;
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

struct sr_if * get_router_interface_by_ip(struct sr_instance * sr, uint32_t tip){
    struct sr_if * runner = sr->if_list;
    while (runner != NULL) {
        if (runner->ip == tip)
            return runner;
        runner = runner->next;
    }
    return NULL;
}



