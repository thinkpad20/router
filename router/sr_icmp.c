
#include "sr_icmp.h"

int is_icmp_cksum_valid(uint8_t * packet, int len){
    return 1;
}

int send_icmp(int type, int code, uint8_t * packet, int len){
    return 1;
}

int is_icmp(uint8_t * packet, int len){
    return 1;
}
