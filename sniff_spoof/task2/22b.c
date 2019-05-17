#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include "header.h"

#define IP_SRC "10.0.2.6"
#define IP_DST "10.131.250.58"

unsigned short checksum(unsigned short *buffer, int size){
    int checksum = 0;
    while(size>1){
        checksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if(size){
        checksum += *(unsigned char*)buffer;
    }
    checksum = (checksum>>16) + (checksum & 0xffff);
    checksum += (checksum>>16);
    return (unsigned short)(~checksum);
}

int main(){
    int sd;
    int len = 0;
    struct sockaddr_in sin;
    char buffer[1024];

    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd < 0) {
        perror("socket() error"); 
        exit(-1); 
    }
    sin.sin_family = AF_INET;

    struct ipheader *ip = (struct ipheader *) buffer;
    struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
    struct in_addr *ip_src = (struct in_addr *)malloc(sizeof(struct in_addr));
    struct in_addr *ip_dst = (struct in_addr *)malloc(sizeof(struct in_addr));
    inet_aton(IP_SRC,ip_src);
    inet_aton(IP_DST,ip_dst);

    len += sizeof(struct icmpheader);
    icmp->icmp_type = 8;
    icmp->icmp_code = 0;
    icmp->icmp_chksum = 0;
    icmp->icmp_id = htons(0x1234); // A real ping should apply the last few bits of pid here
    icmp->icmp_seq = htons(1);
    icmp->icmp_chksum = checksum((unsigned short *)icmp, sizeof(struct icmpheader)); 
    // icmp->icmp_data[0] = htonl(0x08090a0b);
    // icmp->icmp_data[1] = htonl(0x0c0d0e0f);
    // icmp->icmp_data[2] = htonl(0x10111213);
    // icmp->icmp_data[3] = htonl(0x14151617);
    // icmp->icmp_data[4] = htonl(0x18191a1b);
    // icmp->icmp_data[5] = htonl(0x1c1d1e1f);
    // icmp->icmp_data[6] = htonl(0x20212223);
    // icmp->icmp_data[7] = htonl(0x24252627);
    // icmp->icmp_data[8] = htonl(0x28292a2b);
    // icmp->icmp_data[9] = htonl(0x2c2d2e2f);
    // icmp->icmp_data[10] = htonl(0x30313233);
    // icmp->icmp_data[11] = htonl(0x34353637);

    len += sizeof(struct ipheader);
    ip->iph_ihl = 5; // header in 4 bytes
    ip->iph_ver = 4;
    ip->iph_tos = 0;
    ip->iph_len = htons(len); // header and data in bytes
    ip->iph_ident = htons(0x1000);
    ip->iph_flag = 0;
    ip->iph_offset = 0;
    ip->iph_ttl = 64;
    ip->iph_protocol = ICMP_PROTOCOL_NUM;
    ip->iph_chksum = htons(0);
    ip->iph_sourceip = *ip_src;
    ip->iph_destip = *ip_dst;

    if(sendto(sd, buffer, len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto() error"); exit(-1); 
    }
}
