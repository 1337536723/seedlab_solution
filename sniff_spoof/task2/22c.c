#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "header.h"

#define IP_SRC "10.0.2.7"
#define IP_DST "255.255.255.255"

unsigned short checksum(unsigned short *buffer, int size){
    int checksum = 0;
    while(size>1){
        checksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if(size){
        checksum += *(unsigned char *)buffer;
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
    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
    struct in_addr *ip_src = (struct in_addr *)malloc(sizeof(struct in_addr));
    struct in_addr *ip_dst = (struct in_addr *)malloc(sizeof(struct in_addr));
    inet_aton(IP_SRC,ip_src);
    inet_aton(IP_DST,ip_dst);

    len += sizeof(struct udpheader);
    udp->uh_sport = htons(55136);
    udp->uh_dport = htons(22313);
    udp->uh_len = htons(len); // header and data in bytes
    udp->uh_chksum = checksum((unsigned short *)udp, 6); 

    len += sizeof(struct ipheader);
    ip->iph_ihl = 5; // header in 4 bytes
    ip->iph_ver = 4;
    ip->iph_tos = 0;
    ip->iph_len = htons(20); // header and data in bytes
    ip->iph_ident = htons(0x1000);
    ip->iph_flag = 0;
    ip->iph_offset = 0;
    ip->iph_ttl = 64;
    ip->iph_protocol = UDP_PROTOCOL_NUM;
    ip->iph_chksum = htons(0);
    ip->iph_sourceip = *ip_src;
    ip->iph_destip = *ip_dst;

    if(sendto(sd, buffer, len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto() error"); exit(-1); 
    }
}
