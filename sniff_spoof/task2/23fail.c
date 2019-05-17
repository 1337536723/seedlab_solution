#include <pcap.h>
#include <stdlib.h>
#include <time.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include "header.h"

#define MAX_CONN 100
#define MAX_TIMEOUT 30
/* global variant */

struct dict{   
    unsigned short seq; // seq
    int tim;            // time
}dicts[MAX_CONN];       // (ip1 + ip2) % MAX_CONN, simplistic pseudo-hash

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

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    /* old packet's architecture */
    time_t now;
    struct ethheader *oeth = (struct ethheader *)packet;
    if(ntohs(oeth->ether_type) != 0x0800) return;
    struct ipheader *oip = (struct ipheader *)(packet + sizeof(struct ethheader));
    if(oip->iph_protocol != ICMP_PROTOCOL_NUM) return;
    struct ficmpheader *oicmp = (struct ficmpheader *)(packet + sizeof(struct ethheader) + oip->iph_ihl * 4);

    printf("Src: %15s ", inet_ntoa(oip->iph_sourceip));
    printf("Dst: %15s\n", inet_ntoa(oip->iph_destip));

    now = time(NULL); 	
    int ti = time(&now);
    int index = (oip->iph_sourceip.s_addr + oip->iph_destip.s_addr) % MAX_CONN;
    if(dicts[index].tim > ti - 30)
        if(dicts[index].seq == oicmp->icmp_seq)
            return;
    dicts[index].tim = ti;
    dicts[index].seq = oicmp->icmp_seq;

    /* preparing for the new packet */
    int sd;
    int i, len = 0;
    struct sockaddr_in sin;
    char buffer[1024];

    // sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if(sd < 0) {
        perror("socket() error"); 
        exit(-1); 
    }
    sin.sin_family = AF_INET;

    struct ethheader *eth = (struct ethheader *) buffer;
    struct ipheader *ip = (struct ipheader *) (buffer + sizeof(struct ethheader));
    struct ficmpheader *icmp = (struct ficmpheader *)(buffer + sizeof(struct ethheader) + sizeof(struct ipheader));

    len += sizeof(struct ficmpheader);
    icmp->icmp_type = 0;
    icmp->icmp_code = 0;
    icmp->icmp_chksum = 0;
    icmp->icmp_id = oicmp->icmp_id;
    icmp->icmp_seq = oicmp->icmp_seq;
    for(i = 0; i < ICMP_DATA_LENGTH; i++){
         icmp->icmp_data[i] = oicmp->icmp_data[i];
    }
    icmp->icmp_chksum = checksum((unsigned short *)icmp, sizeof(struct ficmpheader));

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
    ip->iph_sourceip = oip->iph_destip;
    ip->iph_destip = oip->iph_sourceip;

    len += sizeof(struct ethheader);
    for(i = 0; i < ETHER_ADDR_LENGTH; i++){
        eth->ether_dhost[i] = oeth->ether_shost[i];
        eth->ether_shost[i] = oeth->ether_dhost[i];
    }

    eth->ether_type = oeth->ether_type;

    if(sendto(sd, buffer, len, 0, (struct sockaddr *)&sin, sizeof(sin)) <= 0) {
        perror("sendto() error"); exit(-1); 
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip proto icmp";
    bpf_u_int32 net;
    for(int i = 0; i < MAX_CONN; i++){
        dicts[i].seq = 0;
        dicts[i].tim = 0;
    }
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle); 
    return 0;
}
