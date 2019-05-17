#include <pcap.h>
#include "header.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    int i;
    struct ethheader *eth = (struct ethheader *)packet;
    if(ntohs(eth->ether_type) == 0x0800){
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);
        int tcp_header_len = (tcp->flag & 0xf0) >> 4;
        int start = 4 * (ip->iph_ihl + tcp_header_len);
        int end = ntohs(ip->iph_len);
        unsigned char *p = (unsigned char *)(ip);
        for(i = start; i < end; i++)
            printf("%c",p[i]);
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp port 23";
    bpf_u_int32 net;
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle); 
    return 0;
}