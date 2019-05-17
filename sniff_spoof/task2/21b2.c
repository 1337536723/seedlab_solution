#include <pcap.h>
#include "header.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    if(ntohs(eth->ether_type) == 0x0800){
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl*4);
        printf("Src: %15s ", inet_ntoa(ip->iph_sourceip));
        printf("Dst: %15s ", inet_ntoa(ip->iph_destip));
        printf("Spo: %5d ", ntohs(tcp->th_sport));
        printf("Dpo: %5d\n", ntohs(tcp->th_dport));
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp && dst portrange 10-100";
    bpf_u_int32 net;
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle); 
    return 0;
}
