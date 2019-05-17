#include <stdio.h>
#include <arpa/inet.h>

#define	ETHER_ADDR_LENGTH	6
#define ICMP_PROTOCOL_NUM 1
#define TCP_PROTOCOL_NUM  6
#define UDP_PROTOCOL_NUM  17
#define ICMP_DATA_LENGTH  14

/* Ethernet */
struct ethheader {
  unsigned char  ether_dhost[ETHER_ADDR_LENGTH]; /* destination host address */
  unsigned char  ether_shost[ETHER_ADDR_LENGTH]; /* source host address */
  unsigned short ether_type;                     /* IP? ARP? RARP? etc */
};
// struct ethheader {
//   u_char  ether_dhost[ETHER_ADDR_LENGTH]; /* destination host address */
//   u_char  ether_shost[ETHER_ADDR_LENGTH]; /* source host address */
//   u_short ether_type;                     /* IP? ARP? RARP? etc */
// };

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4,    /* IP header length in 4 bytes*/
                     iph_ver:4;    /* IP version */
  unsigned char      iph_tos;      /* Type of service */
  unsigned short int iph_len;      /* IP Packet length (data + header) */
  unsigned short int iph_ident;    /* Identification */
  unsigned short int iph_flag:3,   /* Fragmentation flags */
                     iph_offset:13;/* Flags offset */
  unsigned char      iph_ttl;      /* Time to Live */
  unsigned char      iph_protocol; /* Protocol type */
  unsigned short int iph_chksum;   /* IP datagram checksum */
  struct  in_addr    iph_sourceip; /* Source IP address */
  struct  in_addr    iph_destip;   /* Destination IP address */ 
};

/* ICMP Header exclude the timestamp and data */
struct icmpheader {
  unsigned char      icmp_type; // ICMP message type
  unsigned char      icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
};

/* Full & Fake ICMP Header  */
struct ficmpheader {
  unsigned char      icmp_type;   // ICMP message type
  unsigned char      icmp_code;   // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
  unsigned int icmp_data[ICMP_DATA_LENGTH];   //including timestamp and data
};

/* UDP Header */
struct udpheader {
  unsigned short int uh_sport;
  unsigned short int uh_dport;
  unsigned short int uh_len;      /* data + header */
  unsigned short int uh_chksum;
};

/* TCP Header */
struct tcpheader {
  unsigned short int th_sport;
  unsigned short int th_dport;
  unsigned int       th_seq;
  unsigned int       th_ack;
  unsigned short int flag;
};