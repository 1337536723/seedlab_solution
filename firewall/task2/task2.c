#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ip.h>

static struct nf_hook_ops nfho_out; //net filter for outgoing packets
static struct nf_hook_ops nfho_in;  //net filter for incoming packets
struct sk_buff *sock_buff;

struct iphdr *ip_header;     //ip header struct
struct tcphdr *tcp_header;   //tcp header struct
struct icmphdr *icmp_header; //icmp header struct

unsigned int src_port, dst_port;

void print_address(struct iphdr *ip_header)
{
   printk(KERN_INFO "filter SRC: %d.%d.%d.%d \n",
          ip_header->saddr & 0x000000ff,
          (ip_header->saddr & 0x0000ff00) >> 8,
          (ip_header->saddr & 0x00ff0000) >> 16,
          (ip_header->saddr & 0xff000000) >> 24);
   printk(KERN_INFO "filter DST: %d.%d.%d.%d \n",
          ip_header->daddr & 0x000000ff,
          (ip_header->daddr & 0x0000ff00) >> 8,
          (ip_header->daddr & 0x00ff0000) >> 16,
          (ip_header->daddr & 0xff000000) >> 24);
}

bool check_address_src(struct iphdr *ip_header, int a, int b, int c, int d)
{
   if (((ip_header->saddr & 0xff000000) >> 24) != d)
      return false;
   if (((ip_header->saddr & 0x00ff0000) >> 16) != c)
      return false;
   if (((ip_header->saddr & 0x0000ff00) >> 8) != b)
      return false;
   if ((ip_header->saddr & 0x000000ff) != a)
      return false;
   return true;
}

bool check_address_dst(struct iphdr *ip_header, int a, int b, int c, int d)
{
   if (((ip_header->daddr & 0xff000000) >> 24) != d)
      return false;
   if (((ip_header->daddr & 0x00ff0000) >> 16) != c)
      return false;
   if (((ip_header->daddr & 0x0000ff00) >> 8) != b)
      return false;
   if ((ip_header->daddr & 0x000000ff) != a)
      return false;
   return true;
}

unsigned int hook_func_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
   sock_buff = skb;
   ip_header = (struct iphdr *)skb_network_header(sock_buff);

   if (!sock_buff)
      return NF_ACCEPT;

   // tcp
   if (ip_header->protocol == 6)
   {
      tcp_header = (struct tcphdr *)((__u32 *)ip_header + ip_header->ihl);
      src_port = (unsigned int)ntohs(tcp_header->source);
      dst_port = (unsigned int)ntohs(tcp_header->dest);
      // filter 2: B telnet A
      if (dst_port == 23)
      {
         print_address(ip_header);
         if (!check_address_src(ip_header, 10, 0, 2, 6))
         {
            printk(KERN_INFO "filter 2: src not match\n");
            return NF_ACCEPT;
         }
         if (!check_address_dst(ip_header, 10, 0, 2, 5))
         {
            printk(KERN_INFO "filter 2: dst not match\n");
            return NF_ACCEPT;
         }
         printk(KERN_INFO "filter 2: B telnet A\n");
         printk(KERN_INFO "filter 2: SRC_PORT: %d DST_PORT: %d\n", src_port, dst_port);
         return NF_DROP;
      }
   }
   return NF_ACCEPT;
}
unsigned int hook_func_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{

   sock_buff = skb;
   ip_header = (struct iphdr *)skb_network_header(sock_buff); //grab network header using accessor

   if (!sock_buff)
   {
      return NF_ACCEPT;
   }

   //icmp
   if (ip_header->protocol == 1)
   {
      icmp_header = (struct icmphdr *)((__u32 *)ip_header + ip_header->ihl);
      // filter 4: A ping B
      if (icmp_header->type == 8)
      {
         print_address(ip_header);
         if (!check_address_src(ip_header, 10, 0, 2, 5))
         {
            printk(KERN_INFO "filter 4: src not match\n");
            return NF_ACCEPT;
         }
         if (!check_address_dst(ip_header, 10, 0, 2, 6))
         {
            printk(KERN_INFO "filter 4: dst not match\n");
            return NF_ACCEPT;
         }
         printk(KERN_INFO "filter 4: A ping B\n");
         printk(KERN_INFO "filter 4: SRC_PORT: %d DST_PORT: %d\n", src_port, dst_port);
         return NF_DROP;
      }
   }

   // tcp
   if (ip_header->protocol == 6)
   {
      tcp_header = (struct tcphdr *)((__u32 *)ip_header + ip_header->ihl);
      src_port = (unsigned int)ntohs(tcp_header->source);
      dst_port = (unsigned int)ntohs(tcp_header->dest);
      // filter 5: A ssh B
      if (dst_port == 22)
      {
         print_address(ip_header);
         if (!check_address_src(ip_header, 10, 0, 2, 5))
         {
            printk(KERN_INFO "filter 5: src not match\n");
            return NF_ACCEPT;
         }
         if (!check_address_dst(ip_header, 10, 0, 2, 6))
         {
            printk(KERN_INFO "filter 5: dst not match\n");
            return NF_ACCEPT;
         }
         printk(KERN_INFO "filter 5: A ssh B\n");
         printk(KERN_INFO "filter 5: SRC_PORT: %d DST_PORT: %d\n", src_port, dst_port);
         return NF_DROP;
      }
      // filter 1: A telnet B
      if (dst_port == 23)
      {
         print_address(ip_header);
         if (!check_address_src(ip_header, 10, 0, 2, 5))
         {
            printk(KERN_INFO "filter 1: src not match\n");
            return NF_ACCEPT;
         }
         if (!check_address_dst(ip_header, 10, 0, 2, 6))
         {
            printk(KERN_INFO "filter 1: dst not match\n");
            return NF_ACCEPT;
         }
         printk(KERN_INFO "filter 1: A telnet B\n");
         printk(KERN_INFO "filter 1: SRC_PORT: %d DST_PORT: %d\n", src_port, dst_port);
         return NF_DROP;
      }
      // filter 3: A http fudan.edu.cn(202.120.224.115)
      if (dst_port == 80)
      {
         print_address(ip_header);
         if (!check_address_src(ip_header, 10, 0, 2, 5))
         {
            printk(KERN_INFO "filter 3: src not match\n");
            return NF_ACCEPT;
         }
         if (!check_address_dst(ip_header, 202, 120, 224, 115))
         {
            printk(KERN_INFO "filter 3: dst not match\n");
            return NF_ACCEPT;
         }
         printk(KERN_INFO "filter 3: A http fudan.edu.cn\n");
         printk(KERN_INFO "filter 3: SRC_PORT: %d DST_PORT: %d\n", src_port, dst_port);
         return NF_DROP;
      }

   }
   return NF_ACCEPT;
}

int init_module(void)
{
   nfho_in.hook = hook_func_in;
   nfho_in.hooknum = NF_INET_PRE_ROUTING;
   nfho_in.pf = PF_INET;
   nfho_in.priority = NF_IP_PRI_FIRST;
   nf_register_hook(&nfho_in);

   nfho_out.hook = hook_func_out;
   nfho_out.hooknum = NF_INET_POST_ROUTING;
   nfho_out.pf = PF_INET;
   nfho_out.priority = NF_IP_PRI_FIRST;
   nf_register_hook(&nfho_out);
   return 0;
}

void cleanup_module(void)
{
   printk(KERN_INFO "\nbye");
   nf_unregister_hook(&nfho_in);
   nf_unregister_hook(&nfho_out);
}
