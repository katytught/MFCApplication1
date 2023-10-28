#pragma once
#ifndef MYSTRUCTS_H
#define MYSTRUCTS_H
#endif // !MYSTRUCTS_H

#define PROTO_ICMP 1
#define PROTO_TCP 6					
#define PROTO_UDP 17					 
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN    4321

typedef struct pktcount {
	int tcp;
	int udp;
	int icmp;
	int http;
	int arp;
	int icmpv6;
	int ipv4;
	int ipv6;
	int total;
};

typedef struct ethhdr
{
	u_char dest[6];			
	u_char src[6];				
	u_short type;				
};

typedef struct arphdr
{
	u_short ar_hrd;						
	u_short ar_pro;						
	u_char ar_hln;						
	u_char ar_pln;						
	u_short ar_op;						
	u_char ar_srcmac[6];			
	u_char ar_srcip[4];				
	u_char ar_destmac[6];			
	u_char ar_destip[4];				
};

typedef struct iphdr
{
#if defined(LITTLE_ENDIAN)
	u_char ihl : 4;
	u_char version : 4;
#elif defined(BIG_ENDIAN)
	u_char version : 4;
	u_char  ihl : 4;
#endif
	u_char tos;				
	u_short tlen;			
	u_short id;				
	u_short frag_off;	
	u_char ttl;				
	u_char proto;		
	u_short check;		
	u_int saddr;			
	u_int daddr;			
	u_int	op_pad;		
};

typedef struct tcphdr
{
	u_short sport;							
	u_short dport;							
	u_int seq;									
	u_int ack_seq;							
#if defined(LITTLE_ENDIAN)
	u_short res1 : 4,
		doff : 4,
		fin : 1,
		syn : 1,
		rst : 1,
		psh : 1,
		ack : 1,
		urg : 1,
		ece : 1,
		cwr : 1;
#elif defined(BIG_ENDIAN)
	u_short doff : 4,
		res1 : 4,
		cwr : 1,
		ece : 1,
		urg : 1,
		ack : 1,
		psh : 1,
		rst : 1,
		syn : 1,
		fin : 1;
#endif
	u_short window;					
	u_short check;						
	u_short urg_ptr;					
	u_int opt;								
};

typedef struct udphdr
{
	u_short sport;		
	u_short dport;		
	u_short len;			
	u_short check;		
};

typedef struct icmphdr
{
	u_char type;			
	u_char code;			
	u_char seq;			
	u_char chksum;		
};

typedef struct iphdr6
{
    u_int  flowid:20,flowtype:8,version:4;				
	u_short plen;					
	u_char nh;						
	u_char hlim;					
	u_short saddr[8];			
	u_short daddr[8];			
};

//∂®“ÂICMPv6
typedef struct icmphdr6
{
	u_char type;			
	u_char code;			
	u_char seq;			
	u_char chksum;		
	u_char op_type;	
	u_char op_len;		
	u_char op_ethaddr[6];		
};

typedef struct datapkt
{
	char  pktType[8];					
	int time[6];							
	int len;									
	struct ethhdr* ethh;				
	struct arphdr* arph;				
	struct iphdr* iph;					
	struct iphdr6* iph6;				
	struct icmphdr* icmph;		
	struct icmphdr6* icmph6;	
	struct udphdr* udph;			
	struct tcphdr* tcph;				
	void* apph;							
};