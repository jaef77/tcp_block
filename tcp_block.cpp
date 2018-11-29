#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap.h>
#include <netinet/if_ether.h>

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80

#define TCP_FORWARD 1
#define TCP_BACKWARD 2

#pragma pack(push, 1)

typedef struct eth_hdr_custom{
    uint8_t dest_mac[6];
	uint8_t source_mac[6];
	uint16_t eth_type;
}eth_hdr_custom;

typedef struct ip_hdr_custom{
    uint8_t ip_hl:4;
    uint8_t ip_ver:4;
    uint8_t ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_pro;
    uint16_t ip_check;
    struct in_addr ip_src, ip_dest;
}ip_hdr_custom;

typedef struct tcp_hdr_custom{
    uint16_t port_src;	    // tcp source port (2byte)
	uint16_t port_dest;	    // tcp destination port (2byte)
	uint32_t tcp_seq;		// tcp sequence number (4byte)
	uint32_t tcp_ack;		// tcp acknowledgement number (4byte)
	uint8_t tcp_blank:4;	// tcp reserved field (4bit, Little Endian) - 2bit to flag
	uint8_t tcp_hlen:4;	    // tcp header length (4bit, Little Endian)
	uint8_t tcp_flags;	    // tcp flags (8bit) - 2bit from Reserved
	uint16_t tcp_wnd;		// tcp window size (2byte)
	uint16_t tcp_checksum;	// tcp checksum (2byte)
	uint16_t tcp_urgpnt;	// tcp urgent pointer (2byte)
}tcp_hdr_custom;

const u_char http_method[6][10] = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS "};
const u_int32_t http_method_length[6] = {4, 5, 5, 4, 7, 8};


// function for dump
void dump(uint8_t* p, int len) {
	for(int i=0; i<len; i++) {
		printf("%02x ", *p);
		p++;
		if((i & 0x0f) == 0x0f)
			printf("\n");
	}
}

// fucnction for printing MAC Address
void print_mac(uint8_t *mac, int len) {
	for(int i=0;i<len;i++)
	{
		printf("%02x", mac[i]);
		if(i<5)
			printf(":");
	}
    printf("\n");
}

// Get Local MAC ADDRESS & IP ADDRESS
int check_my_add(uint8_t *my_mac, struct in_addr *my_ip, const char *interface)
{
    struct ifreq buf;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0)
    {
        perror("ERROR : socket!");
        return -1;
    }

    strncpy(buf.ifr_name, interface, IFNAMSIZ-1);

    // MAC Address
    if(ioctl(sock, SIOCGIFHWADDR, &buf) < 0)
    {
        perror("ERROR : ioctl - MAC!");
        return -1;
    }
    for(int i=0;i<6;i++)
        my_mac[i] = buf.ifr_hwaddr.sa_data[i];

    //IP Address
    if(ioctl(sock, SIOCGIFADDR, &buf) < 0)
    {
        perror("ERROR : ioctl - IP");
        return -1;
    }
    *my_ip = ((struct sockaddr_in *)&buf.ifr_addr)->sin_addr;
    printf("my IP  : %s\nmy MAC : ", inet_ntoa(*my_ip));
    print_mac(my_mac, 6);
    return 0;
}

int tcp_block(pcap_t *handle, uint8_t *my_mac, const uint8_t* p, int len);
int send_rst_fin(pcap_t *handle, eth_hdr_custom *ETH, ip_hdr_custom *IP, tcp_hdr_custom *TCP, uint8_t *TCP_DATA, uint8_t *my_mac, int packet_len, int what_flag, int if_forward);


int main(int argc, char *argv[])
{
    if(argc != 2)
    {
        printf("Execute Code should be\narp_spoof <interface>");
        return -1;
    }

    // USE CUSTOM ARP_HEADER
    struct in_addr my_ip;
    uint8_t my_mac[6];
    char *interface = argv[1];

    // PCAP_OPEN
    // int debug=0;
    int count = 1;
    int offset = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
    if(handle == NULL)
    {
        perror("ERROR : handle is NULL");
        return -1;
    }

    // Get my local MAC / IP address
    if(check_my_add(my_mac, &my_ip, interface) < 0)
        return -1;

    while (true) {
        struct pcap_pkthdr* header;
        const uint8_t* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        if(tcp_block(handle, my_mac, packet, header->caplen))
        {
            printf("%d packet Blocking done!\n\n", count);
            count++;
        }
    }
    return 0;
}


int send_rst_fin(pcap_t *handle, eth_hdr_custom *ETH, ip_hdr_custom *IP, tcp_hdr_custom *TCP, uint8_t *TCP_DATA, uint8_t *my_mac, int packet_len, int what_flag, int if_forward)
{
    char send_buf[BUFSIZ];

    eth_hdr_custom *send_ETH = (eth_hdr_custom *)calloc(1, sizeof(eth_hdr_custom));
    ip_hdr_custom *send_IP = (ip_hdr_custom *)calloc(1, sizeof(ip_hdr_custom));
    tcp_hdr_custom *send_TCP = (tcp_hdr_custom *)calloc(1, sizeof(tcp_hdr_custom));
    uint8_t *send_TCP_DATA = (uint8_t *)calloc(BUFSIZ, sizeof(uint8_t));

    int eth_header_length = 14;
    int ip_header_length = 4 * IP->ip_hl;
    int tcp_header_length = 4 * TCP->tcp_hlen;
    int tcp_data_length = ntohs(IP->ip_len) - tcp_header_length - ip_header_length;

    // Copy the packet
    memcpy(send_ETH, ETH, eth_header_length);
    memcpy(send_IP, IP, ip_header_length);
    memcpy(send_TCP, TCP, tcp_header_length);
    memcpy(send_TCP_DATA, TCP_DATA, tcp_data_length);

    /********************************************************************************/
    // Check if FORWARD or BACKWARD ==> change the source/destination/tcp seq,ack
    memcpy(send_ETH->source_mac, my_mac, 6);

    if(if_forward == TCP_BACKWARD)
    {
        memcpy(send_ETH->dest_mac, ETH->source_mac, 6);
        send_IP->ip_ttl = 0;
        send_IP->ip_src = IP->ip_dest;
        send_IP->ip_dest = IP->ip_src;
        send_TCP->port_src = TCP->port_dest;
        send_TCP->port_dest = TCP->port_src;
        send_TCP->tcp_seq = ntohs(htonl(TCP->tcp_ack) + 1001);
        send_TCP->tcp_ack = ntohl(htonl(TCP->tcp_seq) + 1);    
    }
    else if(if_forward == TCP_FORWARD)
    {
        send_TCP->tcp_seq = ntohl(htonl(TCP->tcp_seq) + 1);
        send_TCP->tcp_ack = TCP->tcp_ack;
    }
    else
    {
        printf("ERROR!\nWrong if_forward value\n");
        free(send_ETH);
        free(send_IP);
        free(send_TCP);
        free(send_TCP_DATA);
        return -1;
    }

    // Check if RST or FIN (TCP_flag) ==> change the ip_total_length
    uint16_t tcp_length = 0;
    if(what_flag == TCP_FIN + TCP_ACK)      // FIN
        tcp_length = tcp_header_length + tcp_data_length;
    else                                    // RST
    {
        tcp_length = tcp_header_length;
        tcp_data_length = 0;
    }

    send_IP->ip_len = htons(ip_header_length + tcp_length);
    send_TCP->tcp_flags = what_flag;

    /********************************************************************************/
    // IP Checksum
    send_IP->ip_check = 0;
    uint32_t ip_check = 0;
    uint16_t *ip_tmp = (uint16_t *)send_IP;
    for(int i=0;i < (ip_header_length/2); i++)
        ip_check += ntohs(ip_tmp[i]);
    
    if(ip_check > 0xFFFF)
        ip_check = (ip_check / 0x10000) + (ip_check & 0xFFFF);

    send_IP->ip_check = htons(ip_check) ^ 0xFFFF;
    

    // TCP Checksum
    send_TCP->tcp_checksum = 0;
    uint32_t tcp_check = 0;
    uint16_t *tcp_tmp = (uint16_t *)send_TCP;
    uint16_t *tcp_data = (uint16_t *)send_TCP_DATA;

            // pseudo header
    for(int i=6;i<(ip_header_length/2);i++) // ip address
    {
        tcp_check += ntohs(ip_tmp[i]);
    }
    tcp_check += ntohs(send_IP->ip_pro);    // ip_protocol
    tcp_check += ntohs(tcp_length);         // tcp_segment_length
    for(int i=0;i < (tcp_header_length / 2); i++)   // tcp_header (except tcp_checksum field --> set as 0)
    {
        tcp_check += ntohs(tcp_tmp[i]);
    }

    for(int i=0;i < (tcp_data_length / 2); i++)
    {
        tcp_check += ntohs(tcp_data[i]);
    }
    if(tcp_data_length % 2 == 1)
    {
        tcp_check += ntohs(send_TCP_DATA[tcp_data_length-1] << 8);
    }

    if(tcp_check > 0xFFFF)
    {
        tcp_check = (tcp_check / 0x10000) + (tcp_check & 0xFFFF);
    }
    send_TCP->tcp_checksum = htons(tcp_check) ^ 0xFFFF;


    /********************************************************************************/
    int total_length = eth_header_length + ip_header_length + tcp_header_length + tcp_data_length;
    memcpy(send_buf, send_ETH, eth_header_length);
    memcpy(send_buf + eth_header_length, send_IP, ip_header_length);
    memcpy(send_buf + eth_header_length + ip_header_length, send_TCP, tcp_header_length);
    if(tcp_data_length > 0)
    {
        memcpy(send_buf + eth_header_length + ip_header_length + tcp_header_length, send_TCP_DATA, tcp_data_length);
    }

    // SEND PACKET
    if(pcap_sendpacket(handle, (u_char*)(send_buf), total_length) < 0)
    {
        perror("ERROR : sendpacket Failure");
        free(send_ETH);
        free(send_IP);
        free(send_TCP);
        free(send_TCP_DATA);
        return -1;
    }

    if(what_flag == TCP_FIN + TCP_ACK)
    {
        if(if_forward == TCP_FORWARD)
        {
            printf("FIN/ACK forward Sent!\n");
        }
        else
            printf("FIN/ACK backward Sent!\n");
    }
    else   
    {
        if(if_forward == TCP_FORWARD)
        {
            printf("RST forward Sent!\n");
        }
        else
            printf("RST backward Sent!\n");
    }
    free(send_ETH);
    free(send_IP);
    free(send_TCP);
    free(send_TCP_DATA);
    return 0;
}



int tcp_block(pcap_t *handle, uint8_t *my_mac, const uint8_t* p, int len) {
	eth_hdr_custom *ETH = (eth_hdr_custom *)p;
	if(ntohs(ETH->eth_type) == ETHERTYPE_IP)
	{
        p +=  sizeof(eth_hdr_custom);
		ip_hdr_custom *IP = (ip_hdr_custom *)p;
        u_int32_t total_length = ntohs(IP->ip_len);
        u_int32_t ip_header_length = 4 * IP->ip_hl;
		if(IP->ip_pro == IPPROTO_TCP)
		{
            p += ip_header_length;
            tcp_hdr_custom *TCP = (tcp_hdr_custom *)p;
            u_int32_t tcp_header_length = 4 * TCP->tcp_hlen;
            u_int32_t tcp_data_length = total_length - ip_header_length - tcp_header_length;
            if(tcp_data_length > 0)
            {
                int if_http = 0;
                p += tcp_header_length;
                uint8_t *DATA = (uint8_t *)p;
                for(int i=0;i<6;i++)
                {
                    if(memcmp(p, http_method[i], http_method_length[i]) == 0)
                    {
                        printf("HTTP %s packet detected!\n", http_method[i]);
                        if_http = 1;
                        break;
                    }
                }

                if(if_http == 1)    // http request
                {
                    // Forward RST
                    send_rst_fin(handle, ETH, IP, TCP, DATA, my_mac, len, TCP_RST, TCP_FORWARD);

                    // Backward FIN
                    send_rst_fin(handle, ETH, IP, TCP, DATA, my_mac, len, TCP_FIN + TCP_ACK, TCP_BACKWARD);

                    return 1;
                }

                else    // tcp
                {
                    printf("TCP packet detected!\n");
                    // Forward RST
                    send_rst_fin(handle, ETH, IP, TCP, DATA, my_mac, len, TCP_RST, TCP_FORWARD);

                    // Backward RST
                    send_rst_fin(handle, ETH, IP, TCP, DATA, my_mac, len, TCP_RST, TCP_BACKWARD);

                    return 1;
                }
            }
		}
        else
            return 0;
	}
    else
        return 0;
    return 0;
}
