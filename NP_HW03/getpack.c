#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <sys/socket.h>

#define MAC_ADDRSTRLEN 2*6+5+1
void dump_ethernet(u_int32_t length, const u_char *content);
void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content);
char *mac_ntoa(u_char *d);

int main(int argc, const char * argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    char *device = "enp0s3";

    handle = pcap_open_live(device, 65535, 1, 1, errbuf);
    if(!handle) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        exit(1);
    }//end if

    //ethernet only
    if(pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Sorry, Ethernet only.\n");
        pcap_close(handle);
        exit(1);
    }//end if

    //start capture
    pcap_loop(handle, 5, pcap_callback, NULL);

    //free
    pcap_close(handle);
    return 0;
}


char *mac_ntoa(u_char *d) {
    static char str[MAC_ADDRSTRLEN];

    snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);

    return str;
}//end mac_ntoa

void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content) {
    static int d = 0;
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

    printf("No. %d\n", ++d);

    //print header
    printf("\tTime: %s.%.6ld\n", timestr, header->ts.tv_usec);
    printf("\tLength: %d bytes\n", header->len);
    printf("\tCapture length: %d bytes\n", header->caplen);

    //dump ethernet
    dump_ethernet(header->caplen, content);

    printf("\n");
}//end pcap_callback

void dump_ethernet(u_int32_t length, const u_char *content) {
    struct ether_header *ethernet = (struct ether_header *)content;
    char dst_mac_addr[MAC_ADDRSTRLEN] = {};
    char src_mac_addr[MAC_ADDRSTRLEN] = {};
    u_int16_t type;

    //copy header
    strncpy(dst_mac_addr, mac_ntoa(ethernet->ether_dhost), sizeof(dst_mac_addr));
    strncpy(src_mac_addr, mac_ntoa(ethernet->ether_shost), sizeof(src_mac_addr));
    type = ntohs(ethernet->ether_type);

    //print
    if(type <= 1500)
        printf("IEEE 802.3 Ethernet Frame:\n");
    else
        printf("Ethernet Frame:\n");

    printf("---------------------------------------------------------------------------\n");
    printf("| Destination MAC Address: %17s|\n", dst_mac_addr);
    printf("| Source MAC Address:      %17s|\n", src_mac_addr);
    if (type < 1500)
        printf("| Length: %5u|\n", type);
    else
        printf("| Ethernet Type: 0x%04x|\n", type);
    switch (type) {
        case 0x0800:
            printf("The network layer is IP.\n");
            //dump_ip(length, content);
            struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
            u_int version = ip->ip_v;
            u_int header_len = ip->ip_hl << 2;
            u_char tos = ip->ip_tos;
            u_int16_t total_len = ntohs(ip->ip_len);
            u_int16_t id = ntohs(ip->ip_id);
            u_int16_t offset = ntohs(ip->ip_off);
            u_char ttl = ip->ip_ttl;
            u_char protocol = ip->ip_p;
            u_int16_t checksum = ntohs(ip->ip_sum);
            char src_ip[INET_ADDRSTRLEN] = {0};
            char dst_ip[INET_ADDRSTRLEN] = {0};
            //copy ip address
            snprintf(src_ip, sizeof(src_ip), "%s", inet_ntoa(ip->ip_src));
            snprintf(dst_ip, sizeof(dst_ip), "%s", inet_ntoa(ip->ip_dst));
            //print
            printf("---------------------------------------------------------------------------\n");
            printf("| Source IP Address:      %15s|\n", src_ip);
            printf("| Destination IP Address: %15s|\n", dst_ip);
            printf("---------------------------------------------------------------------------\n");
            break;

        case 0x0806:
            printf("The network layer is ARP.\n");
            break;

        case 0x0835:
            printf("The network layer is RARP.\n");
            break;

        default:
            printf("The network layer is %#06x", type);
            break;
    }//end switch
    printf("---------------------------------------------------------------------------\n");

}//end dump_ethernet
