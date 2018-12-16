#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <cstring>
#include <cctype>
#include <queue>

#define MAX_BYTES_2_CAPTURE 2048

void localip(pcap_if_t *name);
void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main(int argc, char const *argv[])
{
    int i = 0, count = 0;
    pcap_t *descr = NULL;
    pcap_if_t *devices, *temp;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Init errbuf
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    // Find the default device on which to capture
    int result = pcap_findalldevs(&devices, errbuf);
    if (result == PCAP_ERROR)
    {
        printf("Cannot find the devices!\n");
        return -1;
    }

    // list all dev
    // for (temp = devices; temp; temp = temp->next)
    // {
    //     printf("%d: %s\n", i++, temp->name);
    // }

    // Network interface
    temp = devices;

    localip(temp);

    descr = pcap_open_live(temp->name, MAX_BYTES_2_CAPTURE, 1, 512, errbuf);
    if (descr != NULL)
    {
        printf("Network interface %d: %s\n", i, temp->name);
    }
    else
    {
        printf("%s\n", errbuf);
        return -1;
    }

    pcap_loop(descr, -1, processPacket, (u_char *)&count);

    return 0;
}

void localip(pcap_if_t *name)
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, name->name, IFNAMSIZ - 1);

    ioctl(fd, SIOCGIFADDR, &ifr);

    close(fd);

    printf("Local IP address: %s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}

void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    // Declare pointers to packet numbers
    const struct ether_header *ethernet_header;
    const struct ip *ipv4_header;
    const struct ip6_hdr *ipv6_header;
    const struct tcphdr *tcp_header;
    const struct udphdr *udp_header;
    const struct icmphdr *icmp_header;

    // Declare IPv4 source and destination address
    char sourIP4[INET_ADDRSTRLEN]; // source address
    char destIP4[INET_ADDRSTRLEN]; // source address
    ethernet_header = (struct ether_header *)(packet);

    int *counter = (int *)arg;

    printf("%s\n", packet);

    switch (ntohs(ethernet_header->ether_type))
    {
    case ETHERTYPE_IP:
        ipv4_header = (struct ip *)(packet + sizeof(ether_header));

        // Get ipv4 source and destination address
        inet_ntop(AF_INET, &(ipv4_header->ip_src), sourIP4, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipv4_header->ip_dst), destIP4, INET_ADDRSTRLEN);

        if (ipv4_header->ip_p != IPPROTO_TCP)
        {
            break;
        }

        tcp_header = (tcphdr *)((u_char *)ipv4_header + sizeof(ip));

        // Get source and destination port number
        u_int sourPort = ntohs(tcp_header->th_sport);
        u_int destPort = ntohs(tcp_header->th_dport);

        printf("%s : %d ---> %s : %d", sourIP4, sourPort, destIP4, destPort);
        break;
    }
}