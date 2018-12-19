#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <iostream>
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
#include <list>

#define MAX_BYTES_2_CAPTURE 2048

using namespace std;
queue<const u_char *> Packetqueue;

// Service port number
typedef enum
{
    http = 80
} ServicePort;

// Connection Information Structure
struct ConnectInfo
{
    char SourIP[INET_ADDRSTRLEN];
    char DestIP[INET_ADDRSTRLEN];
    u_int SourPort;
    u_int DestPort;
    ServicePort ServPort;
};

// Record struct ConnectInfo and identify if the Info is the known ports or create a new Info in port table.
// List port table
list<ConnectInfo> PortTable;
list<ConnectInfo>::iterator Iter;

// Mutex
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

// Prototype
void localip(pcap_if_t *name);
void Inputqueue(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);
// void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void *processPacket(void *packet);

int main(int argc, char const *argv[])
{
    int i = 0, count = 0;
    pcap_t *descr = NULL;
    pcap_if_t *devices, *temp;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Init errbuf
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    // Init mutex
    pthread_mutex_init(&mutex, NULL);

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

    pcap_loop(descr, -1, Inputqueue, (u_char *)&count);

    // Close mutex
    pthread_mutex_destroy(&mutex);

    return 0;
}

// Get local IP address
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

// Input queue
void Inputqueue(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    Packetqueue.push(packet);

    if (Packetqueue.size() >= 100)
    {
        pthread_t thread[100];
        for (int i = 0; i < 100; i++)
        {
            pthread_create(&thread[i], NULL, &processPacket, (void *)Packetqueue.front());
            Packetqueue.pop();
        }
        for (int i = 0; i < 100; i++)
        {
            pthread_join(thread[i], NULL);
        }
    }
}

// Packet process
void *processPacket(void *_packet)
{

    // Declare pointers to packet numbers
    const struct ether_header *ethernet_header;
    const struct ip *ipv4_header;
    const struct ip6_hdr *ipv6_header;
    const struct tcphdr *tcp_header;
    const struct udphdr *udp_header;
    const struct icmphdr *icmp_header;

    // Declare packet
    u_char *packet = (u_char *)_packet;

    // Declare structure
    ConnectInfo connectinfo;

    // Declare IPv4 source and destination address
    char sourIP4[INET_ADDRSTRLEN]; // source address
    char destIP4[INET_ADDRSTRLEN]; // source address
    ethernet_header = (struct ether_header *)(packet);

    int CountForWhile = 0;
    bool Resultoflist = false;

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

        // Lock and accumulate Table
        pthread_mutex_lock(&mutex);
        // List componets
        for (Iter = PortTable.begin(); Iter != PortTable.end(); Iter++)
        {
            if (((strcmp(sourIP4, Iter->SourIP) == 0) && (strcmp(destIP4, Iter->DestIP) == 0) && (sourPort == Iter->SourPort) && (destPort == Iter->DestPort)) ||
                ((strcmp(sourIP4, Iter->DestIP) == 0) && (strcmp(destIP4, Iter->SourIP) == 0) && (sourPort == Iter->DestPort) && (destPort == Iter->SourPort)))
            {
                Resultoflist = true;
                break;
            }
        }
        if (Resultoflist == false)
        {
            connectinfo.SourPort = sourPort;
            connectinfo.DestPort = destPort;
            memcpy(connectinfo.SourIP, sourIP4, INET_ADDRSTRLEN);
            memcpy(connectinfo.DestIP, destIP4, INET_ADDRSTRLEN);
            PortTable.push_back(connectinfo);
            printf("Source: %15s/%5d, Destination: %15s/%5d\n", sourIP4, sourPort, destIP4, destPort);
        }
        // Unlock and accumulate Table
        pthread_mutex_unlock(&mutex);

        // printf("%15s : %5d ---> %15s : %5d\n", sourIP4, sourPort, destIP4, destPort);
        break;
    }
}