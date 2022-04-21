#include <arpa/inet.h>
#include <netinet/ip.h>

typedef struct analisis{
    int icmpv4;
    int igmp;
    int ip;
    int tcp;
    int udp;
    int ipv6;
    int ospf;
    int size0_159;
    int size160_639;
    int size640_1279;
    int size1280_5119;
    int size5120_more;

} Analisis;

typedef struct PacketCustom{
    struct ethhdr * ethernet;
    int size;
    struct iphdr * ip;
} PacketCustom;