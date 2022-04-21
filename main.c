#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdint.h>
#include "sniffer.h"
#include "ip_plot_list.h"


void deactivatePromiscMode(char * card_interface);
void clasifySupProtocol(int protocol);
void clasifyLenPacket(int len);

void *analizer(void * data);

Analisis * analisis;
Nodo * nodo = NULL;
FILE * fp;


int main(){

    int packets = 0;
    
    void * valor_retorno;
    analisis = (Analisis * )malloc(sizeof(Analisis));

    analisis->icmpv4 = 0;
    analisis->igmp = 0;
    analisis->ip = 0;
    analisis->tcp = 0;
    analisis->udp = 0;
    analisis->ipv6 = 0;
    analisis->ospf = 0;
    analisis->size0_159 = 0;
    analisis->size160_639 = 0;
    analisis->size640_1279 = 0;
    analisis->size1280_5119 = 0;
    analisis->size5120_more = 0;

    struct ifreq ethreq;
    int sock;
    char * cardInterface = (char *) calloc(100, sizeof(char));

    printf("\nInserta el número de paquetes\n");
    scanf("%i", &packets);
    pthread_t anlzr[packets];
    fflush(stdin);

    printf("\nInserta el nombre de tu tarjeta de red\n");
    scanf("%s", cardInterface);

    printf("Esta es la tarjeta %s", cardInterface);

    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    strncpy(ethreq.ifr_name, cardInterface, IFNAMSIZ);
    ioctl(sock, SIOCGIFFLAGS, &ethreq);
    ethreq.ifr_flags |= IFF_PROMISC;
    ioctl(sock, SIOCSIFFLAGS, &ethreq);

    struct sockaddr saddr;
    int size_saddr;
    int size;
    int notAnalized = 0;
    fp = fopen("analisis.txt", "a");

    for(int i = 0; i < packets; i++){
        char * buffer = (char *) calloc(65536, sizeof(char));
        size = recvfrom(sock, buffer, 65536, 0, &saddr, &size_saddr);
        PacketCustom * packetCustom = (PacketCustom * ) malloc(sizeof(PacketCustom));
        packetCustom->ethernet = (struct ethhdr * ) buffer;
        packetCustom->size = size;

        if(htons(packetCustom->ethernet->h_proto) == 0x800){
            packetCustom->ip = (struct iphdr * )buffer;
        
            if(pthread_create(&anlzr[i], NULL, analizer, (void *)packetCustom)){
                printf("\nProblemas creando el hilo del analizador\n");
                exit(EXIT_FAILURE);
            };
        }
        else{
            printf("\nPackete no analizado\n");
            fprintf(fp, "\nPackete no analizado\n");
            notAnalized++;
            packets--;
            i--;
            free(packetCustom);
        }

        /*Aquí se despliega la informacion*/

    }

    for(int i = 0; i < packets; i++){
        if(pthread_join(anlzr[i], &valor_retorno)){
            printf("\nProblemas creando el enlace\n");
            exit(EXIT_FAILURE);
        };
    }

    printf("\n--------------------Resumen de análisis-----------------------\n");
    printf("\nPaquetes capturados de:\n");
    printf("ICMPv4: %i\n", analisis->icmpv4);
    printf("IGMP: %i\n", analisis->igmp);
    printf("IP: %i\n", analisis->ip);
    printf("TCP: %i\n", analisis->tcp);
    printf("UDP: %i\n", analisis->udp);
    printf("IPv6: %i\n", analisis->ipv6);
    printf("OSPF: %i\n", analisis->ospf);
    
    fprintf(fp, "\n--------------------Resumen de análisis-----------------------\n");
    fprintf(fp,"\nPaquetes capturados de:\n");
    fprintf(fp,"ICMPv4: %i\n", analisis->icmpv4);
    fprintf(fp,"IGMP: %i\n", analisis->igmp);
    fprintf(fp,"IP: %i\n", analisis->ip);
    fprintf(fp,"TCP: %i\n", analisis->tcp);
    fprintf(fp,"UDP: %i\n", analisis->udp);
    fprintf(fp,"IPv6: %i\n", analisis->ipv6);
    fprintf(fp,"OSPF: %i\n", analisis->ospf);

    desplegarInformacion(nodo, fp);

    printf("\nPaquetes capturados por tamaño:\n");
    printf("0-159: %i\n", analisis->size0_159);
    printf("160-639: %i\n", analisis->size160_639);
    printf("640-1279: %i\n", analisis->size640_1279);
    printf("1280-5119: %i\n", analisis->size1280_5119);
    printf("5120 o mayor: %i\n", analisis->size5120_more);

    fprintf(fp, "\nPaquetes capturados por tamaño:\n");
    fprintf(fp, "0-159: %i\n", analisis->size0_159);
    fprintf(fp, "160-639: %i\n", analisis->size160_639);
    fprintf(fp, "640-1279: %i\n", analisis->size640_1279);
    fprintf(fp, "1280-5119: %i\n", analisis->size1280_5119);
    fprintf(fp, "5120 o mayor: %i\n", analisis->size5120_more);



    free(analisis);
    free(nodo);
    fclose(fp);
    deactivatePromiscMode(cardInterface);
    return 0;
}

void *analizer(void * data){
    PacketCustom * packetCustom = (PacketCustom *) data;
    struct sockaddr_in source,dest;
    int lcu = 0;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = packetCustom->ip->saddr;
    memset(&source, 0, sizeof(source));
    dest.sin_addr.s_addr = packetCustom->ip->daddr;
    
    printf("\nDirección IP fuente: %s\n", inet_ntoa(source.sin_addr));
    fprintf(fp, "\nDirección IP fuente: %s\n", inet_ntoa(source.sin_addr));

    if(actualizarMasUnoSent(nodo, inet_ntoa(source.sin_addr)) == 0){
        nodo = insertarFinal(inet_ntoa(source.sin_addr), 0, 1, nodo);
    }
    
    printf("Dirección IP destino: %s\n", inet_ntoa(dest.sin_addr));
    fprintf(fp, "Dirección IP destino: %s\n", inet_ntoa(dest.sin_addr));

    if(actualizarMasUnoReceived(nodo, inet_ntoa(dest.sin_addr)) == 0){
        nodo = insertarFinal(inet_ntoa(dest.sin_addr), 1, 0, nodo);
    }

    printf("Longitud de cabecera: %i bytes\n", ((unsigned int)packetCustom->ip->ihl)*4);
    fprintf(fp, "Longitud de cabecera: %i bytes\n", ((unsigned int)packetCustom->ip->ihl)*4);
    printf("Longitud Total: %i bytes\n", ntohs(packetCustom->ip->tot_len));
    fprintf(fp, "Longitud Total: %i bytes\n", ntohs(packetCustom->ip->tot_len));
    clasifyLenPacket(ntohs(packetCustom->ip->tot_len));
    printf("Identificador del datagrama: %i\n", ntohs(packetCustom->ip->id));
    fprintf(fp, "Identificador del datagrama: %i\n", ntohs(packetCustom->ip->id));
    printf("Tiempo de vida: %i\n", (unsigned int)packetCustom->ip->ttl);
    fprintf(fp, "Tiempo de vida: %i\n", (unsigned int)packetCustom->ip->ttl);
    printf("Protocolo: ");
    fprintf(fp, "Protocolo: ");
    clasifySupProtocol((unsigned int) packetCustom->ip->protocol);
    printf("\n");
    fprintf(fp,"\n");

    lcu = ntohs(packetCustom->ip->tot_len) - ((unsigned int) packetCustom->ip->ihl)*4;
    printf("Longitud de carga util: %i bytes\n", lcu);
    fprintf(fp, "Longitud de carga util: %i bytes\n", lcu);
    printf("Tipo de Servicio: %i\n", (unsigned int) packetCustom->ip->tos);
    fprintf(fp, "Tipo de Servicio: %i\n", (unsigned int) packetCustom->ip->tos);
    
    int isLast = 0;
    int isFragment = (unsigned int) packetCustom->ip->frag_off & 0xE0;
    char * buffer = (char *) packetCustom->ip;

    if(isFragment == 0x20){
        printf("Esta fragmentado\n");  
        fprintf(fp, "Esta fragmentado\n");  
        isLast = (unsigned int) buffer[21] & 0xFF;

        if(isLast > 0x00){
            printf("Es intermedio\n");
            fprintf(fp, "Es intermedio\n");
        }
        else{
            printf("Es el primero\n");
            fprintf(fp, "Es el primero\n");
        }

    }
    else{
        printf("No esta fragmentado\n");
        fprintf(fp, "No esta fragmentado\n");
    }

    char firstByte = buffer[((unsigned int) packetCustom->ip->ihl)*4];
    printf("El primer byte es: %i\n", firstByte);
    fprintf(fp, "El primer byte es: %i\n", firstByte);
    char lastByte = buffer[packetCustom->size-1];
    printf("El ultimo byte es: %i\n", lastByte);
    fprintf(fp, "El ultimo byte es: %i\n", lastByte);

    free(packetCustom);
    free(buffer);
    
}

void clasifySupProtocol(int protocol){

    switch(protocol){
        case 0x01:{
            printf("ICMPv4");
            fprintf(fp,"ICMPv4");
            analisis->icmpv4++;
        }
        case 0x02:{
            printf("IGMP");
            printf(fp, "IGMP");
            analisis->igmp++;
        }
        case 0x04:{
            printf("IP");
            printf(fp, "IP");
            analisis->ip++;
        }
        case 0x06:{
            printf("TCP");
            printf(fp, "TCP");
            analisis->tcp++;
        }
        case 0x11:{
            printf("UDP");
            printf(fp, "UDP");
            analisis->udp++;
        }
        case 0x29:{
            printf("IPv6");
            printf(fp, "IPv6");
            analisis->ipv6++;
        }
        case 0x59:{
            printf("OSPF");
            printf(fp, "OSPF");
            analisis->ospf++;
        }
        default:{
            printf("0x%.4X", protocol);
            printf(fp, "0x%.4X", protocol);
        }
    }

}

void clasifyLenPacket(int len){
    if(len >= 0 && len <= 159){
        analisis->size0_159++;
    }
    else if(len >= 160 && len <= 939){
        analisis->size160_639++;
    }
    else if(len >= 640 && len <= 1279){
        analisis->size640_1279++;
    }
    else if(len >= 1280 && len <= 5119){
        analisis->size1280_5119++;
    }
    else if(len >= 5120){
        analisis->size5120_more++;
    }
}

void deactivatePromiscMode(char * card_interface){

    char * command = (char *) calloc(100, sizeof(char));

    strcpy(command, "/sbin/ifconfig ");
    strcat(command, card_interface);
    strcat(command, " -promisc");

    system(command);

    free(command);
}