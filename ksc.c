#include <stdio.h>
#include <string.h>
#include "pcap/pcap.h"
#include <unistd.h>
char error_buffer[PCAP_ERRBUF_SIZE];
int get_app_layer_index(const u_char *start, int caplen);
void deal_packet(u_char *user, const struct pcap_pkthdr* h, const u_char *bytes)
{

	int APP_index = get_app_layer_index(bytes, h->caplen);
	if(APP_index){
		printf("Application-layer's length is %d\n", h->caplen - APP_index);
		for(int i = APP_index; i < h->caplen; i++)
			printf("%c ", bytes[i]);
		printf("\n");
		for(int i = APP_index; i < h->caplen; i++)
			printf("%2x ", bytes[i]);		
		printf("\n");
	}
}
int get_app_layer_index(const u_char *start, int caplen)
{
	const u_char *IP_head = start + 14;
	int TCP_index = (*IP_head & 0x0F) * 4;
	const u_char *TCP_head = IP_head + TCP_index;
	int APP_index = ((*(TCP_head + 12) & 0xF0) >> 4) * 4;
	if(caplen - (14 + TCP_index + APP_index))
		return 14 + TCP_index + APP_index;
	else
		return 0;
	
}
int atoi(char *arg)
{
	int length = strlen(arg);
	int power = 1;
	int result = 0;
	for(int i = length -1; i >= 0; i--){
		result += (arg[i] - '0') * power;
		power *= 10; 
	}
	return result;
}
int main(int argc, char **argv)
{
	//pcap_t *cap_handle = pcap_create("any",error_buffer); why not use this function
	char device_name[100] = "wlp2s0";
	char port_obj[5] = "dst";
	char net_obj[5] = "dst";
	char ip[40] = "123.206.89.123";
	char port[50] = "5473";
	int packet_num = 10;

	int choice;
	while((choice = getopt(argc, argv, "n:i:o:O:d:hp:")) != -1){
		switch(choice){
			case 'n':
				packet_num = atoi(optarg);
				break;
			case 'i':
				sprintf(ip,"%s", optarg);
				break;
			case 'o':
				sprintf(net_obj, "%s", optarg);
				break;
			case 'O':
				sprintf(port_obj, "%s", optarg);
				break;
			case 'd':
				sprintf(device_name, "%s", optarg);
				break;
			case 'h':
				printf("-O port ('dst' or 'src')\n");
				printf("-o ip ('dst' or 'src')\n");
				printf("-i ip address (like '123.206.89.123')\n");
				printf("-d device name (like 'wlp2s0' in Fedora,you can use `ifconfig`)\n");
				printf("-h this help\n");
				printf("-p port (like '5473')\n");
				printf("-n packet nums (default nums is 10)\n");
				return 0;
			case 'p':
				sprintf(port, "%s", optarg);
				break;
			case '?':
				printf("unknow arguement,please use -h to get usage\n");
				return -1;
		}
	}

	bpf_u_int32 mask;
	bpf_u_int32 net;

	pcap_t *cap_handle ;

	pcap_lookupnet(device_name, &net, &mask, error_buffer);
	cap_handle =  pcap_open_live(device_name,BUFSIZ, 1,0,error_buffer);
	if(!cap_handle){
		printf("Error\n%s\n", error_buffer);
		return -1;
	}

	struct bpf_program filter;
	char filter_app[100];
	sprintf(filter_app, "%s net %s and tcp %s port %s", net_obj, ip, port_obj, port);

	pcap_compile(cap_handle, &filter, filter_app, 0, net);
	pcap_setfilter(cap_handle, &filter);
	
	pcap_loop(cap_handle, packet_num, deal_packet, NULL);

	pcap_close(cap_handle);
	return 0;
}
