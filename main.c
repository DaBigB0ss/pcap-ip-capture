#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>

struct ip_packet
{
        u_char ip_vhl;
        u_char ip_tos;
        u_short ip_len;
        u_short ip_id;
        u_short ip_off;
        u_char ip_ttl;
        u_char ip_p;
        u_short ip_sum;
        struct in_addr ip_src;
        struct in_addr ip_dst;
};

void ip_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1;
	const struct ip_packet *ip;
	printf("\nPacket number %d:\n", count);
	ip = (struct ip_packet*)(packet + 14);
	printf("Source: %s\n", inet_ntoa(ip->ip_src));
	printf("Destination: %s\n", inet_ntoa(ip->ip_dst));
	count++;
}

int main(int argc, char **argv)
{
	char *dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handler;
	char filter_exp[] = "ip";
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;

	if (argc == 2)
	{
		dev = argv[1];
	}
	else
	{
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL)
		{
            printf("Can't find default device.");
			return 1;
		}
	}

	pcap_lookupnet(dev, &net, &mask, errbuf);
	handler = pcap_open_live(dev, 1518, 1, 1000, errbuf);
	pcap_compile(handler, &fp, filter_exp, 0, net);
	pcap_setfilter(handler, &fp);
	pcap_loop(handler, 15, ip_handler, NULL);
	pcap_freecode(&fp);
	pcap_close(handler);
	printf("\nCapture complete.\n");
    return 0;
}
