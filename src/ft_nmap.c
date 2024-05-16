#include "../include/ft_nmap.h"

void	close_pcap(t_nmap *nmap)
{
	if (nmap->handle != NULL)
		pcap_close(nmap->handle);
	if (nmap->fp.bf_insns != NULL)
		pcap_freecode(&nmap->fp);

	nmap->handle = NULL;
	nmap->fp.bf_insns = NULL;
}

void	close_nmap(t_nmap *nmap)
{
	if (nmap->sockfd != -1)
		close(nmap->sockfd);
	if (nmap->sockfd_udp != -1)
		close(nmap->sockfd_udp);
	if (nmap->alldevs != NULL)
		pcap_freealldevs(nmap->alldevs);
	close_pcap(nmap);
}

char	*get_default_dev(t_nmap *nmap)
{
	char		errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&nmap->alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return (NULL);
	}
	if (nmap->alldevs == NULL)
	{
		fprintf(stderr, "No devices found.\n");
		return (NULL);
	}

	return (nmap->alldevs->name);
}

int	create_pcap(pcap_t **handle, struct bpf_program *fp, int port, char *ip, char *dev)
{
	char	errbuf[PCAP_ERRBUF_SIZE]; // Buffer for error messages
	int		timeout = 1000; // Timeout in milliseconds
	char	filter_exp[100]; // Filter expression
	bpf_u_int32	netp, maskp; // IP and subnet mask of the network device

	if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1)
	{
		fprintf(stderr, "Error: Couldn't get netmask for device %s: %s\n", dev, errbuf);
		return (1);
	}

	*handle = pcap_open_live(dev, BUFSIZ, 1, timeout, errbuf);
	if (*handle == NULL)
	{
		fprintf(stderr, "Error: Couldn't open device %s: %s\n", dev, errbuf);
		return (1);
	}

	sprintf(filter_exp, "tcp and src host %s and src port %d", ip, port);

	if (pcap_compile(*handle, fp, filter_exp, 0, netp) == -1)
	{
		fprintf(stderr, "Error: Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(*handle));
		return (1);
	}

	if (pcap_setfilter(*handle, fp) == -1)
	{
		fprintf(stderr, "Error: Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(*handle));
		return (1);
	}

	return (0);
}

int	main(int argc, char **argv)
{
	if (argc < 2)
	{
		printf("Usage:\n");
		printf("> ft_nmap [--help] [--ports [NUMBER/RANGED]] --ip IP_ADDRESS [--speedup [NUMBER]] [--scan [TYPE]]\n");
		printf("Or:\n");
		printf("> ft_nmap [--help] [--ports [NUMBER/RANGED]] --file FILE [--speedup [NUMBER]] [--scan [TYPE]]\n");
	}

	t_nmap		nmap;
	nmap.args = parse_args(argc, argv);
	nmap.sockfd = -1;
	nmap.sockfd_udp = -1;

	if (nmap.args.scans[SYN] == 1 || nmap.args.scans[null] == 1 || nmap.args.scans[ACK] == 1 || nmap.args.scans[FIN] == 1 || nmap.args.scans[XMAS] == 1)
		nmap.sockfd = create_socket(IPPROTO_TCP);
	if (nmap.args.scans[UDP] == 1)
		nmap.sockfd_udp = create_socket(IPPROTO_UDP);

	nmap.destaddr = get_sockaddr(nmap.args.ip);
	if (fill_srcaddr(&nmap.srcaddr) != 0)
	{
		close_nmap(&nmap);
		return (1);
	}
	char	*dev = get_default_dev(&nmap); // Network device to capture packets from
	if (dev == NULL)
		return (1);

	// ready for threading (pthread) here (speedup) - for now, just loop through the ports
	// we create a pcap handle for each port because pcap_dispatch is blocking and not thread-safe
	// we use the same socket for each thread with a mutex
	printf("Scanning %s (%s)\n", nmap.args.ip, inet_ntoa(((struct sockaddr_in)nmap.destaddr).sin_addr));
	for (int i = 0; nmap.args.port[i] != 0; i++)
	{
		if (create_pcap(&nmap.handle, &nmap.fp, nmap.args.port[i], nmap.args.ip, nmap.alldevs->name) != 0)
		{
			close_nmap(&nmap);
			return (1);
		}
		if (send_syn_scan(nmap.sockfd, nmap.args.port[i], nmap.srcaddr, nmap.destaddr) != 0)
		{
			close_nmap(&nmap);
			return (1);
		}

		// pcap_dispatch is blocking and not thread-safe
		// when no response is received, it will block indefinitely so we need to use poll to set a timeout
		int ret = pcap_dispatch(nmap.handle, 0, packet_handler, NULL);
		if (ret == -1)
		{
			fprintf(stderr, "pcap_dispatch failed: %s\n", pcap_geterr(nmap.handle));
			return (1);
		}
		else if (ret == 0)
		{
			printf("No packets were captured\n");
		}
		close_pcap(&nmap);
	}

	close_nmap(&nmap);
	return (0);
}
