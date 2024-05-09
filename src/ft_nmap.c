#include "../include/ft_nmap.h"

void	close_nmap(t_nmap *nmap)
{
	if (nmap->sockfd != -1)
		close(nmap->sockfd);
	if (nmap->sockfd_udp != -1)
		close(nmap->sockfd_udp);
	if (nmap->handle != NULL)
		pcap_close(nmap->handle);
	if (nmap->fp.bf_insns != NULL)
		pcap_freecode(&nmap->fp);
}

int	create_pcap(t_nmap *nmap)
{
	char	errbuf[PCAP_ERRBUF_SIZE]; // Buffer for error messages
	char	*dev = "eth0"; // Network device to capture packets from
	int		timeout = 1000; // Timeout in milliseconds
	//char	filter_exp[100]; // Filter expression
	char	filter_exp[] = "tcp";
	//struct bpf_program	fp; // Compiled filter program (expression)
	bpf_u_int32	netp, maskp; // IP and subnet mask of the network device

	if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1)
	{
		fprintf(stderr, "Error: Couldn't get netmask for device %s: %s\n", dev, errbuf);
		return (1);
	}

	nmap->handle = pcap_open_live(dev, BUFSIZ, 1, timeout, errbuf);
	if (nmap->handle == NULL)
	{
		fprintf(stderr, "Error: Couldn't open device %s: %s\n", dev, errbuf);
		return (1);
	}

	//sprintf(filter_exp, "src host %s and dst host %s", nmap->args.ip, inet_ntoa(((struct sockaddr_in)nmap->destaddr).sin_addr));

	if (pcap_compile(nmap->handle, &nmap->fp, filter_exp, 0, netp) == -1)
	{
		fprintf(stderr, "Error: Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(nmap->handle));
		return (1);
	}

	if (pcap_setfilter(nmap->handle, &nmap->fp) == -1)
	{
		fprintf(stderr, "Error: Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(nmap->handle));
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

	nmap.handle = NULL;
	if (create_pcap(&nmap) != 0)
	{
		close_nmap(&nmap);
		return (1);
	}

	printf("Scanning %s (%s) on port %d\n", nmap.args.ip, inet_ntoa(((struct sockaddr_in)nmap.destaddr).sin_addr), nmap.args.port[0]);
	if (send_syn_scan(nmap.handle, nmap.destaddr, nmap.args.port[0]) != 0)
	{
		close_nmap(&nmap);
		return (1);
	}

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

	close_nmap(&nmap);
	return (0);
}
