#include "../include/ft_nmap.h"

void	close_nmap(t_nmap *nmap)
{
	if (nmap->sockfd != -1)
		close(nmap->sockfd);
	if (nmap->sockfd_udp != -1)
		close(nmap->sockfd_udp);
	if (nmap->handle != NULL)
		pcap_close(nmap->handle);
}

int	create_pcap(t_nmap *nmap)
{
	char	errbuf[PCAP_ERRBUF_SIZE]; // Buffer for error messages
	char	*dev = "eth0"; // Network device to capture packets from
	int		snaplen = 65353; // Maximum number of bytes to capture per packet
	int		promisc = 1; // Set the device in promiscuous mode
	int		timeout = 1000; // Timeout in milliseconds

	nmap->handle = pcap_open_live(dev, snaplen, promisc, timeout, errbuf);
	if (nmap->handle == NULL)
	{
		fprintf(stderr, "Error: Couldn't open device %s: %s\n", dev, errbuf);
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

	if (send_syn_scan(nmap.handle, nmap.destaddr, 80) != 0)
	{
		close_nmap(&nmap);
		return (1);
	}

	// packet_handler will be call for each packet received
	if (pcap_loop(nmap.handle, 0, packet_handler, NULL) < 0)
	{
		fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(nmap.handle));
		return (1);
	}

	close_nmap(&nmap);
	return (0);
}
