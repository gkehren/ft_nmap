#include "../include/ft_nmap.h"

int	create_pcap(pcap_t **handle, struct bpf_program *fp, int port, char *ip, char *dev)
{
	char	errbuf[PCAP_ERRBUF_SIZE]; // Buffer for error messages
	int		timeout = 500; // Timeout in milliseconds
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

int		get_next_port(t_nmap *nmap)
{
	int	port = 0;

	pthread_mutex_lock(&nmap->mutex_index);
	port = nmap->args.port[nmap->index];
	nmap->index++;
	pthread_mutex_unlock(&nmap->mutex_index);

	return (port);
}

void	*thread_scan(void *arg)
{
	t_nmap	*nmap = (t_nmap *)arg;
	int		port = 0;

	while ((port = get_next_port(nmap)) != 0)
	{
		int scan_index = 0;

		while (scan_index < 6) {
			if (nmap->args.scans[scan_index]) {
				printf("PORT: %d, SCAN_TYPE[%d]: %d\n", port, nmap->args.scans[scan_index], scan_index);
				pcap_t	*handle;
				struct bpf_program	fp;

				if (create_pcap(&handle, &fp, port, nmap->args.ip, nmap->alldevs->name) != 0)
				{
					close_pcap(handle, &fp);
					return (void *)1;
				}

				if (send_scan(nmap, scan_index, port) != 0) {
					close_pcap(handle, &fp);
					destroy_mutex(nmap);
					return (void *)1;
				}

				int ret = pcap_dispatch(handle, 1, packet_handler, NULL);
				if (ret == -1)
				{
					fprintf(stderr, "pcap_dispatch failed: %s\n", pcap_geterr(handle));
					close_pcap(handle, &fp);
					return (void *)1;
				}
				else if (ret == 0)
				{
					printf("No packet were captured\n");
				} else {
					printf("Packet successfully captured\n");
				}
				// write(1, "Received\n\n", 10);
				close_pcap(handle, &fp);

			}
			scan_index++;
			write(1, "\n", 1);
		}
	}

	return (void *)0;
}

int	scan(t_nmap *nmap)
{
	pthread_t	threads[nmap->args.speedup];

	pthread_mutex_init(&nmap->mutex_socket_tcp, NULL);
	pthread_mutex_init(&nmap->mutex_index, NULL);
	nmap->index = 0;

	for (int i = 0; i < nmap->args.speedup; i++)
	{
		if (pthread_create(&threads[i], NULL, thread_scan, (void *)nmap) != 0)
		{
			fprintf(stderr, "Error: Couldn't create thread\n");
			destroy_mutex(nmap);
			return (1);
		}
	}

	for (int i = 0; i < nmap->args.speedup; i++)
	{
		if (pthread_join(threads[i], NULL) != 0)
		{
			fprintf(stderr, "Error: Couldn't join thread\n");
			destroy_mutex(nmap);
			return (1);
		}
	}

	destroy_mutex(nmap);
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
	nmap.sockfd_tcp = -1;
	nmap.sockfd_udp = -1;

	if (nmap.args.scans[SYN] == 1 || nmap.args.scans[null] == 1 || nmap.args.scans[ACK] == 1 || nmap.args.scans[FIN] == 1 || nmap.args.scans[XMAS] == 1)
		nmap.sockfd_tcp = create_socket(IPPROTO_TCP);
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

	printf("Scanning %s (%s)\n", nmap.args.ip, inet_ntoa(((struct sockaddr_in)nmap.destaddr).sin_addr));
	if (scan(&nmap) != 0)
	{
		close_nmap(&nmap);
		return (1);
	}
	close_nmap(&nmap);
	return (0);
}
