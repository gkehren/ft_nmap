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

int		get_next_port(t_nmap *nmap, uint16_t *index)
{
	int	port = 0;

	pthread_mutex_lock(&nmap->mutex_index);
	port = nmap->args.port_data[nmap->index].port;
	*index = nmap->index;
	nmap->index++;
	pthread_mutex_unlock(&nmap->mutex_index);

	return (port);
}

void	*thread_scan(void *arg)
{
	t_nmap			*nmap = (t_nmap *)arg;
	t_user_data		user_data = {0};

	user_data.nmap = nmap;
	while ((user_data.port = get_next_port(nmap, &user_data.index)) != 0)
	{
		int scan_index = 0;

		while (scan_index < 6) {
			if (nmap->args.scans[scan_index]) {
				pcap_t	*handle;
				struct bpf_program	fp;

				user_data.scan_type = scan_index;
				if (create_pcap(&handle, &fp, user_data.port, nmap->args.ip, nmap->alldevs->name) != 0)
				{
					close_pcap(handle, &fp);
					return (void *)1;
				}

				if (send_scan(nmap, scan_index, user_data.port) != 0) {
					close_pcap(handle, &fp);
					destroy_mutex(nmap);
					return (void *)1;
				}

				int	fd = pcap_get_selectable_fd(handle);
				if (fd == -1)
				{
					fprintf(stderr, "pcap_get_selectable_fd failed: %s\n", pcap_geterr(handle));
					close_pcap(handle, &fp);
					destroy_mutex(nmap);
					return (void *)1;
				}

				int	timeout = 500;
				struct pollfd	pfd = {fd, POLLIN, timeout};

				int	ret = poll(&pfd, 1, timeout);
				if (ret == -1) {
					fprintf(stderr, "poll failed: %s\n", strerror(errno));
					close_pcap(handle, &fp);
					destroy_mutex(nmap);
					return (void *)1;
				}
				else if (ret == 0) {
					user_data.nmap->args.port_data[user_data.index].response[user_data.scan_type] = process_response(&user_data, 0, 1);
				}
				else {
					if (pfd.revents & POLLIN) {
						int ret = pcap_dispatch(handle, 1, packet_handler, (u_char *)&user_data);
						if (ret == -1) {
							fprintf(stderr, "pcap_dispatch failed: %s\n", pcap_geterr(handle));
							close_pcap(handle, &fp);
							return (void *)1;
						}
						else if (ret == 0) {
							user_data.nmap->args.port_data[user_data.index].response[user_data.scan_type] = process_response(&user_data, 0, 1);
						}
					}
				}
				close_pcap(handle, &fp);

			}
			// Doit etre remplace par une fonction qui va faire la conclusion
			user_data.nmap->args.port_data[user_data.index].conclusion = UNDEFINED;
			scan_index++;
		}
	}

	return (void *)0;
}

int	scan(t_nmap *nmap)
{
	pthread_t	threads[nmap->args.speedup];

	pthread_mutex_init(&nmap->mutex_socket_tcp, NULL);
	pthread_mutex_init(&nmap->mutex_socket_udp, NULL);
	pthread_mutex_init(&nmap->mutex_index, NULL);
	nmap->index = 0;
	nmap->args.opened_ports = 0;

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

	t_nmap		nmap = {0};
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

	nmap.args.total_ports = 0;
    for (int i = 0; i < 1024; ++i) {
        if (nmap.args.port_data[i].port == 0) {
            break ;
        }
        ++nmap.args.total_ports;
    }
	printf(
		"Scan Configurations\n" \
		"Target Ip-Address : %s (%s)\n" \
		"No of Ports to scan : %d\n" \
		"Scans to be performed :",
		nmap.args.ip, inet_ntoa(((struct sockaddr_in)nmap.destaddr).sin_addr), nmap.args.total_ports
	);

    const char   scan_type_string[6][5] = SCAN_TYPE_STRING;

	for (int i = 0; i < 6 ; ++i) {
		if (nmap.args.scans[i]) {
			printf(" %s", scan_type_string[i]);
		}
	}

	printf(
		"\nNo of threads : %d\n" \
		"Scanning..\n",
		nmap.args.speedup
	);

	struct timeval scan_start_time;
	gettimeofday(&scan_start_time, 0);

	if (scan(&nmap) != 0)
	{
		close_nmap(&nmap);
		return (1);
	}

	display_final_data(&nmap, scan_start_time);
	close_nmap(&nmap);
	return (0);
}
