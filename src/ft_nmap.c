#include "../include/ft_nmap.h"

volatile sig_atomic_t	stop_flag = 0;
pthread_mutex_t			mutex_flag;

static t_response_result	get_conclusion(t_response_result response_results[6], t_scan_type scans[6]) {
	if (scans[SYN]) {
		if (response_results[SYN] == OPEN) {
			return OPEN;
		} else if (response_results[SYN] == CLOSED) {
			return CLOSED;
		}
	}

	int scans_amt = 0;

	for (int scan_index = 0; scan_index < 6; ++scan_index) {
		if (scans[scan_index]) {
			++scans_amt;
		}
	}

	if (scans_amt == 1) {
		for (int scan_index = 0; scan_index < 6; ++scan_index) {
			if (scans[scan_index]) {
				return response_results[scan_index];
			}
		}
	}

	t_scan_type	response_count[6] = {0};

	for (int scan_index = 0; scan_index < 6; ++scan_index) {
		if (scans[scan_index]) {
			++response_count[response_results[scan_index]];
		}
	}

	uint8_t		max_res_index = 0;
	uint8_t		max_res = response_count[max_res_index];
	uint8_t		dupes = 0;

	for (int response_index = 1; response_index < 6; ++response_index) {
		if (response_count[response_index] > max_res) {
			max_res_index = response_index;
			max_res = response_count[max_res_index];
			dupes = 0;
		} else if (response_count[response_index] == max_res) {
			++dupes;
		}
	}


	if (!dupes) {
		return max_res_index;
	} else {
		for (int scan_index = 0; scan_index < 6; ++scan_index) {
			if (scans[scan_index] && response_count[response_results[scan_index]] == max_res) {
				return response_results[scan_index];
			}
		}
	}

	return UNDEFINED;
}

int		get_next_port(t_nmap *nmap, uint16_t *index)
{
	int	port = 0;

	pthread_mutex_lock(&nmap->mutex_index);
	if (nmap->index >= 1024) {
	pthread_mutex_unlock(&nmap->mutex_index);
		return 0;
	}
	port = nmap->args.port_data[nmap->index].port;
	*index = nmap->index;
	nmap->index++;
	pthread_mutex_unlock(&nmap->mutex_index);

	return (port);
}

void scan_services(t_nmap *nmap) {
	struct servent *service = NULL;
	int index = 0;

	while (nmap->args.port_data[index].port) {
		int scan_index = 0;

		while (scan_index < 6) {
			if (nmap->args.scans[scan_index]) {
				service = getservbyport(htons(nmap->args.port_data[index].port), scan_index == UDP ? "udp" : "tcp");
				if (service) {
					ft_strcpy(nmap->args.port_data[index].service, service->s_name);
				}
			}

			scan_index++;
		}

		index++;
	}
}

void	*thread_scan(void *arg)
{
	t_nmap			*nmap = (t_nmap *)arg;
	t_user_data		user_data = {0};

	user_data.nmap = nmap;
	while ((user_data.port = get_next_port(nmap, &user_data.index)) > 0)
	{
		pthread_mutex_lock(&mutex_flag);
		if (stop_flag == 1)
		{
			pthread_mutex_unlock(&mutex_flag);
			break ;
		}
		pthread_mutex_unlock(&mutex_flag);

		int scan_index = 0;

		while (scan_index < 6) {
			if (nmap->args.scans[scan_index]) {
				write(1, ".", 1);
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
					nmap->args.port_data[user_data.index].response[user_data.scan_type] = process_response(&user_data, 0, 1);
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
							nmap->args.port_data[user_data.index].response[user_data.scan_type] = process_response(&user_data, 0, 1);
						}
					}
				}
				close_pcap(handle, &fp);
			}
			scan_index++;
		}
		if ((nmap->args.port_data[user_data.index].conclusion = get_conclusion(nmap->args.port_data[user_data.index].response, nmap->args.scans)) == OPEN) {
			nmap->args.opened_ports++;
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
	pthread_mutex_init(&mutex_flag, NULL);
	nmap->index = 0;
	nmap->args.opened_ports = 0;

	uint16_t n_threads = nmap->args.speedup;
	int thread_count = 0;

	if (nmap->args.speedup == 0)
	{
		thread_scan(nmap);
	}
	else
	{
		for (int i = 0; i < n_threads; i++)
		{
			pthread_mutex_lock(&mutex_flag);
			if (stop_flag == 1)
			{
				pthread_mutex_unlock(&mutex_flag);
				break ;
			}
			pthread_mutex_unlock(&mutex_flag);

			if (pthread_create(&threads[i], NULL, thread_scan, (void *)nmap) != 0)
			{
				fprintf(stderr, "Error: Couldn't create thread\n");
				destroy_mutex(nmap);
				return (1);
			}
			thread_count++;
		}
		for (int i = 0; i < thread_count; i++)
		{
			if (pthread_join(threads[i], NULL) != 0)
			{
				fprintf(stderr, "Error: Couldn't join thread\n");
				destroy_mutex(nmap);
				return (1);
			}
		}
	}

	destroy_mutex(nmap);
	return (0);
}

void	sig_handler(int sig, siginfo_t *info, void *ucontext)
{
	(void)info;
	(void)ucontext;
	if (sig == SIGINT)
	{
		pthread_mutex_lock(&mutex_flag);
		stop_flag = 1;
		pthread_mutex_unlock(&mutex_flag);
		printf("\nSIGINT received, shutting down..\n");
	}
}

int	main(int argc, char **argv)
{
	if (argc < 2)
	{
		printf("Usage:\n");
		printf("> ft_nmap [--help] [--ports [NUMBER/RANGED]] --ip IP_ADDRESS [--speedup [NUMBER]] [--scan [TYPE]] [--spoof [IP_ADDRESS]] [--exclude [IP_ADDRESS/HOSTNAME]] [--exclude-ports [NUMBER/RANGED]]\n");
		printf("Or:\n");
		printf("> ft_nmap [--help] [--ports [NUMBER/RANGED]] --file FILE [--speedup [NUMBER]] [--scan [TYPE]] [--spoof [IP_ADDRESS]] [--exclude [IP_ADDRESS/HOSTNAME]] [--exclude-ports [NUMBER/RANGED]]\n");
		printf("Or:\n");
		printf("> ft_nmap [--help] [--ports [NUMBER/RANGED]] --random N [--speedup [NUMBER]] [--scan [TYPE]] [--spoof [IP_ADDRESS]] [--exclude [IP_ADDRESS/HOSTNAME]] [--exclude-ports [NUMBER/RANGED]]\n");
		printf("\n");
		return (0);
	}

	struct sigaction	sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = sig_handler;

	if (sigaction(SIGINT, &sa, NULL) == -1)
	{
		fprintf(stderr, "Error: Couldn't set signal handler\n");
		return (1);
	}

	t_nmap		nmap = {0};
	nmap.args = parse_args(argc, argv);
	nmap.sockfd_tcp = -1;
	nmap.sockfd_udp = -1;

	if (nmap.args.scans[SYN] == 1 || nmap.args.scans[null] == 1 || nmap.args.scans[ACK] == 1 || nmap.args.scans[FIN] == 1 || nmap.args.scans[XMAS] == 1)
		nmap.sockfd_tcp = create_socket(IPPROTO_TCP, -1);
	if (nmap.args.scans[UDP] == 1)
		nmap.sockfd_udp = create_socket(IPPROTO_UDP, nmap.args.ttl);

	char	*dev = get_default_dev(&nmap); // Network device to capture packets from
	if (dev == NULL)
		return (1);

	if (fill_srcaddr(&nmap, &nmap.srcaddr) != 0) {
		close_nmap(&nmap);
		return (1);
	}

	while (nmap.args.ip && *nmap.args.ip) {
		nmap.destaddr = get_sockaddr(&nmap, nmap.args.ip);
		if (!is_excluded(inet_ntoa(((struct sockaddr_in)nmap.destaddr).sin_addr), nmap.args.excludes)) {

			display_start_data(&nmap);

			struct timeval scan_start_time;
			gettimeofday(&scan_start_time, 0);

			if (scan(&nmap) != 0) {
				close_nmap(&nmap);
				return (1);
			}

			if (stop_flag == 1)
				break ;

			scan_services(&nmap);

			display_end_data(&nmap, scan_start_time);
		} else {
			printf("Ip Address '%s' (%s) is excluded.\n", nmap.args.ip, inet_ntoa(((struct sockaddr_in)nmap.destaddr).sin_addr));
		}

		if (nmap.args.file) {
			if (nmap.args.ip) {
				free(nmap.args.ip);
				nmap.args.ip = NULL;
			}
			get_next_line(fileno(nmap.args.file_fd), &nmap.args.ip);
		} else if (nmap.args.rand_ip_amt && nmap.args.rand_ip_amt != RAND_IP_AMT_INIT) {
			if (nmap.args.rand_ip_amt > 0) {
				--nmap.args.rand_ip_amt;
			}
			free(nmap.args.rand_ip);
			nmap.args.rand_ip = NULL;
			if ((nmap.args.rand_ip = generate_random_ip()) == NULL) {
				fprintf(stderr, "generate_random_ip malloc error\n");
				close_nmap(&nmap);
				exit(EXIT_FAILURE);
			}
			nmap.args.ip = nmap.args.rand_ip;
		} else {
			break ;
		}

		write(1, "\n\n", 2);
	}

	close_nmap(&nmap);
	return (0);
}
