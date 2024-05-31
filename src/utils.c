#include "../include/ft_nmap.h"

void	close_nmap(t_nmap *nmap)
{
	if (nmap->sockfd_tcp != -1)
		close(nmap->sockfd_tcp);
	if (nmap->sockfd_udp != -1)
		close(nmap->sockfd_udp);
	if (nmap->alldevs != NULL)
		pcap_freealldevs(nmap->alldevs);
	if (nmap->args.file) {
		if (nmap->args.ip) {
			free(nmap->args.ip);
			nmap->args.ip = NULL;
		}
		while (get_next_line(fileno(nmap->args.file_fd), &nmap->args.ip) > 0) {
			free(nmap->args.ip);
		}
		free(nmap->args.ip);
	}
	if (nmap->args.file_fd) {
		fclose(nmap->args.file_fd);
	}
	if (nmap->args.rand_ip) {
		free(nmap->args.rand_ip);
	}

	if (nmap->args.excludes) {
		for (int i = 0; nmap->args.excludes[i]; ++i) {
			free(nmap->args.excludes[i]);
		}
		free(nmap->args.excludes);
	}
}

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

void	close_pcap(pcap_t *handle, struct bpf_program *fp)
{
	if (handle != NULL)
		pcap_close(handle);
	if (fp->bf_insns != NULL)
		pcap_freecode(fp);
}

void	destroy_mutex(t_nmap *nmap)
{
	pthread_mutex_destroy(&nmap->mutex_socket_tcp);
	pthread_mutex_destroy(&nmap->mutex_socket_udp);
	pthread_mutex_destroy(&nmap->mutex_index);
}

char	*get_default_dev(t_nmap *nmap)
{
	char		errbuf[PCAP_ERRBUF_SIZE] = "";

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

char *generate_random_ip(void) {
	unsigned char	byte1, byte2, byte3, byte4;
	char			*s = NULL;

	byte1 = rand() % 256;
	byte2 = rand() % 256;
	byte3 = rand() % 256;
	byte4 = rand() % 256;

	while ((byte1 == 10) || (byte1 == 172 && (byte2 >= 16 && byte2 <= 31)) || (byte1 == 192 && byte2 == 168)) {
		byte1 = rand() % 256;
		byte2 = rand() % 256;
		byte3 = rand() % 256;
		byte4 = rand() % 256;
	}

	s = (char *)malloc(sizeof(char) * 16);
	sprintf(s, "%d.%d.%d.%d", byte1, byte2, byte3, byte4);

	return s;
}

int is_excluded(char *ip, char **excludes) {
	if (!ip || !excludes || !*excludes) {
		return 0;
	}

	while (*excludes) {
		if (ft_strcmp(ip, *excludes) == 0) {
			return 1;
		}
		++excludes;
	}

	return 0;
}
