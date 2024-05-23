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
		while (nmap->args.ip) {
			free(nmap->args.ip);
			nmap->args.ip = NULL;
			get_next_line(fileno(nmap->args.file_fd), &nmap->args.ip);
			if (!*nmap->args.ip) {
				free(nmap->args.ip);
				break ;
			}
		}
	}
	if (nmap->args.file_fd) {
		fclose(nmap->args.file_fd);
	}
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
