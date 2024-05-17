#ifndef FT_NMAP_H
# define FT_NMAP_H

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <arpa/inet.h>
# include <sys/socket.h>
# include <unistd.h>
# include <sys/types.h>
# include <sys/time.h>
# include <errno.h>
# include <fcntl.h>
# include <signal.h>
# include <sys/ioctl.h>
# include <netdb.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>
# include <netinet/in.h>
# include <pcap.h>
# include <ifaddrs.h>
# include <pthread.h>

# include "../libft/libft.h"

enum scan_type
{
	SYN,
	null,
	ACK,
	FIN,
	XMAS,
	UDP
};

typedef struct s_args
{
	char			*ip;
	char			*file;
	int				port[1024];
	int				speedup;
	int				scans[6];
}	t_args;

typedef struct s_nmap
{
	t_args				args;
	int					index;
	int					sockfd;
	int					sockfd_udp;
	pcap_if_t			*alldevs;
	struct sockaddr_in	srcaddr;
	struct sockaddr_in	destaddr;
	pthread_mutex_t		mutex_socket;
	pthread_mutex_t		mutex_index;
}	t_nmap;

typedef struct s_pseudo_header
{
	struct in_addr	saddr;
	struct in_addr	daddr;
	unsigned char	zero;
	unsigned char	protocol;
	unsigned short	tcp_len;
}	t_pseudo_header;

t_args	parse_args(int argc, char **argv);

void	close_nmap(t_nmap *nmap);

// socket.c
int					create_socket(int protocol);
struct sockaddr_in	get_sockaddr(char *host);
int					fill_srcaddr(struct sockaddr_in *srcaddr);

// packet.c
int					send_syn_scan(int sockfd, int port, struct sockaddr_in srcaddr, struct sockaddr_in destaddr, pthread_mutex_t *mutex_socket);
void				packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);

// utils.c
void				close_nmap(t_nmap *nmap);
void				close_pcap(pcap_t *handle, struct bpf_program *fp);
void				destroy_mutex(t_nmap *nmap);
char				*get_default_dev(t_nmap *nmap);

#endif
