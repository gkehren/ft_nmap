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
	pcap_t				*handle;
	int					sockfd;
	int					sockfd_udp;
	struct bpf_program	fp;
	pcap_if_t			*alldevs;
	struct sockaddr_in	srcaddr;
	struct sockaddr_in	destaddr;
}	t_nmap;

t_args	parse_args(int argc, char **argv);

void	close_nmap(t_nmap *nmap);

// socket.c
int		create_socket(int protocol);
struct	sockaddr_in get_sockaddr(char *host);

// packet.c
int		send_syn_scan(int sockfd, int port, struct sockaddr_in srcaddr, struct sockaddr_in destaddr);
void	packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);

#endif
