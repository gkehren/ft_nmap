#ifndef FT_NMAP_H
# define FT_NMAP_H

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <arpa/inet.h>
# include <sys/socket.h>
# include <netinet/in.h>
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
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
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
	t_args	args;
	int		sockfd;
	int		sockfd_udp;
	struct sockaddr_in	destaddr;
}	t_nmap;

t_args	parse_args(int argc, char **argv);

// socket.c
int create_socket(int protocol);

#endif
