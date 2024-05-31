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
# include <poll.h>
# include <signal.h>

# include "../libft/libft.h"


# define FINAL_DISPLAY_NEWLINE "\n                                    "
# define RAND_IP_AMT_INIT -2

typedef enum e_scan_type
{
	SYN, // = TH_SYN,
	null, // = 0,
	FIN, // = TH_FIN,
	XMAS, // = TH_FIN | TH_PUSH | TH_URG,
	ACK, // = TH_ACK,
	UDP
}	t_scan_type ;

# define SCAN_TYPE_STRING { \
	"SYN", \
	"NULL", \
	"FIN", \
	"XMAS", \
	"ACK", \
	"UDP" \
}

typedef enum e_response_result
{
	UNDEFINED		= 0,
	CLOSED			= 1,
	OPEN			= 2,
	FILTERED		= 3,
	OPEN_FILTERED	= 4,
	UNFILTERED		= 5
}	t_response_result ;

# define RESPONSE_RESULT_STRING { \
	"Undefined", \
	"Closed", \
	"Open", \
	"Filtered", \
	"Open|Filtered", \
	"Unfiltered" \
}

typedef struct s_port_data {
	uint16_t			port;
	t_response_result	response[6];
	char				service[256];
	t_response_result	conclusion;
}	t_port_data;

typedef struct s_port_range {
	uint16_t			min;
	uint16_t			max;
}	t_port_range;

typedef struct s_args
{
	char			*ip;
	char			*spoof;
	char			*rand_ip;
	char			*file;
	char			**excludes;
	FILE			*file_fd;
	t_port_range	*exclude_ports_range;
	int				exclude_ports_range_size;
	t_port_data		port_data[1024];
	uint16_t		speedup;
	int				rand_ip_amt;
	t_scan_type		scans[6];
	uint16_t		total_ports;
	uint16_t		opened_ports;
	uint16_t		ttl;
	uint16_t		data_length;
}	t_args;

typedef struct s_nmap
{
	t_args					args;
	uint16_t				index;
	int						sockfd_tcp;
	int						sockfd_udp;
	pcap_if_t				*alldevs;
	struct sockaddr_in		srcaddr;
	struct sockaddr_in		destaddr;
	pthread_mutex_t			mutex_socket_tcp;
	pthread_mutex_t			mutex_socket_udp;
	pthread_mutex_t			mutex_index;
}	t_nmap;

typedef struct s_user_data {
	t_nmap			*nmap;
	t_scan_type		scan_type;
	uint16_t		port;
	uint16_t		index;
}	t_user_data;

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
int					create_socket(int protocol, int ttl);
struct sockaddr_in	get_sockaddr(t_nmap *nmap, char *host);
int					fill_srcaddr(t_nmap *nmap, struct sockaddr_in *srcaddr);

// packet.c
int					send_scan(t_nmap *nmap, enum e_scan_type scan_type, int port);
void				packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
t_response_result	process_response(t_user_data *user_data, struct tcphdr *tcphdr, uint8_t timeout);

// utils.c
void				close_nmap(t_nmap *nmap);
int					create_pcap(pcap_t **handle, struct bpf_program *fp, int port, char *ip, char *dev);
void				close_pcap(pcap_t *handle, struct bpf_program *fp);
void				destroy_mutex(t_nmap *nmap);
char				*get_default_dev(t_nmap *nmap);
char				*generate_random_ip(void);
int					is_excluded(char *ip, char **excludes);

// display.c
void				display_start_data(t_nmap *nmap);
void				display_end_data(t_nmap *nmap, struct timeval scan_start_time);

#endif
