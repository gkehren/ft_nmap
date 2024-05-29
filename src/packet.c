#include "../include/ft_nmap.h"

unsigned short	calculate_checksum(unsigned short *addr, int len)
{
	int				sum = 0;

	for (int i = 0; i < 12; i++)
		sum += addr[i];

	for (int i = 12; i < len; i++)
		sum += addr[i];

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ((unsigned short)~sum);
}

struct tcphdr	create_tcp_header(int port, int flags)
{
	struct tcphdr	tcphdr;
	memset(&tcphdr, 0, sizeof(struct tcphdr));
	tcphdr.th_sport = htons(43906); // Source port (random)
	tcphdr.th_dport = htons(port); // Destination port
	tcphdr.th_seq = htonl(42); // Sequence number
	tcphdr.th_ack = 0; // Acknowledgement number
	tcphdr.th_off = 5; // Data offset
	tcphdr.th_flags = flags; // Flags (SYN, ACK, FIN, RST, PSH, URG)
	tcphdr.th_win = htons(1024); // Window
	tcphdr.th_urp = 0; // Urgent pointer
	return (tcphdr);
}

struct iphdr	create_ip_header(struct sockaddr_in srcaddr, struct sockaddr_in destaddr, int ttl)
{
	struct iphdr	iphdr;
	memset(&iphdr, 0, sizeof(struct iphdr));
	iphdr.ihl = 5; // Header length
	iphdr.version = 4; // Version
	iphdr.tos = 0; // Type of service
	iphdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr)); // Total length
	iphdr.id = 0; // Identification
	iphdr.frag_off = htons(0); // Fragment offset
	iphdr.ttl = ttl; // Time to live
	iphdr.protocol = IPPROTO_TCP; // Protocol
	iphdr.check = 0; // Checksum
	iphdr.saddr = srcaddr.sin_addr.s_addr; // Source address
	iphdr.daddr = destaddr.sin_addr.s_addr; // Destination address
	return (iphdr);
}

unsigned short calculate_tcp_checksum(unsigned char *packet, int packet_len, struct sockaddr_in srcaddr, struct sockaddr_in destaddr)
{
	t_pseudo_header	pseudo_header;
	pseudo_header.saddr = srcaddr.sin_addr;
	pseudo_header.daddr = destaddr.sin_addr;
	pseudo_header.zero = 0;
	pseudo_header.protocol = IPPROTO_TCP;
	pseudo_header.tcp_len = htons(packet_len - sizeof(struct iphdr));

	char pseudo_packet[sizeof(pseudo_header) + packet_len - sizeof(struct iphdr)];
	memcpy(pseudo_packet, &pseudo_header, sizeof(pseudo_header));
	memcpy(pseudo_packet + sizeof(pseudo_header), packet + sizeof(struct iphdr), packet_len - sizeof(struct iphdr));

	return (calculate_checksum((unsigned short *)pseudo_packet, (sizeof(pseudo_header) + packet_len - sizeof(struct iphdr)) / 2));
}

static int send_udp_scan(int sockfd, struct sockaddr_in destaddr, pthread_mutex_t *mutex_socket, int data_length)
{
	char	data[data_length];

	for (int i = 0; i < data_length; i++)
		data[i] = 42;

	pthread_mutex_lock(mutex_socket);
	if (sendto(sockfd, data, data_length, 0, (struct sockaddr *)&destaddr, sizeof(destaddr)) == -1)
	{
		perror("sendto");
		pthread_mutex_unlock(mutex_socket);
		return (1);
	}
	pthread_mutex_unlock(mutex_socket);
	return (0);
}

static int send_tcp_scan(int sockfd, int port, int flags, struct sockaddr_in srcaddr, struct sockaddr_in destaddr, pthread_mutex_t *mutex_socket, int ttl, int data_length)
{
	char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + data_length];
	struct iphdr	iphdr = create_ip_header(srcaddr, destaddr, ttl);
	struct tcphdr	tcphdr = create_tcp_header(port, flags);

	// Create the packet
	memcpy(packet, &iphdr, sizeof(struct iphdr));
	memcpy(packet + sizeof(struct iphdr), &tcphdr, sizeof(struct tcphdr));

	for (int i = 0; i < data_length; i++)
		packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + i] = 42;

	// Calculate checksum
	iphdr.check = 0;
	iphdr.check = calculate_checksum((unsigned short *)packet, sizeof(struct iphdr) / 2);
	memcpy(packet + 10, &iphdr.check, sizeof(iphdr.check));

	// Calculate the TCP checksum
	tcphdr.th_sum = calculate_tcp_checksum((unsigned char *)packet, sizeof(packet), srcaddr, destaddr);
	memcpy(packet + sizeof(struct iphdr) + 16, &tcphdr.th_sum, sizeof(tcphdr.th_sum));

	// Update the TCP checksum in the packet
	*(unsigned short *)(packet + sizeof(struct iphdr) + 16) = tcphdr.th_sum;

	// Send the packet
	pthread_mutex_lock(mutex_socket);
	if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&destaddr, sizeof(destaddr)) == -1)
	{
		perror("sendto");
		pthread_mutex_unlock(mutex_socket);
		return (1);
	}
	pthread_mutex_unlock(mutex_socket);
	return (0);
}

int	send_scan(t_nmap *nmap, const t_scan_type scan_type, const int port) {
	static const int	tcp_scan_flags[5] = {
		TH_SYN, // SYN
		0, // NULL
		TH_FIN, // FIN
		TH_FIN | TH_PUSH | TH_URG, // XMAS
		TH_ACK // ACK
	};

	struct sockaddr_in	destaddr = nmap->destaddr;
	destaddr.sin_port = htons(port);
	if (scan_type == UDP) {
		return send_udp_scan(nmap->sockfd_udp, destaddr, &nmap->mutex_socket_udp, nmap->args.data_length);
	} else {
		return send_tcp_scan(nmap->sockfd_tcp, port, tcp_scan_flags[scan_type], nmap->srcaddr, destaddr, &nmap->mutex_socket_tcp, nmap->args.ttl, nmap->args.data_length);
	}
}

t_response_result	process_response(t_user_data *user_data, struct tcphdr *tcphdr, uint8_t timeout) {
	switch (user_data->scan_type) {
		case SYN:
			if (timeout) {
				return FILTERED;
			} else if (tcphdr->syn && tcphdr->ack) {
				return OPEN;
			} else if (tcphdr->rst) {
				return CLOSED;
			}
			break;
		case null:
			if (timeout) {
				return OPEN_FILTERED;
			} else if (tcphdr->rst) {
				return CLOSED;
			}
			break;
		case FIN:
			if (timeout) {
				return OPEN_FILTERED;
			} else if (tcphdr->rst) {
				return CLOSED;
			}
			break;
		case XMAS:
			if (timeout) {
				return OPEN_FILTERED;
			} else if (tcphdr->rst) {
				return CLOSED;
			}
			break;
		case ACK:
			if (timeout) {
				return OPEN_FILTERED;
			} else if (tcphdr->rst) {
				return UNFILTERED;
			}
			break;
		case UDP:
			if (timeout) {
				return OPEN_FILTERED;
			}
			break;
		default:
			return UNDEFINED;
	}

	return UNDEFINED;
}

void	packet_handler(u_char *user_data_arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	(void)pkthdr;
	t_user_data	*user_data = (t_user_data *)user_data_arg;
	struct ip *iphdr = (struct ip *)(packet + 14);
	struct tcphdr *tcphdr = (struct tcphdr *)(packet + 14 + iphdr->ip_hl * 4);

	user_data->nmap->args.port_data[user_data->index].response[user_data->scan_type] = process_response(user_data, tcphdr, 0);
}
