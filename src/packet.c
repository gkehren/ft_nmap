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
	tcphdr.th_seq = htonl(0); // Sequence number
	tcphdr.th_ack = 0; // Acknowledgement number
	tcphdr.th_off = 5; // Data offset
	tcphdr.th_flags = flags; // Flags (SYN, ACK, FIN, RST, PSH, URG)
	tcphdr.th_win = htons(1024); // Window
	tcphdr.th_urp = 0; // Urgent pointer
	return (tcphdr);
}

struct iphdr	create_ip_header(struct sockaddr_in srcaddr, struct sockaddr_in destaddr)
{
	struct iphdr	iphdr;
	iphdr.ihl = 5; // Header length
	iphdr.version = 4; // Version
	iphdr.tos = 0; // Type of service
	iphdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr)); // Total length
	iphdr.id = 0; // Identification
	iphdr.frag_off = htons(0); // Fragment offset
	iphdr.ttl = 64; // Time to live
	iphdr.protocol = IPPROTO_TCP; // Protocol
	iphdr.check = 0; // Checksum
	iphdr.saddr = srcaddr.sin_addr.s_addr; // Source address
	iphdr.daddr = destaddr.sin_addr.s_addr; // Destination address

	iphdr.check = 0;
	iphdr.check = calculate_checksum((unsigned short *)&iphdr, sizeof(struct iphdr));
	return iphdr;
}

unsigned short calculate_tcp_checksum(struct tcphdr tcphdr, struct sockaddr_in srcaddr, struct sockaddr_in destaddr)
{
	t_pseudo_header	pseudo_header;
	pseudo_header.saddr = srcaddr.sin_addr;
	pseudo_header.daddr = destaddr.sin_addr;
	pseudo_header.zero = 0;
	pseudo_header.protocol = IPPROTO_TCP;
	pseudo_header.tcp_len = htons(sizeof(struct tcphdr));

	char pseudo_packet[sizeof(pseudo_header) + sizeof(struct tcphdr)];
	memcpy(pseudo_packet, &pseudo_header, sizeof(pseudo_header));
	memcpy(pseudo_packet + sizeof(pseudo_header), &tcphdr, sizeof(struct tcphdr));

	tcphdr.th_sum = 0;
	unsigned short tcp_len = htons(sizeof(struct tcphdr));
	memcpy(pseudo_packet + sizeof(pseudo_header) - sizeof(tcp_len), &tcp_len, sizeof(tcp_len));
	return (calculate_checksum((unsigned short *)pseudo_packet, (sizeof(pseudo_header) + sizeof(struct tcphdr)) / 2));
}

static int send_udp_scan(int sockfd, struct sockaddr_in destaddr, pthread_mutex_t *mutex_socket)
{
	pthread_mutex_lock(mutex_socket);
	if (sendto(sockfd, 0, 0, 0, (struct sockaddr *)&destaddr, sizeof(destaddr)) == -1)
	{
		perror("sendto");
		pthread_mutex_unlock(mutex_socket);
		return (1);
	}
	write(1, "UDP Sent\n", 9);
	pthread_mutex_unlock(mutex_socket);
	return (0);
}

static int send_tcp_scan(int sockfd, int port, int flags, struct sockaddr_in srcaddr, struct sockaddr_in destaddr, pthread_mutex_t *mutex_socket)
{
	char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
	struct iphdr	iphdr = create_ip_header(srcaddr, destaddr);
	struct tcphdr	tcphdr = create_tcp_header(port, flags);


	// iphdr.check = 0;
	// iphdr.check = calculate_checksum((unsigned short *)&iphdr, sizeof(struct iphdr));

	// tcphdr.check = 0;
	// tcphdr.check = calculate_checksum((unsigned short *)&tcphdr, sizeof(struct tcphdr));

	// memcpy(packet, &iphdr, sizeof(struct iphdr));
	// memcpy(packet + sizeof(struct iphdr), &tcphdr, sizeof(struct tcphdr));


	// Create the packet
	memcpy(packet, &iphdr, sizeof(struct iphdr));
	memcpy(packet + sizeof(struct iphdr), &tcphdr, sizeof(struct tcphdr));

	// Calculate checksum
	iphdr.check = 0;
	iphdr.check = calculate_checksum((unsigned short *)packet, sizeof(struct iphdr) / 2);
	memcpy(packet + 10, &iphdr.check, sizeof(iphdr.check));

	// Calculate the TCP checksum
	tcphdr.th_sum = calculate_tcp_checksum(tcphdr, srcaddr, destaddr);
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
	write(1, "TCP Sent\n", 9);
	pthread_mutex_unlock(mutex_socket);
	return (0);
}

int	send_scan(t_nmap *nmap, const e_scan_type scan_type, const int port) {
	static const int	tcp_scan_flags[5] = {
		0, // NULL
		TH_SYN, // SYN
		TH_ACK, // ACK
		TH_FIN, // FIN
		TH_FIN | TH_PUSH | TH_URG // XMAS
	};

	nmap->destaddr.sin_port = htons(port);
	if (scan_type == UDP) {
		return send_udp_scan(nmap->sockfd_udp, nmap->destaddr, &nmap->mutex_socket_udp);
	} else {
		return send_tcp_scan(nmap->sockfd_tcp, port, tcp_scan_flags[scan_type], nmap->srcaddr, nmap->destaddr, &nmap->mutex_socket_tcp);
	}
}

void	packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	(void)pkthdr;
	(void)user_data;
	struct ip *iphdr = (struct ip *)(packet + 14);

	struct tcphdr * tcphdr = (struct tcphdr *)(packet + 14 + iphdr->ip_hl * 4);

	char src_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &iphdr->ip_src, src_ip, INET_ADDRSTRLEN);
	printf("Received TCP packet from %s:%d\n", src_ip, ntohs(tcphdr->th_sport));

	if (tcphdr->th_flags & TH_SYN && tcphdr->th_flags & TH_ACK)
	{
		printf("Port %d is open\n", ntohs(tcphdr->th_sport));
	}
	else if (tcphdr->th_flags & TH_RST)
	{
		printf("Port %d is closed\n", ntohs(tcphdr->th_sport));
	}
	else
	{
		printf("Port %d is filtered\n", ntohs(tcphdr->th_sport));
	}
}
