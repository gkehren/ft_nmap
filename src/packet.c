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

int send_syn_scan(int sockfd, int port, struct sockaddr_in srcaddr, struct sockaddr_in destaddr)
{
	// Create the TCP header
	struct tcphdr tcphdr;
	memset(&tcphdr, 0, sizeof(struct tcphdr)); // Initialize the TCP header
	tcphdr.th_sport = htons(43906); // Source port
	tcphdr.th_dport = htons(port); // Destination port
	tcphdr.th_seq = htonl(0); // Sequence number
	tcphdr.th_ack = 0; // Acknowledgement number
	tcphdr.th_off = 5; // Data offset
	tcphdr.th_flags = TH_SYN; // Flags
	tcphdr.th_win = htons(1024); // Window
	tcphdr.th_urp = 0; // Urgent pointer

	struct iphdr iphdr;
	memset(&iphdr, 0, sizeof(struct iphdr)); // Initialize the IP header
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

	// Create the packet
	char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
	memcpy(packet, &iphdr, sizeof(struct iphdr));
	memcpy(packet + sizeof(struct iphdr), &tcphdr, sizeof(struct tcphdr));

	// Calculate checksum
	iphdr.check = 0;
	iphdr.check = calculate_checksum((unsigned short *)packet, sizeof(struct iphdr) / 2);
	memcpy(packet + 10, &iphdr.check, sizeof(iphdr.check));

	// Create the pseudo header for the TCP checksum
	struct {
		struct in_addr saddr;
		struct in_addr daddr;
		unsigned char zero;
		unsigned char protocol;
		unsigned short tcp_len;
	} pseudo_header;

	pseudo_header.saddr = srcaddr.sin_addr;
	pseudo_header.daddr = destaddr.sin_addr;
	pseudo_header.zero = 0;
	pseudo_header.protocol = IPPROTO_TCP;
	pseudo_header.tcp_len = htons(sizeof(struct tcphdr));

	// Create the pseudo packet for the TCP checksum
	char pseudo_packet[sizeof(pseudo_header) + sizeof(struct tcphdr)];
	memcpy(pseudo_packet, &pseudo_header, sizeof(pseudo_header));
	memcpy(pseudo_packet + sizeof(pseudo_header), &tcphdr, sizeof(struct tcphdr));

	// Calculate the TCP checksum
	tcphdr.th_sum = 0;
	unsigned short tcp_len = htons(sizeof(struct tcphdr));
	memcpy(pseudo_packet + sizeof(pseudo_header) - sizeof(tcp_len), &tcp_len, sizeof(tcp_len));
	tcphdr.th_sum = calculate_checksum((unsigned short *)pseudo_packet, (sizeof(pseudo_header) + sizeof(struct tcphdr)) / 2);
	memcpy(packet + sizeof(struct iphdr) + 16, &tcphdr.th_sum, sizeof(tcphdr.th_sum));

	// Update the TCP checksum in the packet
	*(unsigned short *)(packet + sizeof(struct iphdr) + 16) = tcphdr.th_sum;

	// Send the packet
	if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&destaddr, sizeof(destaddr)) == -1)
	{
		perror("sendto");
		return (1);
	}
	return (0);
}

void	packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	(void)pkthdr;
	(void)user_data;
	struct ip *iphdr = (struct ip *)(packet + 14);

	struct tcphdr * tcphdr = (struct tcphdr *)(packet + 14 + iphdr->ip_hl * 4);

	char src_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &iphdr->ip_src, src_ip, INET_ADDRSTRLEN);
	//printf("Received TCP packet from %s:%d\n", src_ip, ntohs(tcphdr->th_sport));

	if (tcphdr->th_flags & TH_SYN && tcphdr->th_flags & TH_ACK)
	{
		printf("Port %d on %s is open\n", ntohs(tcphdr->th_sport), src_ip);
	}
	else if (tcphdr->th_flags & TH_RST)
	{
		printf("Port %d on %s is closed\n", ntohs(tcphdr->th_sport), src_ip);
	}
	else
	{
		printf("Port %d on %s is filtered\n", ntohs(tcphdr->th_sport), src_ip);
	}
}
