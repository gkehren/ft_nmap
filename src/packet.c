#include "../include/ft_nmap.h"

unsigned short	calculate_checksum(unsigned short *paddress, int len)
{
	int				sum = 0;
	int				count = len;
	unsigned short	oddbyte;

	while (count > 1)
	{
		sum += *paddress++;
		count -= 2;
	}

	if (count > 0)
	{
		oddbyte = 0;
		*((u_char *)&oddbyte) = *(u_char *)paddress;
		sum += oddbyte;
	}

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ((unsigned short)~sum);
}

// TODO: this function is wrong and we are not allowed to use pcap_sendpacket need to use a sockfd fron scratch
int send_syn_scan(pcap_t *handle, struct sockaddr_in destaddr, int port)
{
	// Create the IP header
	struct ip iphdr;
	memset(&iphdr, 0, sizeof(struct ip)); // Initialize the IP header
	iphdr.ip_hl = 5; // Header length
	iphdr.ip_v = 4; // Version
	iphdr.ip_tos = 0; // Type of service
	iphdr.ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr)); // Total length
	iphdr.ip_id = 0; // Identification
	iphdr.ip_off = 0; // Fragment offset
	iphdr.ip_ttl = 255; // Time to live
	iphdr.ip_p = IPPROTO_TCP; // Protocol
	iphdr.ip_sum = 0; // Checksum (calculated later)
	iphdr.ip_src.s_addr = INADDR_ANY; // Source address
	iphdr.ip_dst = destaddr.sin_addr; // Destination address
	iphdr.ip_sum = calculate_checksum((unsigned short *)&iphdr, sizeof(iphdr));

	// Create the TCP header
	struct tcphdr tcphdr;
	memset(&tcphdr, 0, sizeof(struct tcphdr)); // Initialize the TCP header
	tcphdr.th_sport = htons(12345); // Source port
	tcphdr.th_dport = htons(port); // Destination port (80 for testing purposes)
	tcphdr.th_seq = 0; // Sequence number
	tcphdr.th_ack = 0; // Acknowledgement number
	tcphdr.th_off = 5; // Data offset
	tcphdr.th_flags = TH_SYN; // Flags
	tcphdr.th_win = htons(65535); // Window
	tcphdr.th_sum = 0; // Checksum (calculated later)
	tcphdr.th_urp = 0; // Urgent pointer

	unsigned short tcp_len = sizeof(tcphdr) / sizeof(unsigned short);
	int ip_len = sizeof(struct ip) / sizeof(unsigned short);
	int total_len = ip_len + tcp_len;
	unsigned short *pseudo_packet = malloc(total_len * sizeof(unsigned short));
	memcpy(pseudo_packet, &iphdr, sizeof(struct ip));
	memcpy(pseudo_packet + ip_len, &tcphdr, sizeof(struct tcphdr));
	tcphdr.th_sum = calculate_checksum(pseudo_packet, total_len);

	// Create the packet
	char packet[sizeof(struct ip) + sizeof(struct tcphdr)] = {0};
	memcpy(packet, &iphdr, sizeof(struct ip));
	memcpy(packet + sizeof(struct ip), &tcphdr, sizeof(struct tcphdr));

	// Send the packet
	if (pcap_sendpacket(handle, (u_char *)packet, sizeof(packet)) == -1)
	{
		fprintf(stderr, "Error: %s\n", pcap_geterr(handle));
		free(pseudo_packet);
		return (1);
	}
	free(pseudo_packet);
	return (0);
}

void	packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	(void)pkthdr;
	(void)user_data;
	struct ip *iphdr = (struct ip *)(packet + 14);

	if (iphdr->ip_p != IPPROTO_TCP)
	{
		if (iphdr->ip_p == IPPROTO_ICMP)
			printf("Received ICMP packet\n");
		else if (iphdr->ip_p == IPPROTO_UDP)
			printf("Received UDP packet\n");
		else
			printf("Received packet with protocol %d\n", iphdr->ip_p);
		return;
	}

	struct tcphdr * tcphdr = (struct tcphdr *)(packet + 14 + iphdr->ip_hl * 4);

	char src_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &iphdr->ip_src, src_ip, INET_ADDRSTRLEN);
	printf("Received TCP packet from %s:%d\n", src_ip, ntohs(tcphdr->th_sport));

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
