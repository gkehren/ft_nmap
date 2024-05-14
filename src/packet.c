#include "../include/ft_nmap.h"

unsigned short	calculate_checksum(unsigned short *paddress, int len)
{
	int				sum = 0;

	for (int i = 0; i < 12; i++)
		sum += paddress[i];

	for (int i = 12; i < len; i++)
		sum += paddress[i];

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

	char options[4]; // Maximum Segment Size (MSS) option
	options[0] = 2; // Option kind: Maximum Segment Size
	options[1] = 4; // Option length: 4 bytes
	*(unsigned short *)&options[2] = htons(1460); // Maximum Segment Size

	// Create the packet
	char packet[sizeof(struct tcphdr) + sizeof(options)] = {0};
	memcpy(packet, &tcphdr, sizeof(struct tcphdr));
	memcpy(packet + sizeof(struct tcphdr), options, sizeof(options));

	// Calculate checksum
	unsigned short pseudo_packet[12 + sizeof(packet) / 2];
	pseudo_packet[0] = srcaddr.sin_addr.s_addr >> 16;
	pseudo_packet[1] = srcaddr.sin_addr.s_addr & 0xffff;
	pseudo_packet[2] = destaddr.sin_addr.s_addr >> 16;
	pseudo_packet[3] = destaddr.sin_addr.s_addr & 0xffff;
	pseudo_packet[4] = htons(IPPROTO_TCP);
	pseudo_packet[5] = htons(sizeof(packet));
	memcpy(&pseudo_packet[6], packet, sizeof(packet));
	unsigned short checksum = calculate_checksum(pseudo_packet, 6 + sizeof(packet) / 2);

	// Update the checksum
	tcphdr.th_sum = checksum;
	*(unsigned short *)(packet + 16) = checksum;

	// Update the data offset
	tcphdr.th_off += sizeof(options) / 4;

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
