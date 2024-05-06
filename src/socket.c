#include "../include/ft_nmap.h"

int create_socket(int protocol)
{
	int sockfd;
	if (protocol == IPPROTO_TCP)
		sockfd = socket(AF_INET, SOCK_RAW, protocol);
	else if (protocol == IPPROTO_UDP)
		sockfd = socket(AF_INET, SOCK_DGRAM, protocol);
	else
	{
		fprintf(stderr, "Error: Invalid protocol\n");
		exit(EXIT_FAILURE);
	}
	if (sockfd < 0)
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}
	return (sockfd);
}
