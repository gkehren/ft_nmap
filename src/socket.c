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

struct sockaddr_in get_sockaddr(char *host)
{
	struct addrinfo hints, *res;
	int status;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if ((status = getaddrinfo(host, NULL, &hints, &res)) != 0)
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in ip_address = *(struct sockaddr_in *)res->ai_addr;
	freeaddrinfo(res);
	return (ip_address);
}
