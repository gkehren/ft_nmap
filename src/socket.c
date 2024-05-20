#include "../include/ft_nmap.h"

int	create_socket(int protocol)
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

	if (protocol == IPPROTO_TCP) {
		int on = 1;
		if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1) {
			perror("setsockopt");
			return (1);
		}
	}

	return (sockfd);
}

struct sockaddr_in	get_sockaddr(char *host)
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

int fill_srcaddr(struct sockaddr_in *srcaddr)
{
	struct ifaddrs *ifaddr, *ifa;
	struct sockaddr_in local_ip;

	if (getifaddrs(&ifaddr) == -1)
	{
		perror("getifaddrs");
		return (1);
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr == NULL || strcmp(ifa->ifa_name, "lo") == 0)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET)
		{
			local_ip = *(struct sockaddr_in *)ifa->ifa_addr;
			break;
		}
	}
	freeifaddrs(ifaddr);

	srcaddr->sin_family = AF_INET;
	srcaddr->sin_port = htons(0);
	srcaddr->sin_addr.s_addr = local_ip.sin_addr.s_addr;

	return (0);
}
