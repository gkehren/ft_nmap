#include "../include/ft_nmap.h"

void	close_nmap(t_nmap *nmap)
{
	if (nmap->sockfd != -1)
		close(nmap->sockfd);
	if (nmap->sockfd_udp != -1)
		close(nmap->sockfd_udp);
}

int	main(int argc, char **argv)
{
	if (argc < 2)
	{
		printf("Usage:\n");
		printf("> ft_nmap [--help] [--ports [NUMBER/RANGED]] --ip IP_ADDRESS [--speedup [NUMBER]] [--scan [TYPE]]\n");
		printf("Or:\n");
		printf("> ft_nmap [--help] [--ports [NUMBER/RANGED]] --file FILE [--speedup [NUMBER]] [--scan [TYPE]]\n");
	}

	t_nmap		nmap;
	nmap.args = parse_args(argc, argv);
	nmap.sockfd = -1;
	nmap.sockfd_udp = -1;

	if (nmap.args.scans[SYN] == 1 || nmap.args.scans[null] == 1 || nmap.args.scans[ACK] == 1 || nmap.args.scans[FIN] == 1 || nmap.args.scans[XMAS] == 1)
		nmap.sockfd = create_socket(IPPROTO_TCP);
	if (nmap.args.scans[UDP] == 1)
		nmap.sockfd_udp = create_socket(IPPROTO_UDP);

	nmap.destaddr = get_sockaddr(nmap.args.ip);

	printf("sockfd: %d\n", nmap.sockfd);
	printf("sockfd_udp: %d\n", nmap.sockfd_udp);
	printf("ip: %s\n", inet_ntoa(nmap.destaddr.sin_addr));

	close_nmap(&nmap);
	return (0);
}
