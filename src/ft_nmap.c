#include "../include/ft_nmap.h"

int	main(int argc, char **argv)
{
	if (argc < 2)
	{
		printf("Usage:\n");
		printf("> ft_nmap [--help] [--ports [NUMBER/RANGED]] --ip IP_ADDRESS [--speedup [NUMBER]] [--scan [TYPE]]\n");
		printf("Or:\n");
		printf("> ft_nmap [--help] [--ports [NUMBER/RANGED]] --file FILE [--speedup [NUMBER]] [--scan [TYPE]]\n");
	}
	t_args args = parse_args(argc, argv);

	printf("ip: %s\n", args.ip);
	printf("file: %s\n", args.file);
	printf("port_begin: %d\n", args.port_begin);
	printf("port_end: %d\n", args.port_end);
	printf("speedup: %d\n", args.speedup);
	printf("scan: %d\n", args.scan);

	return (0);
}
