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
	t_args	args = parse_args(argc, argv);

	printf("ip: %s\n", args.ip);
	printf("file: %s\n", args.file);
	printf("speedup: %d\n", args.speedup);
	printf("scans:\n");
	for (int i = 0; i < 6; i++)
		printf("scan[%d]: %d\n", i, args.scans[i]);

	printf("ports:\n");
	for (int i = 0; i < 1024; i++)
	{
		if (args.port[i] != 0)
			printf("port[%d]: %d\n", i, args.port[i]);
	}

	return (0);
}
