#include "../include/ft_nmap.h"

void	parse_arg_help(char **argv, int *i)
{
	if (strcmp(argv[*i], "--help") == 0)
	{
		printf("Help Screen\n");
		printf("ft_nmap [OPTIONS]\n");
		printf(" --help\t\t\tDisplay this help screen\n");
		printf(" --ports\t\tports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n");
		printf(" --ip\t\t\tip addresses to scan in dot format\n");
		printf(" --file\t\t\tFile name containing IP addresses to scan\n");
		printf(" --speedup\t\t[250 max] number of parallel threads to use\n");
		printf(" --scan\t\t\tSYN/NULL/FIN/XMAS/ACK/UDP\n");
		exit(0);
	}
}

// TODO: need to handle the case where the user provides a range of ports
// Example: --ports 1-100 or --ports 1,2,3,4,5 or --ports 1,5-15
// The ports to be scanned can be read as a range or individually. In the case no port
// is specified the scan must run with the range 1-1024.
// The number of ports scanned cannot exceed 1024.
void	parse_arg_ports(t_args *args, int argc, char **argv, int *i)
{
	if (strcmp(argv[*i], "--ports") == 0)
	{
		if (*i + 1 < argc)
		{
			(*i)++;
			args->port_begin = atoi(argv[*i]);
			args->port_end = atoi(argv[*i]);
		}
		else
		{
			printf("Error: --ports requires an argument\n");
			exit(1);
		}
	}
}

void	parse_arg_ip(t_args *args, int argc, char **argv, int *i)
{
	if (strcmp(argv[*i], "--ip") == 0)
	{
		if (*i + 1 < argc)
		{
			(*i)++;
			args->ip = argv[*i];
		}
		else
		{
			printf("Error: --ip requires an argument\n");
			exit(1);
		}
	}
}

void	parse_arg_file(t_args *args, int argc, char **argv, int *i)
{
	if (strcmp(argv[*i], "--file") == 0)
	{
		if (*i + 1 < argc)
		{
			(*i)++;
			args->file = argv[*i];
		}
		else
		{
			printf("Error: --file requires an argument\n");
			exit(1);
		}
	}
}

void	parse_arg_speedup(t_args *args, int argc, char **argv, int *i)
{
	if (strcmp(argv[*i], "--speedup") == 0)
	{
		if (*i + 1 < argc)
		{
			(*i)++;
			int speedup = atoi(argv[*i]);
			if (speedup > 250)
			{
				printf("Error: --speedup must be less than 250\n");
				exit(1);
			}
			else if (speedup < 0)
			{
				printf("Error: --speedup must be positive\n");
				exit(1);
			}
			args->speedup = speedup;
		}
		else
		{
			printf("Error: --speedup requires an argument\n");
			exit(1);
		}
	}
}

// TODO:
// We must be able to run each type of scan individually, and several scans simultaneously.
void	parse_arg_scan(t_args *args, int argc, char **argv, int *i)
{
	if (strcmp(argv[*i], "--scan") == 0)
	{
		if (*i + 1 < argc)
		{
			(*i)++;
			if (strcmp(argv[*i], "SYN") == 0)
				args->scan = SYN;
			else if (strcmp(argv[*i], "NULL") == 0)
				args->scan = null;
			else if (strcmp(argv[*i], "ACK") == 0)
				args->scan = ACK;
			else if (strcmp(argv[*i], "FIN") == 0)
				args->scan = FIN;
			else if (strcmp(argv[*i], "XMAS") == 0)
				args->scan = XMAS;
			else if (strcmp(argv[*i], "UDP") == 0)
				args->scan = UDP;
			else
			{
				printf("Error: --scan must be one of SYN/NULL/ACK/FIN/XMAS/UDP\n");
				exit(1);
			}
		}
		else
		{
			printf("Error: --scan requires an argument\n");
			exit(1);
		}
	}
}

t_args	parse_args(int argc, char **argv)
{
	t_args	args;
	int	i = 1;

	args.ip = NULL;
	args.file = NULL;
	args.port_begin = 1;
	args.port_end = 1024;
	args.speedup = 0;
	args.scan = ALL;

	while (i < argc)
	{
		parse_arg_help(argv, &i);
		parse_arg_ports(&args, argc, argv, &i);
		parse_arg_ip(&args, argc, argv, &i);
		parse_arg_file(&args, argc, argv, &i);
		parse_arg_speedup(&args, argc, argv, &i);
		parse_arg_scan(&args, argc, argv, &i);
		i++;
	}

	if (args.ip == NULL && args.file == NULL)
	{
		printf("Error: --ip or --file is required\n");
		exit(1);
	}
	else if (args.ip != NULL && args.file != NULL)
	{
		printf("Error: --ip and --file are mutually exclusive\n");
		exit(1);
	}

	return (args);
}
