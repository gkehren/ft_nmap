#include "../include/ft_nmap.h"

void exit_parsing(t_args* args, int ret) {
	while (args->ip) {
		free(args->ip);
		args->ip = NULL;
		get_next_line(fileno(args->file_fd), &args->ip);
		if (!*args->ip) {
			free(args->ip);
			break ;
		}
	}
	if (args->file_fd) {
		fclose(args->file_fd);
	}

	exit(ret);
}

void	parse_arg_help(t_args *args, char **argv, int *i)
{
	if (ft_strcmp(argv[*i], "--help") == 0)
	{
		printf("Help Screen\n");
		printf("ft_nmap [OPTIONS]\n");
		printf(" --help\t\t\tDisplay this help screen\n");
		printf(" --ports\t\tports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n");
		printf(" --ip\t\t\tip addresses to scan in dot format\n");
		printf(" --file\t\t\tFile name containing IP addresses to scan\n");
		printf(" --speedup\t\t[250 max] number of parallel threads to use\n");
		printf(" --scan\t\t\tSYN/NULL/FIN/XMAS/ACK/UDP\n");
		exit_parsing(args, 0);
	}
}

int	add_port_end_of_table(t_args *args, int port)
{
	int	i = 0;
	while (args->port_data[i].port != 0)
	{
		if (args->port_data[i].port == port)
		{
			printf("Error: --ports the port %d is already in the list\n", port);
			return (1);
		}
		i++;
	}
	if (i >= 1024)
	{
		printf("Error: --ports the number of ports scanned cannot exceed 1024\n");
		return (1);
	}
	args->port_data[i].port = port;
	return (0);
}

int	add_port_range(t_args *args, int begin, int end)
{
	if (end - begin > 1024)
	{
		printf("Error: --ports the number of ports scanned cannot exceed 1024\n");
		return (1);
	}
	int	port = begin;
	while (port <= end)
	{
		if (add_port_end_of_table(args, port) == 1)
			return (1);
		port++;
	}
	return (0);
}

void	parse_arg_ports(t_args *args, int argc, char **argv, int *i)
{
	if (ft_strcmp(argv[*i], "--ports") == 0)
	{
		if (*i + 1 < argc)
		{
			(*i)++;
			char	**tokens = ft_split(argv[*i], ',');
			for (int j = 0; tokens[j] != NULL; j++)
			{
				char	*token = tokens[j];
				if (strstr(token, "-") != NULL)
				{
					int	begin = ft_atoi(strtok(token, "-"));
					int	end = ft_atoi(strtok(NULL, "-"));
					if (begin < 1 || begin > 65535 || end < 1 || end > 65535)
					{
						printf("Error: --ports incorrect range port (1-65535)\n");
						ft_free(tokens);
						exit_parsing(args, 1);
					}
					if (add_port_range(args, begin, end) == 1)
					{
						ft_free(tokens);
						exit_parsing(args, 1);
					}
				}
				else
				{
					int	port = ft_atoi(token);
					if (port < 1 || port > 65535)
					{
						printf("Error: --ports incorrect range port (1-65535)\n");
						ft_free(tokens);
						exit_parsing(args, 1);
					}
					if (add_port_end_of_table(args, port) == 1)
					{
						ft_free(tokens);
						exit_parsing(args, 1);
					}
				}
			}
			ft_free(tokens);
		}
		else
		{
			printf("Error: --ports requires an argument\n");
			exit_parsing(args, 1);
		}
	}
}

void	parse_arg_ip(t_args *args, int argc, char **argv, int *i)
{
	if (ft_strcmp(argv[*i], "--ip") == 0)
	{
		if (args->file) {
			printf("Error: --ip and --file are mutually exclusive\n");
			exit_parsing(args, 1);
		}
		if (*i + 1 < argc)
		{
			(*i)++;
			args->ip = argv[*i];
		}
		else
		{
			printf("Error: --ip requires an argument\n");
			exit_parsing(args, 1);
		}
	}
}

void	parse_arg_file(t_args *args, int argc, char **argv, int *i)
{
	if (ft_strcmp(argv[*i], "--file") == 0)
	{
		if (args->ip) {
			printf("Error: --ip and --file are mutually exclusive\n");
			exit_parsing(args, 1);
		}
		if (*i + 1 < argc)
		{
			(*i)++;
			args->file = argv[*i];
			if ((args->file_fd = fopen(args->file, "r")) == NULL) {
				perror("fopen");
				exit_parsing(args, 1);
			} else {
				get_next_line(fileno(args->file_fd), &args->ip);
			}
		}
		else
		{
			printf("Error: --file requires an argument\n");
			exit_parsing(args, 1);
		}
	}
}

void	parse_arg_speedup(t_args *args, int argc, char **argv, int *i)
{
	if (ft_strcmp(argv[*i], "--speedup") == 0)
	{
		if (*i + 1 < argc)
		{
			(*i)++;
			int	speedup = ft_atoi(argv[*i]);
			if (speedup > 250)
			{
				printf("Error: --speedup must be less than 250\n");
				exit_parsing(args, 1);
			}
			else if (speedup < 0)
			{
				printf("Error: --speedup must be positive\n");
				exit_parsing(args, 1);
			}
			args->speedup = speedup;
		}
		else
		{
			printf("Error: --speedup requires an argument\n");
			exit_parsing(args, 1);
		}
	}
}

void	parse_arg_scan(t_args *args, int argc, char **argv, int *i)
{
	if (ft_strcmp(argv[*i], "--scan") == 0)
	{
		if (*i + 1 < argc)
		{
			char	*token;
			(*i)++;
			token = strtok(argv[*i], ",");
			while (token != NULL)
			{
				if (ft_strcmp(token, "SYN") == 0)
					args->scans[SYN] = 1;
				else if (ft_strcmp(token, "NULL") == 0)
					args->scans[null] = 1;
				else if (ft_strcmp(token, "ACK") == 0)
					args->scans[ACK] = 1;
				else if (ft_strcmp(token, "FIN") == 0)
					args->scans[FIN] = 1;
				else if (ft_strcmp(token, "XMAS") == 0)
					args->scans[XMAS] = 1;
				else if (ft_strcmp(token, "UDP") == 0)
					args->scans[UDP] = 1;
				else
				{
					printf("Error: --scan must be one of SYN/NULL/ACK/FIN/XMAS/UDP\n");
					exit_parsing(args, 1);
				}
				token = strtok(NULL, ",");
			}
		}
		else
		{
			printf("Error: --scan requires an argument\n");
			exit_parsing(args, 1);
		}
	}
}

t_args	parse_args(int argc, char **argv)
{
	t_args	args;
	int		i = 1;

	args.ip = NULL;
	args.file = NULL;
	args.file_fd = NULL;
	args.speedup = 1;

	ft_memset(&args.port_data, 0, sizeof(t_port_data) * 1024);
	ft_memset(&args.scans, 0, sizeof(t_scan_type) * 6);

	while (i < argc)
	{
		parse_arg_help(&args, argv, &i);
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
		exit_parsing(&args, 1);
	}
	// else if (args.ip != NULL && args.file != NULL)
	// {
	// 	printf("Error: --ip and --file are mutually exclusive\n");
	// 	exit_parsing(&args, 1);
	// }

	if (args.scans[SYN] == 0 && args.scans[null] == 0 && args.scans[ACK] == 0 && args.scans[FIN] == 0 && args.scans[XMAS] == 0 && args.scans[UDP] == 0)
	{
		for (int i = 0; i < 6; i++)
			args.scans[i] = 1;
	}
	if (args.port_data[0].port == 0)
	{
		for (int i = 1; i <= 1024; i++)
			add_port_end_of_table(&args, i);
	}

	return (args);
}
