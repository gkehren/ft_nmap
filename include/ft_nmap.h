#ifndef FT_NMAP_H
# define FT_NMAP_H

# include <stdio.h>
# include <string.h>
# include <stdlib.h>

enum scan_type
{
	SYN,
	null,
	ACK,
	FIN,
	XMAS,
	UDP,
	ALL
};

typedef struct s_args
{
	char			*ip;
	char			*file;
	int				port_begin;
	int				port_end;
	int				speedup;
	enum scan_type	scan;
}	t_args;

t_args	parse_args(int argc, char **argv);

#endif
