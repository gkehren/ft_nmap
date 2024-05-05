#ifndef FT_NMAP_H
# define FT_NMAP_H

# include <stdio.h>

# include "../libft/libft.h"

enum scan_type
{
	SYN,
	null,
	ACK,
	FIN,
	XMAS,
	UDP
};

typedef struct s_args
{
	char			*ip;
	char			*file;
	int				port[1024];
	int				speedup;
	int				scans[6];
}	t_args;

t_args	parse_args(int argc, char **argv);

#endif
