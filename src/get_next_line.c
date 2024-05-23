#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#define BUFFER_SIZE 2

int	is_line(char *s)
{
	while (s && *s)
	{
		if (*s == '\n')
			return (1);
		++s;
	}
	return (0);
}

int	getlen_n(const char *s, char n)
{
	int	i;

	if (s == NULL)
		return (0);
	i = 0;
	while (s[i] && s[i] != n)
		++i;
	return (i);
}

static char	*parse_str(char *tmp, int r)
{
	int		i;
	int		j;
	char	*new_tmp;

	if (!tmp)
		return (NULL);
	i = getlen_n(tmp, '\n');
	if (!tmp[i] && r < BUFFER_SIZE)
	{
		free(tmp);
		return (NULL);
	}
	if (!(new_tmp = malloc(sizeof(char) * (getlen_n(tmp + i, 0) + 1))))
	{
		free(tmp);
		return (NULL);
	}
	j = -1;
	++i;
	while (tmp[i])
		new_tmp[++j] = tmp[i++];
	new_tmp[++j] = '\0';
	free(tmp);
	return (new_tmp);
}

static char	*get_line_str(char *s)
{
	char	*line;
	int		i;

	if (!s)
		return (NULL);
	i = 0;
	i = getlen_n(s, '\n');
	if (!(line = malloc(sizeof(char) * (i + 1))))
	{
		free(s);
		return (NULL);
	}
	i = -1;
	while (s[++i] && s[i] != '\n')
		line[i] = s[i];
	line[i] = '\0';
	return (line);
}

static char	*concatenate_str(char *s1, char *s2)
{
	char	*s;
	int		i;
	int		j;

	if (!(s = malloc(sizeof(char) * (getlen_n(s1, 0) + getlen_n(s2, 0) + 1))))
	{
		if (s1) {
			free(s1);
		}
		return (NULL);
	}
	i = -1;
	j = 0;
	while (s1 && s1[j])
		s[++i] = s1[j++];
	if (s1) {
		free(s1);
	}
	j = 0;
	while (s2 && s2[j])
		s[++i] = s2[j++];
	s[++i] = '\0';
	return (s);
}

static int	read_file(int fd, char **s, char **tmp)
{
	char	read_str[BUFFER_SIZE + 1];
	int		r;

	while ((r = read(fd, read_str, BUFFER_SIZE)) >= 0)
	{
		read_str[r] = '\0';
		if (r == 0 && !*tmp) {
			return -1;
		}
		if (!(*tmp = concatenate_str(*tmp, read_str)))
			return (-1);
		if (is_line(read_str) || r < BUFFER_SIZE)
		{
			if (!(*s = get_line_str(*tmp)))
			{
				free(*tmp);
				return (-1);
			}
			*tmp = parse_str(*tmp, r);
			return (r < BUFFER_SIZE && (r == 0 || read_str[r - 1] != '\n')
					&& getlen_n(*tmp, 0) == 0 ? 0 : 1);
		}
	}
	return (r);
}
int			get_next_line(int fd, char **s)
{
	static char	*tmp = NULL;
	int			r;

	if (BUFFER_SIZE < 1 || fd < 0 || !s){
		return (-1);}
	if (is_line(tmp))
	{
		if (!(*s = get_line_str(tmp)))
		{
			free(tmp);
			return (-1);
		}
		tmp = parse_str(tmp, BUFFER_SIZE);

		return (1);
	}
	if ((r = read_file(fd, s, &tmp)) < 1){
		if (tmp) {
			free(tmp);
			tmp = NULL;
		}
	}
	return (r);
}