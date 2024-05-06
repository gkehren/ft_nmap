FILES:= ft_nmap parse socket
NAME:= ft_nmap

# ------------------
CC:=gcc
SRCPATH:=src/
INCLUDES:= -I./include
CCHPATH:=obj/
CFLAGS:=-Wall -Werror -Wextra -g3
# ==================

# ----- Library -----
LIBFT:=libft
LIBFTPATH:=./libft/
LIBFTLIB:=$(addsuffix .a,$(LIBFT))
LIBFTINCLUDES:= -I$(LIBFTPATH)
LIBFTFLAGS:= -L$(LIBFTPATH) -lft
# ==================

# ----- Colors -----
BLACK:="\033[1;30m"
RED:="\033[1;31m"
GREEN:="\033[1;32m"
CYAN:="\033[1;35m"
PURPLE:="\033[1;36m"
WHITE:="\033[1;37m"
EOC:="\033[0;0m"
# ==================

# ------ Auto ------
SRC:=$(addprefix $(SRCPATH),$(addsuffix .c,$(FILES)))
OBJ:=$(addprefix $(CCHPATH),$(addsuffix .o,$(FILES)))
# ==================
CCHF:=.cache_exists

all: ${LIBFT} ${NAME}

${NAME}: ${OBJ} ${LIBFTPATH}${LIBFTLIB}
	@echo ${CYAN} " - Compiling $@" $(RED)
	@${CC} ${CFLAGS} ${SRC} -o ${NAME} ${LIBFTFLAGS} -lm
	@echo $(GREEN) " - OK" $(EOC)

${CCHPATH}%.o: ${SRCPATH}%.c
	@mkdir -p $(@D)
	@echo ${PURPLE} " - Compiling $< into $@" ${EOC}
	@${CC} ${CFLAGS} ${INCLUDES} ${LIBFTINCLUDES} -c $< -o $@

${LIBFTPATH}${LIBFTLIB}:
	@${MAKE} -C ${LIBFTPATH} > /dev/null 2>&1

${LIBFT}:
	@${MAKE} -C ${LIBFTPATH} > /dev/null 2>&1

%.c:
	@echo ${RED}"Missing file : $@" ${EOC}

clean:
	@rm -rf ${CCHPATH}
	@${MAKE} -C ${LIBFTPATH} clean > /dev/null 2>&1

fclean:	clean
	@rm -f ${NAME}
	@${MAKE} -C ${LIBFTPATH} fclean > /dev/null 2>&1

re:	fclean
	@${MAKE} all

.PHONY:	all clean fclean re
