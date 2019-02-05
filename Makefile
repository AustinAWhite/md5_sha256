NAME	=	ft_ssl
#CFLAGS	=	-Wall -Werror -Wextra
FILES	=	ssl parse_input
SRC		=	$(FILES:%=src/%.c)
OBJ		=	$(FILES:%=obj/%.o)

all: $(NAME) clean fclean re
.PHONY : all

$(NAME) : $(OBJ)
	@make -C libft/
	@echo "Compiling $(NAME)..."
	@gcc $(OBJ) -o $(NAME) -L libft/ -lft

clean:
	@echo "Removing Object Files..."
	@make -C libft/ clean
	@/bin/rm -f $(OBJ)

fclean: clean
	@echo "Removing $(NAME)..."
	@make -C libft/ fclean
	@/bin/rm -f $(NAME)

re: fclean all