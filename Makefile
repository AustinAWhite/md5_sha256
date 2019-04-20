NAME	=	mySSL
CFLAGS	=	-Wall -Werror -Wextra
FILES	=	main error md5 sha256 utils dispatcher
SRC		=	$(FILES:%=src/%.c)
OBJ		=	$(SRC:%.c=%.o)

all : $(NAME)

$(NAME) : $(OBJ)
	@make -C libft/
	@echo "Compiling $(NAME)..."
	@gcc $(OBJ) -o $(NAME) -L libft/ -lft

debug:
	@echo "Compiling $(NAME) for lldb use..."
	@gcc $(SRC) libft/*.c -o $(NAME) -g

cleandebug:
	@echo "Removing debug files..."
	@/bin/rm -rf $(NAME).dSYM

clean:
	@echo "Removing Object Files..."
	@/bin/rm -f $(OBJ)
	@make -C libft/ clean

fclean: cleandebug clean
	@echo "Removing $(NAME)..."
	@make -C libft/ fclean
	@/bin/rm -f $(NAME)

re: fclean all
