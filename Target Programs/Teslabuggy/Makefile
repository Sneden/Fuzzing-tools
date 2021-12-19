CC 	=	gcc

# Debug build.
# CFLAGS = -g

# Release build.
CFLAGS	=	-Wall -W -ansi -pedantic -Wno-format -Wextra

OBJS	=	buggy.o

.c.o:
	$(CC) -c $*.c $(CFLAGS)

buggy: $(OBJS) 
	$(CC) -o buggy $(OBJS)

clean:
	rm -f *.o *.swp buggy

