NAME = crttys
LDFLAGS = -lssl -lcrypto
SRCS = crttys.c net.c log.c device.c webserver.c hashmap.c iterator.c

all: fullssl

hexgen:
	$(CC) hexgen.c -Wall -Wextra -o hexgen $(LDFLAGS)

web: hexgen
	./hexgen web/index.html index.c webIndex
	./hexgen web/terminal.html terminal.c webTerminal

normal:
	$(CROSS_COMPILE)$(CC) -DENABLE_SSL=0 $(SRCS) -Wall -Wextra -o $(NAME) $(LDFLAGS)

ssl:
	$(CROSS_COMPILE)$(CC) -DENABLE_SSL=1 $(SRCS) -Wall -Wextra -o $(NAME) $(LDFLAGS)

webssl:
	$(CROSS_COMPILE)$(CC) -DENABLE_WEB_SSL=1 $(SRCS) -Wall -Wextra -o $(NAME) $(LDFLAGS)

fullssl:
	$(CROSS_COMPILE)$(CC) -DENABLE_SSL=1 -DENABLE_WEB_SSL=1 $(SRCS) -Wall -Wextra -o $(NAME) $(LDFLAGS)

debugssl:
	$(CROSS_COMPILE)$(CC) -DENABLE_SSL=1 -DENABLE_WEB_SSL=1 -g $(SRCS) -Wall -Wextra -o $(NAME) $(LDFLAGS)
