NAME = crttys
LDFLAGS = -lssl -lcrypto
SRCS = crttys.c config.c net.c log.c device.c webserver.c hashmap.c iterator.c index.c terminal.c

all: fullssl

hexgen:
	$(CC) hexgen.c -Wall -Wextra -o hexgen $(LDFLAGS)

web: hexgen
	./hexgen web/index.html index.c webIndex
	./hexgen web/terminal.html terminal.c webTerminal

normal: web
	$(CROSS_COMPILE)$(CC) -DENABLE_SSL=0 $(SRCS) -Wall -Wextra -o $(NAME) $(LDFLAGS)

ssl: web
	$(CROSS_COMPILE)$(CC) -DENABLE_SSL=1 $(SRCS) -Wall -Wextra -o $(NAME) $(LDFLAGS)

webssl: web
	$(CROSS_COMPILE)$(CC) -DENABLE_WEB_SSL=1 $(SRCS) -Wall -Wextra -o $(NAME) $(LDFLAGS)

fullssl: web
	$(CROSS_COMPILE)$(CC) -DENABLE_SSL=1 -DENABLE_WEB_SSL=1 $(SRCS) -Wall -Wextra -o $(NAME) $(LDFLAGS)

debugssl: web
	$(CROSS_COMPILE)$(CC) -DENABLE_SSL=1 -DENABLE_WEB_SSL=1 -DLOGLEVEL=1 -g $(SRCS) -Wall -Wextra -o $(NAME) $(LDFLAGS)

clean:
	rm -rf hexgen index.c terminal.c crttys