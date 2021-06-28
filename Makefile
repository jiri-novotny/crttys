NAME = crttys
LDFLAGS = -lssl -lcrypto

all: fullssl

normal:
	$(CROSS_COMPILE)$(CC) -DENABLE_SSL=0 crttys.c net.c device.c webserver.c hashmap.c iterator.c -Wall -Wextra -o $(NAME) $(LDFLAGS)

ssl:
	$(CROSS_COMPILE)$(CC) -DENABLE_SSL=1 crttys.c net.c device.c webserver.c hashmap.c iterator.c -Wall -Wextra -o $(NAME) $(LDFLAGS)

webssl:
	$(CROSS_COMPILE)$(CC) -DENABLE_WEB_SSL=1 crttys.c net.c device.c webserver.c hashmap.c iterator.c -Wall -Wextra -o $(NAME) $(LDFLAGS)

fullssl:
	$(CROSS_COMPILE)$(CC) -DENABLE_SSL=1 -DENABLE_WEB_SSL=1 crttys.c net.c device.c webserver.c hashmap.c iterator.c -Wall -Wextra -o $(NAME) $(LDFLAGS)

debugssl:
	$(CROSS_COMPILE)$(CC) -DENABLE_SSL=1 -DENABLE_WEB_SSL=1 -g crttys.c net.c device.c webserver.c hashmap.c iterator.c -Wall -Wextra -o $(NAME) $(LDFLAGS)
