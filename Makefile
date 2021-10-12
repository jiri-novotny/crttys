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

debug: web
	$(CROSS_COMPILE)$(CC) -DENABLE_SSL=0 -DLOGLEVEL=5 -g $(SRCS) -Wall -Wextra -o $(NAME) $(LDFLAGS)

ssl: web
	$(CROSS_COMPILE)$(CC) -DENABLE_SSL=1 $(SRCS) -Wall -Wextra -o $(NAME) $(LDFLAGS)

webssl: web
	$(CROSS_COMPILE)$(CC) -DENABLE_WEB_SSL=1 $(SRCS) -Wall -Wextra -o $(NAME) $(LDFLAGS)

fullssl: web
	$(CROSS_COMPILE)$(CC) -DENABLE_SSL=1 -DENABLE_WEB_SSL=1 $(SRCS) -Wall -Wextra -o $(NAME) $(LDFLAGS)

debugssl: web
	$(CROSS_COMPILE)$(CC) -DENABLE_SSL=1 -DENABLE_WEB_SSL=1 -DLOGLEVEL=5 -g $(SRCS) -Wall -Wextra -o $(NAME) $(LDFLAGS)

debugtest: web
	$(CROSS_COMPILE)$(CC) -DENABLE_SSL=0 -DLOGLEVEL=5 -DWS_TEST=1 -g $(SRCS) -Wall -Wextra -o $(NAME) $(LDFLAGS)

test: web
	$(CROSS_COMPILE)$(CC) -DENABLE_SSL=0 -DWS_TEST=1 -O2 $(SRCS) -Wall -Wextra -o $(NAME) $(LDFLAGS)

clean:
	rm -rf hexgen index.c terminal.c crttys


run: webssl
	./crttys -k key.pem -c cert.pem -K web/privkey.pem -C web/chain.pem -d 65001 -w 4433