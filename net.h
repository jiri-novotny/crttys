#ifndef NET_H
#define NET_H

#define MAX_CLIENTS 32

int setSocketFlags(int sock, int f);
int openSocket(int port);
int acceptSocket(int remoteSock, int epollFd);

#endif
