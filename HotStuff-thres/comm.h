#ifndef COMM_H
#define COMM_H
#include "hotstuff.h"



void *client_func(void *clifd_recv);
void *network_listen(void);
void *network_connect(void);

int writen(int fd, const char* msg, int size);
int sendMsg(int cfd, char* msg, int len);
int readn(int fd, char* buf, int size);
int recvMsg(int cfd, char** msg);

void broadcast(char tag);
#endif /* comm.h */