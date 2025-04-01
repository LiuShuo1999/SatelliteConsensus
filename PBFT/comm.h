#ifndef COMM_H
#define COMM_H
#include "PBFT.h"

void *network_listen(void);
void *network_connect(void);

int writen(int fd, const char* msg, int size);
int sendMsg(int cfd, char* msg, int len);
int readn(int fd, char* buf, int size);
int recvMsg(int cfd, char** msg);
void *client_func1(void *clifd_recv);
void broadcast(char tag);


//udp
void *udp_client_func1(void *clifd_recv);
void udp_broadcast(char tag);
void udp_nack(char tag, int blockid);
#endif /* comm.h */