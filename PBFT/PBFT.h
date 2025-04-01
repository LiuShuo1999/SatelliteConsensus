#ifndef PBFT_H
#define PBFT_H

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>
#include <netinet/in.h>
#include <time.h>

#include "uECC.h"
#include "sha2.h"
#include "ipc.h"
#include "config.h"
#include "comm.h"

// Constants for PBFT
#define N 4
#define f 1
#define LEADER_ID 1
#define BUFFER_SIZE 1024
#define HASH_SIZE 32
#define SIG_SIZE 48

// Configuration
#define MAX_BLOCK 55
#define MAX_ROUND 15
#define MAX_NODES 10
#define MAX_ARR 12

// External variables for semaphore and shared memory
extern key_t mtx;
extern int mtx_sem;
extern key_t mtx2;
extern int mtx_sem2;
extern int sem_flg;
extern int sem_val;
extern int run_times;
extern int block_arr_number;
extern int single_block_size;
extern int block_size_arr[MAX_ARR];
extern int nack_proposal[MAX_BLOCK];
extern int nack_prepare[MAX_ROUND][MAX_BLOCK][MAX_NODES];
extern int nack_commit[MAX_ROUND][MAX_BLOCK][MAX_NODES];


// External variables for debugging and node configuration
extern int debug_flag;
extern int ID, BASE_PORT, LISTEN_PORT;
extern int block_flag[300];
#define ADDR "192.168.200.108"
extern char ADDRs[4][16];
extern int PORTs[4];
extern FILE *fp;
#define BACKLOG 10
extern struct timeval start_block, end_block;

// Structure to handle socket connections
struct socket_handler {
	int id; // node id
	int socket;
};

// External variables for PBFT protocol
extern char *proposal;
extern int tmp_socket[N+1];
extern int client_num;
extern struct socket_handler sh[10];
extern struct uECC_Curve_t *curves[5];
extern int sizeofp;
extern char block_hash[32];
extern int my_prepare;
extern int my_commit;
extern int block_id;
extern char consensus_state;
extern __uint8_t prepare_vote[N+1];
extern __uint8_t commit_vote[N+1];
extern int prepare_1_number;
extern int prepare_0_number;
extern int commit_1_number;
extern int commit_0_number;
extern int ready;
extern int commit;
extern int ready_number;
extern int ready_node[N+1];

// Structure for proposal message
struct msg_P {
	int id;
	int block_id;
	char tag;
	char hash[32]; // hash of proposal
	char sig[48];  // signature of this msg
};

// Structure for generic message
struct msg {
	int id;
	int block_id;
	char tag;
	int vote; // 0 or 1 for prepare or commit phase
	char hash[32]; // hash of proposal
	char sig[48];  // signature of this msg
};

// Structure for signing and verifying
struct sign_struct {
	char tag;
	int id;
	int block_id;
	int vote;
	char hash[HASH_SIZE];
};

// Structure for NACK message
struct nack_struct {
	char tag; // b p c
	int id;
	int block_id;
	char sig[48]; // signature of this msg
};

// External variables for cryptographic keys
extern char public_key_string[13][192];
extern char private_key_string[13][96];
extern uint8_t private_key[13+1][32];
extern uint8_t public_key[13+1][64];

#endif /* PBFT_H */
