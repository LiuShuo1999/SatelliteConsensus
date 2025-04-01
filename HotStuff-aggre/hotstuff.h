#ifndef HOTSTUFF_H
#define HOTSTUFF_H
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <sys/types.h>        
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>   
#include <netinet/in.h>
#include <time.h>


#include "uECC.h"
#include "sha2.h"
#include "ipc.h"
// #include "core.h"
// #include "bls_BN254.h"
#include "config.h"
#include "comm.h"

#define MAX_K 10
#define MAX_SK 20

#define N 4
#define f 1
#define thres_hold 3

#define LEADER_ID 1
#define BUFFER_SIZE 1024
#define HASH_SIZE 32
#define SIG_SIZE 48
#define MSG_SIZE  HASH_SIZE + SIG_SIZE + 3*4 + 1

#define ADDR "127.0.0.1"
#define BACKLOG 10

extern char ADDRs[4][16];
extern int PORTs[4];

// Consensus related variables
extern key_t mtx;
extern int mtx_sem;
extern key_t mtx2;
extern int mtx_sem2;
extern int sem_flg;
extern int sem_val;
extern FILE *fp;

struct socket_handler {
	int id; // node id
	int socket;
};

extern struct timeval start_block, end_block;
extern int debug_flag;
extern int temp_socket[N+1];
extern int ID, BASE_PORT, LISTEN_PORT;
extern int client_num;
extern int leader_socket;
extern struct socket_handler sh[10];

extern int tot_precommit;
extern int tot_commit;
extern int tot_decide;
extern int tot_viewchange;

extern int ready;
extern int commit;
extern int ready_number;
extern int ready_node[N+1];

extern char *proposal;
extern int sizeofp;
extern char block_hash[32];

extern int block_id;

extern char consensus_state;

extern char preprepare_sig[N+1][SIG_SIZE];
extern char precommit_sig[N+1][SIG_SIZE];
extern char commit_sig[N+1][SIG_SIZE];
extern char decide_sig[N+1][SIG_SIZE];
extern char viewchange_sig[N+1][SIG_SIZE];

extern int precommit_id[N];
extern int commit_id[N];
extern int decide_id[N];
extern int viewchange_id[N];

extern struct uECC_Curve_t *curves[5];

// Proposal message structure
struct msg_P {
	int id;
	int block_id;
	char tag;
	char hash[32]; // hash of proposal
	char sig[SIG_SIZE]; // signature of this msg
};

// Follower message structure
struct msg {
	int id;
	int block_id;
	char tag;
	int vote; // 0 or 1 for prepare or commit phase
	char hash[32]; // hash of proposals
	char sig[SIG_SIZE]; // signature of this msg
};

// Leader aggregate message structure
struct msg_L {
	int id;
	int block_id;
	char tag;
	int vote; // 0 or 1 for prepare or commit phase
	int ids[2*f];
	char hash[32]; // hash of proposals
	char sigs[2*f][SIG_SIZE]; // signatures of this msg
	char sig[SIG_SIZE];
};

// Structure for signing and verifying
struct sign_struct {
	char tag;
	int id;
	int block_id;
	int vote;
	char hash[HASH_SIZE];
};

// Extended structure for signing and verifying
struct sign_struct2 {
	char tag;
	int id;
	int block_id;
	int vote;
	char hash[HASH_SIZE];
	char sigs[2*f][SIG_SIZE];
};


#endif /* hotstuff.h */