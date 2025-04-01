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
#include "core.h"
#include "bls_BN254.h"
#include "config.h"
#include "comm.h"
#include "thres_signature.h"
#define MAX_K 10
#define MAX_SK 20

#define N 4
#define f 1

#define LEADER_ID 1
#define BUFFER_SIZE 1024
#define HASH_SIZE 32
#define SIG_SIZE 48
// #define BLOCK_SIZE 1024*1024*6
// #define MSG_P_SIZE BLOCK_SIZE + HASH_SIZE + SIG_SIZE + 2*4 + 1
#define MSG_SIZE  HASH_SIZE + SIG_SIZE + 3*4 + 1
#define THRES_SIG_SIZE 33

#define ADDR 	"127.0.0.1"		 
#define BACKLOG 	10   

extern char ADDRs[4][16];
extern int PORTs[4];

//consensus
extern key_t mtx;
extern int mtx_sem;
extern key_t mtx2;
extern int mtx_sem2;
extern int sem_flg;
extern int sem_val;
extern FILE *fp;
struct socket_handler{
	int id;// node id
	int socket;
};
extern struct timeval start_block,end_block;
extern int debug_flag;
extern int sizeofp;
extern char *proposal;
extern int temp_socket[N+1];
extern int ID,BASE_PORT,LISTEN_PORT;
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

// extern char block[BLOCK_SIZE];
extern char block_hash[32];

extern int block_id;

extern char consensus_state;

extern BIG_256_56 a[MAX_K];
extern BIG_256_56 SKs[MAX_SK];
extern int players;
extern int k;
extern ECP_BN254 G1;
extern ECP2_BN254 G2;
extern ECP_BN254 g1;
extern ECP2_BN254 g2;
extern ECP2_BN254 VK;
extern ECP2_BN254 VKs[MAX_SK];

extern int S_p[MAX_SK];
extern ECP_BN254 Sigs_p[MAX_SK];
extern ECP_BN254 SIG_p;
extern int S_c[MAX_SK];
extern ECP_BN254 Sigs_c[MAX_SK];
extern ECP_BN254 SIG_c;
extern int S_d[MAX_SK];
extern ECP_BN254 Sigs_d[MAX_SK];
extern ECP_BN254 SIG_d;
extern int S_v[MAX_SK];
extern ECP_BN254 Sigs_v[MAX_SK];
extern ECP_BN254 SIG_v;

extern struct uECC_Curve_t * curves[5];



struct msg_P{//proposal MSG
	
	int id;
	int block_id;
	char tag;
	char hash[32];//hash of proposal
	char sig[48];//signature of this msg
			//proposal size ?
	// char block[BLOCK_SIZE];
};

struct msg{	
	int id;
	int block_id;
	char tag;
	int vote;//0 or 1 of prepare or commit phase
	char hash[32];//hash of proposal
    char thres_ch[THRES_SIG_SIZE];
	char sig[48];//signature of this msg
			//proposal size ?
};

struct sign_struct{//just for sign and verify
	char tag;
	int id;
	int block_id;
	int vote;
	char hash[HASH_SIZE];
};

struct sign_struct2{//just for sign and verify
	char tag;
	int id;
	int block_id;
	int vote;
	char hash[HASH_SIZE];
    char thres_ch[THRES_SIG_SIZE];
};


#endif /* hotstuff.h */