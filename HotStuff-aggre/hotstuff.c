#include "hotstuff.h"
// #define ID 1
// #define BASE_PORT 18975
// #define LISTEN_PORT 	BASE_PORT + ID

//tag
//pre-prepare  b  block
//pre-commit   p
//commit       c
//decide       d
//view-change  v

#define MAX_ARR 12

char preprepare_sig[N+1][SIG_SIZE];
char precommit_sig[N+1][SIG_SIZE];
char commit_sig[N+1][SIG_SIZE];
char decide_sig[N+1][SIG_SIZE];
char viewchange_sig[N+1][SIG_SIZE];

int ID,BASE_PORT,LISTEN_PORT;

char public_key_string[13][192] = {
	"9f a5 ef bd 99 5a bb cd d1 f8 e0 8f 5d ae bf 24 0c d8 91 46 5d 89 91 55 9c 36 92 2e b4 23 3d fd a1 88 60 be a6 4b c6 41 7c 4c bc ba e0 8d 53 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	"3d b7 07 05 3b b6 95 5b 9b 40 16 4f 90 0f c2 bb b1 ea 57 19 b7 c8 25 ca 4f 82 6f 6e 78 54 71 14 91 85 16 8e 09 30 aa 41 4c 79 93 b6 f6 91 78 7a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	"66 28 e7 aa 37 d1 2a 94 28 c0 03 0a b6 89 48 17 ba e3 bd 45 b2 a1 9e 6f f8 fc 9b e1 06 a3 32 c5 63 b3 5a 35 16 30 bb 8c e0 d3 5c 27 8f 28 d0 b0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	"2e f0 f1 33 58 2b 22 0c 80 8f ce 64 fe 23 a1 78 1c 40 4d 3a ef a3 de fd df 04 2a 6d f0 fa bc 15 a1 28 6c 36 4e c5 bf 8a 98 26 f9 68 3a e7 03 dc 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	"97 ab 36 69 c6 7a 83 e3 d9 49 a1 13 7d d8 07 50 bd 44 bd 13 61 10 0b 09 55 e8 6d 9e 74 c4 71 f8 77 78 42 01 ba ea 22 c7 2a 74 c1 b1 44 c0 10 ea 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	"dc 6c b0 7c a4 97 4c 5a 0c 4f ff 54 c9 0e 64 a9 5d e4 ac dd a4 8a 8c bf 75 57 ff d1 7a 68 9a 2d 0b a2 28 0d 56 be aa 2c b4 2c b8 4d 64 f2 04 9d 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	"14 0b be 2a c5 86 79 58 df 2c ac 71 7c 3e 9f 55 c4 0a cd 42 00 0d d6 a2 ea 3b ca 53 39 e8 1e 5e 85 38 be 0d 00 39 45 67 a8 cc 32 48 a9 01 7d 55 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	"8f c6 c6 f2 62 2d 89 a0 03 b3 14 50 1f 00 b5 12 a4 77 9f 79 35 a5 f4 c4 13 13 d3 90 c9 7d 39 17 e9 35 ba 4b a7 67 c6 c0 01 c3 1a 12 82 7f 24 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	"0e c6 1e 74 1f 82 d8 e6 d8 52 87 14 f7 de 5a 28 3d a7 d0 e5 33 d8 b4 b2 45 80 2e 1e 31 c0 c7 86 6b 6d 6d fd 4a 46 d4 15 37 e1 13 4f b7 39 0a 86 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	"09 1e 0e 9b ad cc cd c7 5c 50 83 14 c3 29 51 43 2b 07 85 4c 0e 33 df 32 91 8e ad 10 bd 0a bb 99 3e 77 60 c4 ea 77 09 d4 db cf d1 6c c3 55 ca 38 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	"75 b0 ce ca 13 74 26 47 4d 84 0e bd c4 f7 e4 03 08 d3 55 d4 0b 1b 1a 8a d3 89 a6 0a f4 86 6f 25 55 85 16 5b be 86 4d 34 45 15 8f 1d 76 e9 80 4b 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	"77 d2 ea ca e0 39 1e 2b 97 4c dd 79 2c 6c 82 67 6f a5 60 ca 67 16 62 32 b0 5e eb 93 74 2a 51 cd 36 e7 ed 35 e7 29 31 5a 2d bb 96 f3 75 af be bf 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	"df 67 30 1c 55 20 97 62 39 76 7b 37 2c 1e 08 0a df 68 f7 1d e9 61 07 10 cc c3 19 c0 ef 1d 68 1c 31 6c 4b b2 e9 f9 21 3d 9d f7 f5 a0 37 eb ca b8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
};
char private_key_string[13][96] = {
	"8c 1b c1 e1 34 66 30 8e 0f 07 8a b5 57 0a 10 02 55 80 98 73 a3 8c 52 dd 00 00 00 00 00 00 00 00",
	"c8 43 21 2e 41 b3 01 bc 6b 83 3d 3b a1 38 15 2f b7 d2 d6 71 8e 36 f8 13 00 00 00 00 00 00 00 00",
	"76 71 30 f1 b3 55 b2 58 52 1c fd 17 bf e7 86 58 8a 2c 1c d5 f1 dd 42 19 00 00 00 00 00 00 00 00",
	"2f c4 44 27 8e 26 b5 21 6a ac 2d fd 5b 2e 7a 24 31 b6 76 da 27 0a c6 51 00 00 00 00 00 00 00 00",
	"1e 9e 36 3d 8d d4 cd ec 00 05 2b c0 aa 18 a6 8e ba 4a 0d 62 e4 aa ad 4d 00 00 00 00 00 00 00 00",
	"97 a1 75 3a d9 ed 3d 35 20 40 bd 35 41 28 34 61 d5 92 a7 80 bc 3a dc 2f 00 00 00 00 00 00 00 00",
	"4a 27 34 f7 47 1d e5 e4 d4 72 61 6d 18 ac 43 27 9f ba bb dc 7e 4b c3 88 00 00 00 00 00 00 00 00",
	"ba 91 b4 7e e1 da 98 37 6a 03 07 7e 81 21 95 97 e5 50 c2 12 6a 7f 30 c9 00 00 00 00 00 00 00 00",
	"b0 9f 0e 0c 56 ae 26 75 7f a4 3b aa 26 56 ab 10 34 7d f5 2c 4c 2a 73 c9 00 00 00 00 00 00 00 00",
	"29 44 3d 84 03 b3 f4 6c 41 e5 5e c6 95 02 ab b3 c1 3e c3 f0 14 2b 81 1c 00 00 00 00 00 00 00 00",
	"3a e1 52 fe c5 d6 6f cd 94 73 7c be 8f fb c5 b8 97 94 8d 12 fa 28 86 0e 00 00 00 00 00 00 00 00",
	"cb 6b 28 61 8b 40 ef 62 1d 3a 9e e6 e4 b6 b6 68 4e 5f bb db da 79 a4 37 00 00 00 00 00 00 00 00",
	"23 40 a2 ca 4f 10 7a c4 81 16 b1 4a 08 5e 73 79 49 5c 31 04 4c a0 d6 1d 00 00 00 00 00 00 00 00"
};

char ADDRs[4][16]={
	"127.0.0.1",
	"127.0.0.1",
	"127.0.0.1",
	"127.0.0.1"
};

// Define ports and file pointer
int PORTs[4] = {100, 102, 103, 104};
FILE *fp;

// Define semaphore keys and values
key_t mtx;
int mtx_sem;
key_t mtx2;
int mtx_sem2;
int sem_flg;
int sem_val;

// Define keys for cryptographic operations
uint8_t private_key[13 + 1][32] = {0};
uint8_t public_key[13 + 1][64] = {0};

// Define network-related variables
int client_num = 0;
struct socket_handler sh[10];
int leader_socket;
int temp_socket[N + 1];

// Define cryptographic curve
struct uECC_Curve_t *curves[5];

// Define block-related variables
char *proposal;
int sizeofp;
char block_hash[32];
int block_id;

// Define consensus state
char consensus_state = 'p';

// Define consensus votes
__uint8_t precommit_vote[N + 1];
__uint8_t commit_vote[N + 1];
__uint8_t decide_vote[N + 1];
__uint8_t viewchange_vote[N + 1];

// Define counters for consensus phases
int tot_precommit;
int tot_commit;
int tot_decide;
int tot_viewchange;

// Define debug flag
int debug_flag = 0;

// Define readiness and commit flags
int ready = 0;
int commit = 0;
int ready_number = 0;

// Define arrays for node IDs in different phases
int ready_node[N + 1];
int precommit_id[N];
int commit_id[N];
int decide_id[N];
int viewchange_id[N];

// Define time measurement variables
struct timeval start_block, end_block;

// Initialize consensus variables
void init() {
	down(mtx_sem);
	for (int i = 0; i < N + 1; i++) {
		precommit_vote[i] = 0xff;
		commit_vote[i] = 0xff;
		decide_vote[i] = 0xff;
		viewchange_vote[i] = 0xff;
		ready_node[i] = 0xff;
	}
	tot_precommit = 0;
	tot_commit = 0;
	tot_decide = 0;
	ready = 0;
	commit = 1;
	ready_number = 0;
	up(mtx_sem);
}

int main(int argc,char **argv)
{
	// Initialize public keys
	init_public_key();

	/**************************************************connect**********************************************************************************************/
	// Set semaphore flags and values
	sem_flg = IPC_CREAT | 0644;
	sem_val = 1;
	mtx = 211;
	mtx_sem = set_sem(mtx, sem_val, sem_flg);

	// Set initial consensus state
	consensus_state = 'i';

	// Check for required arguments
	if(argc < 7){
		printf("Error: Missing parameter\n");
		_exit(-1);
	}

	// Parse command line arguments
	BASE_PORT = atoi(argv[1]);
	ID = atoi(argv[2]);
	debug_flag = atoi(argv[3]);
	int run_times = atoi(argv[4]);
	int block_arr_number = atoi(argv[5]);
	int single_block_size = atoi(argv[6]);
	LISTEN_PORT = PORTs[ID-1]; // Set listen port based on ID

	// Define file paths for output
	char FILE_PATH[4][70] = {
		"./Data_hotstuff_aggre_01.txt",
		"./Data_hotstuff_aggre_02.txt",
		"./Data_hotstuff_aggre_03.txt",
		"./Data_hotstuff_aggre_04.txt"
	};

	// Open output file
	fp = fopen(FILE_PATH[ID-1], "w");
	if(fp == NULL){
		fprintf(fp, "Error: file open error!\n");
		_exit(-1);
	}

	// Create and detach network listen thread
	pthread_t th = -1;  
	int ret = pthread_create(&th, NULL, network_listen, NULL); 
	if(ret == 0){
		fprintf(fp, "listen thread: %d establish success\r\n", (int)th);
		pthread_detach(th);   
	} else {
		fprintf(fp, "listen thread establish fail\r\n");
		_exit(-1);
	}

	// Create and detach network connect thread
	ret = pthread_create(&th, NULL, network_connect, NULL); 
	if(ret == 0){
		fprintf(fp, "connect thread: %d establish success\r\n", (int)th);
		pthread_detach(th);   
	} else {
		fprintf(fp, "connect thread establish fail\r\n");
		_exit(-1);
	}

	// Disable Nagle's algorithm for all client sockets
	int flag = 1;
	for(int i = 0; i < client_num; i++){
		if(setsockopt(sh[i].socket, IPPROTO_TCP, TCP_NODELAY, (void *)&flag, sizeof(flag)) < 0){
			fprintf(fp, "set no Nagle ERROR!\n");
			_exit(1);
		}
	}

	/**************************************************Pre-prepare**********************************************************************************************/
	// Initialize random seed and time measurement variables
	srand(10086);
	struct timeval startt, endd, startx, endx, tmp_start, tmp_end;
	double time_tmp, cpu_time[600], aver_time[30];

	// Define block size arrays
	int block_size_arr_0[MAX_ARR] = {256, 512, 1*1024, 2*1024, 4*1024, 6*1024, 8*1024, 10*1024, 12*1024, 14*1024, 16*1024, 18*1024};
	int block_size_arr_1[MAX_ARR] = {256*1024, 512*1024, 1*1024*1024, 2*1024*1024, 4*1024*1024, 6*1024*1024, 8*1024*1024, 10*1024*1024, 12*1024*1024, 14*1024*1024, 16*1024*1024, 18*1024*1024};
	int block_size_arr[MAX_ARR];

	// Select block size array based on BASE_PORT
	if(BASE_PORT == 1){
		for(int i = 0; i < MAX_ARR; i++) block_size_arr[i] = block_size_arr_1[i];
	} else if(BASE_PORT == 0){
		for(int i = 0; i < MAX_ARR; i++) block_size_arr[i] = block_size_arr_0[i];
	}

for(int b_idx = 0; b_idx < block_arr_number + 1; b_idx++) {
	// Determine block size
	if(b_idx == block_arr_number) {
		sizeofp = single_block_size;
	} else {
		sizeofp = block_size_arr[b_idx];
	}

	// Allocate memory for the proposal
	proposal = (char *)malloc(sizeofp * sizeof(char));
	if(proposal == NULL) {
		fprintf(fp, "Memory allocation error\n");
		_exit(-1);
	}

	// Run consensus for the specified number of times
	for(int idx = 0; idx < run_times; idx++) {
		init(); // Initialize consensus variables

		// Synchronize commit flag
		if(idx == 0) commit = 1;

		// Leader node setup
		if(ID == LEADER_ID) {
			while(1) {
				usleep(300);
				broadcast('s');
				if(ready_number == N - 1) break;
			}
			ready = 1;
		}

		block_id = idx;

		// Initialize block with random data
		if(ID == LEADER_ID) {
			for(int i = 0; i < sizeofp; i++) proposal[i] = rand();
			broadcast('r');
		}

		while(!ready);
		commit = 0;

		// Start timing
		gettimeofday(&start_block, NULL);
		gettimeofday(&startx, NULL);
		gettimeofday(&tmp_start, NULL);
		gettimeofday(&startt, NULL);

		if(consensus_state != 'p')
			consensus_state = 'b';

		tot_viewchange = 0;

		// Compute block hash
		if(ID == LEADER_ID)
			sha2(proposal, sizeofp, block_hash, 0);

		// Leader broadcasts block
		while(ID == LEADER_ID) {
			if(client_num == N - 1) {
				broadcast('b');
				break;
			}
		}

		// Precommit phase
		while(1) {
			if(consensus_state == 'p' && ID != LEADER_ID) {
				struct msg m;
				m.id = ID; m.block_id = block_id; m.tag = 'p'; m.vote = 1;
				memcpy(m.hash, block_hash, HASH_SIZE);

				// Sign the message
				struct sign_struct tmp = { .tag = m.tag, .id = m.id, .block_id = m.block_id, .vote = m.vote };
				memcpy(tmp.hash, m.hash, HASH_SIZE);
				__uint8_t hash[32], sig1[64];
				hash_sign_struct(hash, &tmp);
				if (!uECC_sign(private_key[ID], hash, 32, sig1, uECC_secp192r1())) {
					fprintf(fp, "uECC_sign() failed\n");
					return 1;
				}
				memcpy(m.sig, sig1, SIG_SIZE);

				if(sendMsg(leader_socket, (char*)&m, sizeof(m)) == -1) {
					perror("Failed to send data\n");
					_exit(-1);
				}
				break;
			} else if (consensus_state == 'p' && ID == LEADER_ID) {
				struct msg_L m;
				m.id = ID; m.block_id = block_id; m.tag = 'p'; m.vote = 1;
				memcpy(m.hash, block_hash, HASH_SIZE);
				for(int i = 0; i < 2 * f; i++) {
					m.ids[i] = precommit_id[i];
					memcpy(m.sigs[i], precommit_sig[m.ids[i]], SIG_SIZE);
				}

				// Sign the message
				struct sign_struct2 tmp = { .tag = m.tag, .id = m.id, .block_id = m.block_id, .vote = m.vote };
				memcpy(tmp.hash, m.hash, HASH_SIZE);
				for(int i = 0; i < 2 * f; i++) memcpy(tmp.sigs[i], m.sigs[i], SIG_SIZE);
				__uint8_t hash[32], sig1[64];
				hash_sign_struct2(hash, &tmp);
				if (!uECC_sign(private_key[ID], hash, 32, sig1, uECC_secp192r1())) {
					fprintf(fp, "uECC_sign() failed\n");
					return 1;
				}
				memcpy(m.sig, sig1, SIG_SIZE);

				for(int i = 0; i < client_num; i++) {
					if(sendMsg(sh[i].socket, (char*)&m, sizeof(m)) == -1) {
						perror("Failed to send data");
						_exit(-1);
					}
				}
				break;
			}
		}

		// Commit phase
		while(1) {
			if(consensus_state == 'c' && ID != LEADER_ID) {
				struct msg m;
				m.id = ID; m.block_id = block_id; m.tag = 'c'; m.vote = 1;
				memcpy(m.hash, block_hash, HASH_SIZE);

				// Sign the message
				struct sign_struct tmp = { .tag = m.tag, .id = m.id, .block_id = m.block_id, .vote = m.vote };
				memcpy(tmp.hash, m.hash, HASH_SIZE);
				__uint8_t hash[32], sig1[64];
				hash_sign_struct(hash, &tmp);
				if (!uECC_sign(private_key[ID], hash, 32, sig1, uECC_secp192r1())) {
					fprintf(fp, "uECC_sign() failed\n");
					return 1;
				}
				memcpy(m.sig, sig1, SIG_SIZE);

				if(sendMsg(leader_socket, (char*)&m, sizeof(m)) == -1) {
					perror("Failed to send data\n");
					_exit(-1);
				}
				break;
			} else if (consensus_state == 'c' && ID == LEADER_ID) {
				struct msg_L m;
				m.id = ID; m.block_id = block_id; m.tag = 'c'; m.vote = 1;
				memcpy(m.hash, block_hash, HASH_SIZE);
				for(int i = 0; i < 2 * f; i++) {
					m.ids[i] = commit_id[i];
					memcpy(m.sigs[i], commit_sig[m.ids[i]], SIG_SIZE);
				}

				// Sign the message
				struct sign_struct2 tmp = { .tag = m.tag, .id = m.id, .block_id = m.block_id, .vote = m.vote };
				memcpy(tmp.hash, m.hash, HASH_SIZE);
				for(int i = 0; i < 2 * f; i++) memcpy(tmp.sigs[i], m.sigs[i], SIG_SIZE);
				__uint8_t hash[32], sig1[64];
				hash_sign_struct2(hash, &tmp);
				if (!uECC_sign(private_key[ID], hash, 32, sig1, uECC_secp192r1())) {
					fprintf(fp, "uECC_sign() failed\n");
					return 1;
				}
				memcpy(m.sig, sig1, SIG_SIZE);

				for(int i = 0; i < client_num; i++) {
					if(sendMsg(sh[i].socket, (char*)&m, sizeof(m)) == -1) {
						perror("Failed to send data");
						_exit(-1);
					}
				}
				break;
			}
		}

		// Decide phase
		while(1) {
			if(consensus_state == 'd' && ID != LEADER_ID) {
				struct msg m;
				m.id = ID; m.block_id = block_id; m.tag = 'd'; m.vote = 1;
				memcpy(m.hash, block_hash, HASH_SIZE);

				// Sign the message
				struct sign_struct tmp = { .tag = m.tag, .id = m.id, .block_id = m.block_id, .vote = m.vote };
				memcpy(tmp.hash, m.hash, HASH_SIZE);
				__uint8_t hash[32], sig1[64];
				hash_sign_struct(hash, &tmp);
				if (!uECC_sign(private_key[ID], hash, 32, sig1, uECC_secp192r1())) {
					fprintf(fp, "uECC_sign() failed\n");
					return 1;
				}
				memcpy(m.sig, sig1, SIG_SIZE);

				if(sendMsg(leader_socket, (char*)&m, sizeof(m)) == -1) {
					perror("Failed to send data\n");
					_exit(-1);
				}
				break;
			} else if (consensus_state == 'd' && ID == LEADER_ID) {
				struct msg_L m;
				m.id = ID; m.block_id = block_id; m.tag = 'd'; m.vote = 1;
				memcpy(m.hash, block_hash, HASH_SIZE);
				for(int i = 0; i < 2 * f; i++) {
					m.ids[i] = decide_id[i];
					memcpy(m.sigs[i], decide_sig[m.ids[i]], SIG_SIZE);
				}

				// Sign the message
				struct sign_struct2 tmp = { .tag = m.tag, .id = m.id, .block_id = m.block_id, .vote = m.vote };
				memcpy(tmp.hash, m.hash, HASH_SIZE);
				for(int i = 0; i < 2 * f; i++) memcpy(tmp.sigs[i], m.sigs[i], SIG_SIZE);
				__uint8_t hash[32], sig1[64];
				hash_sign_struct2(hash, &tmp);
				if (!uECC_sign(private_key[ID], hash, 32, sig1, uECC_secp192r1())) {
					fprintf(fp, "uECC_sign() failed\n");
					return 1;
				}
				memcpy(m.sig, sig1, SIG_SIZE);

				for(int i = 0; i < client_num; i++) {
					if(sendMsg(sh[i].socket, (char*)&m, sizeof(m)) == -1) {
						perror("Failed to send data");
						_exit(-1);
					}
				}
				break;
			}
		}

		// Viewchange phase
		while(1) {
			if(consensus_state == 'v' && ID != LEADER_ID) {
				struct msg m;
				m.id = ID; m.block_id = block_id; m.tag = 'v'; m.vote = 1;
				memcpy(m.hash, block_hash, HASH_SIZE);

				// Sign the message
				struct sign_struct tmp = { .tag = m.tag, .id = m.id, .block_id = m.block_id, .vote = m.vote };
				memcpy(tmp.hash, m.hash, HASH_SIZE);
				__uint8_t hash[32], sig1[64];
				hash_sign_struct(hash, &tmp);
				if (!uECC_sign(private_key[ID], hash, 32, sig1, uECC_secp192r1())) {
					fprintf(fp, "uECC_sign() failed\n");
					return 1;
				}
				memcpy(m.sig, sig1, SIG_SIZE);

				if(sendMsg(leader_socket, (char*)&m, sizeof(m)) == -1) {
					perror("Failed to send data\n");
					_exit(-1);
				}
				break;
			} else if (consensus_state == 'v' && ID == LEADER_ID) {
				struct msg_L m;
				m.id = ID; m.block_id = block_id; m.tag = 'v'; m.vote = 1;
				memcpy(m.hash, block_hash, HASH_SIZE);
				for(int i = 0; i < 2 * f; i++) {
					m.ids[i] = viewchange_id[i];
					memcpy(m.sigs[i], viewchange_sig[m.ids[i]], SIG_SIZE);
				}

				// Sign the message
				struct sign_struct2 tmp = { .tag = m.tag, .id = m.id, .block_id = m.block_id, .vote = m.vote };
				memcpy(tmp.hash, m.hash, HASH_SIZE);
				for(int i = 0; i < 2 * f; i++) memcpy(tmp.sigs[i], m.sigs[i], SIG_SIZE);
				__uint8_t hash[32], sig1[64];
				hash_sign_struct2(hash, &tmp);
				if (!uECC_sign(private_key[ID], hash, 32, sig1, uECC_secp192r1())) {
					fprintf(fp, "uECC_sign() failed\n");
					return 1;
				}
				memcpy(m.sig, sig1, SIG_SIZE);

				for(int i = 0; i < client_num; i++) {
					if(sendMsg(sh[i].socket, (char*)&m, sizeof(m)) == -1) {
						perror("Failed to send data");
						_exit(-1);
					}
				}
				consensus_state = 'x';

				// Measure time taken for consensus
				gettimeofday(&endd, NULL);
				double time_taken = (endd.tv_sec - startt.tv_sec) + (endd.tv_usec - startt.tv_usec) / 1000000.0;
				cpu_time[idx] = time_taken;
				break;
			}
		}

		// Wait for consensus to complete
		while(1) {
			if(consensus_state == 'x') break;
		}

		// Measure time taken for each phase
		if(ID != LEADER_ID) {
			gettimeofday(&endd, NULL);
			double time_taken = (endd.tv_sec - startt.tv_sec) + (endd.tv_usec - startt.tv_usec) / 1000000.0;
			cpu_time[idx] = time_taken;
		}

		commit = 1;
	}

	// Calculate average time for each block size
	double tot = 0;
	for(int i = 0; i < run_times; i++) tot += cpu_time[i];
	aver_time[b_idx] = tot / run_times;
}
	// Print average time and throughput for each block size
	for(int i = 0; i < block_arr_number + 1; i++) {
		double tmp_size;
		if(i == block_arr_number) {
			fprintf(fp, "Block size: %d\n", single_block_size);
			tmp_size = single_block_size;
		} else {
			fprintf(fp, "Block size: %d\n", block_size_arr[i]);
			tmp_size = block_size_arr[i];
		}
		// Print average time in milliseconds
		fprintf(fp, "%f ms\n", aver_time[i] * 1000);
		// Print throughput (block size / average time)
		fprintf(fp, "%f\n", tmp_size / (aver_time[i] * 256 * 1000));
		fprintf(fp, "\n\n");
	}
	sleep(1);
	return 0;
}






