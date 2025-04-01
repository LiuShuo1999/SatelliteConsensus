#include "comm.h"

/*
函数描述: 发送指定的字节数
函数参数:
	- fd: 通信的文件描述符(套接字)
	- msg: 待发送的原始数据
	- size: 待发送的原始数据的总字节数
函数返回值: 函数调用成功返回发送的字节数, 发送失败返回-1
*/
int writen(int fd, const char* msg, int size)
{
	const char* buf = msg;
	int count = size;
	while (count > 0)
	{
		int len = send(fd, buf, count, 0);
		if (len == -1)
		{
			close(fd);
			return -1;
		}
		else if (len == 0)
		{
			continue;
		}
		buf += len;
		count -= len;
	}
	return size;
}

/*
函数描述: 发送带有数据头的数据包
函数参数:
	- cfd: 通信的文件描述符(套接字)
	- msg: 待发送的原始数据
	- len: 待发送的原始数据的总字节数
函数返回值: 函数调用成功返回发送的字节数, 发送失败返回-1
*/
int sendMsg(int cfd, char* msg, int len)
{
	if(msg == NULL || len <= 0 || cfd <=0)
	{
		return -1;
	}
	// 申请内存空间: 数据长度 + 包头4字节(存储数据长度)
	char* data = (char*)malloc(len+4);
	int bigLen = htonl(len);
	memcpy(data, &bigLen, 4);
	memcpy(data+4, msg, len);
	// 发送数据
	int ret = writen(cfd, data, len+4);
	// 释放内存
	free(data);
	return ret;
}

/*
函数描述: 接收指定的字节数
函数参数:
	- fd: 通信的文件描述符(套接字)
	- buf: 存储待接收数据的内存的起始地址
	- size: 指定要接收的字节数
函数返回值: 函数调用成功返回发送的字节数, 发送失败返回-1
*/
int readn(int fd, char* buf, int size)
{
	char* pt = buf;
	int count = size;
	//fprintf(fp,"readn point0\n\n\n");
	while (count > 0)
	{
		int len = recv(fd, pt, count, 0);
		if (len == -1)
		{
			return -1;
		}
		else if (len == 0)
		{
			return size - count;
		}
		pt += len;
		count -= len;
	}
	return size;
}   

/*
函数描述: 接收带数据头的数据包
函数参数:
	- cfd: 通信的文件描述符(套接字)
	- msg: 一级指针的地址，函数内部会给这个指针分配内存，用于存储待接收的数据，这块内存需要使用者释放
函数返回值: 函数调用成功返回接收的字节数, 发送失败返回-1
*/
int recvMsg(int cfd, char** msg)
{
	// 接收数据
	// 1. 读数据头
	int len = 0;
	readn(cfd, (char*)&len, 4);
	len = ntohl(len);
	//fprintf(fp,"数据块大小: %d\n", len);
	// 根据读出的长度分配内存，+1 -> 这个字节存储\0
	char *buf = (char*)malloc(len+1);
	int ret = readn(cfd, buf, len);
	if(ret != len)
	{
		close(cfd);
		free(buf);
		return -1;
	}
	buf[len] = '\0';
	*msg = buf;
	return ret;
}



// Thread function to handle client communication
void *client_func1(void *clifd_recv)
{
	int ret = -1;
	char recv_buf[BUFFER_SIZE];        // Define receive buffer
	char send_buf[BUFFER_SIZE];        // Define send buffer
	int clifd = *(int *)clifd_recv;    // Get client file descriptor from argument
	fprintf(fp,"New client %d connect success, thread start work\r\n", clifd);

	char **msg;
	msg = (char**)malloc(sizeof(char*));

	while(1)
	{	
		// Receive message from client
		ret = recvMsg(clifd, msg);
		if(ret < 1)
		{
			fprintf(fp,"client %d close", clifd);
			close(clifd);      
			client_num--;    
			pthread_exit(NULL);  
		}

		if(ret == sizeofp){
			// Handle proposal message
			if(debug_flag){
				gettimeofday(&end_block, NULL);
				double tmp_time = (end_block.tv_sec - start_block.tv_sec) + (end_block.tv_usec - start_block.tv_usec) / 1000000.0;
				fprintf(fp,"\033[31m Block Time:%f \033[0m\n", tmp_time);
			}
			
			for(int i = 0; i < sizeofp; i++)
				proposal[i] = (*msg)[i];
		} else if(ret == sizeof(struct msg_P)){
			// Handle msg_P message
			struct msg_P m;
			memcpy(&m, *msg, ret);
			if(m.tag == 'b'){
				struct sign_struct tmp;
				tmp.tag = m.tag;
				tmp.id = m.id;
				tmp.block_id = m.block_id;
				tmp.vote = 1;
				for(int i = 0; i < HASH_SIZE; i++) tmp.hash[i] = m.hash[i];

				__uint8_t hash[32];
				__uint8_t sig[64];
				for(int i = 0; i < SIG_SIZE; i++) sig[i] = m.sig[i];

				hash_sign_struct(hash, &tmp);
				if(block_id != m.block_id) continue;

				if (!uECC_verify(public_key[m.id], hash, 32, sig, uECC_secp192r1())) {
					fprintf(fp,"uECC_verify() failed\n");
					return 1;
				} else {
					down(mtx_sem);
					consensus_state = 'p';
					block_flag[block_id] = 1;
					if(debug_flag) fprintf(fp,"become p \n");
					
					my_prepare = 1;
					prepare_1_number++;
					block_id = m.block_id;
					for(int i = 0; i < HASH_SIZE; i++) block_hash[i] = m.hash[i];
					up(mtx_sem);
				}
			}
		} else if(ret == sizeof(struct msg)){
			// Handle msg message
			struct msg m;
			memcpy(&m, *msg, ret);
			if(m.tag == 'p' || m.tag == 'c'){
				if(block_id != m.block_id) continue;
				struct sign_struct tmp;
				tmp.tag = m.tag;
				tmp.id = m.id;
				tmp.block_id = m.block_id;
				tmp.vote = m.vote;
				for(int i = 0; i < HASH_SIZE; i++) tmp.hash[i] = m.hash[i];

				__uint8_t hash[32];
				__uint8_t sig[64];
				for(int i = 0; i < SIG_SIZE; i++) sig[i] = m.sig[i];

				hash_sign_struct(hash, &tmp);
				if (!uECC_verify(public_key[m.id], hash, 32, sig, uECC_secp192r1())) {
					fprintf(fp,"uECC_verify() failed\n");
					return 1;
				} else {
					if(m.tag == 'p'){
						if(debug_flag) fprintf(fp,"I receive a prepare vote!\n");
						down(mtx_sem);
						if(prepare_vote[m.id] == 0xff){
							if(m.vote == 1){ prepare_1_number++; prepare_vote[m.id] = m.vote; }
							if(m.vote == 0){ prepare_0_number++; prepare_vote[m.id] = m.vote; }
							if(prepare_1_number >= 2*f+1 || prepare_0_number >= 2*f+1){
								consensus_state = 'c';
								my_commit = 1;
								if(prepare_1_number >= 2*f+1){ my_commit = 1; if(commit_1_number == 0) commit_1_number++; }
								if(prepare_0_number >= 2*f+1){ my_commit = 0; commit_0_number++; }
							}
						}
						up(mtx_sem);
					} else if(m.tag == 'c'){
						if(debug_flag) fprintf(fp,"I receive a commit vote!\n");
						down(mtx_sem);
						if(commit_vote[m.id] == 0xff){
							if(m.vote == 1){ commit_1_number++; commit_vote[m.id] = m.vote; }
							if(m.vote == 0){ commit_0_number++; commit_vote[m.id] = m.vote; }
							if(commit_1_number >= 2*f+1 || commit_0_number >= 2*f+1){
								if(commit_1_number >= 2*f+1){ consensus_state = 'x'; }
								if(commit_0_number >= 2*f+1){ consensus_state = 'v'; }
							}
						}
						up(mtx_sem);
					}
				}
			}
		} else if(ret == 6){
			// Handle signal messages
			if(strcmp(*msg, "ready?") == 0 && commit == 1){
				sprintf(send_buf, "ready%d", ID);
				if (sendMsg(clifd, (char*)send_buf, strlen(send_buf)) == -1) {
					perror("Failed to send data");
					_exit(-1);
				}
			} else if(strcmp(*msg, "start!") == 0){
				ready = 1;
			} else {
				int id = (*msg)[5] - '0';
				down(mtx_sem);
				if(ready_node[id] == 0xff){
					ready_number++;
					ready_node[id] = 1;
				}
				up(mtx_sem);
			}
		}

		memset(recv_buf, 0, sizeof(recv_buf));   // Clear receive buffer
		memset(send_buf, 0, sizeof(send_buf));   // Clear send buffer
	}
}


void broadcast(char tag) { // b->proposal p->prepare c->commit
	char send_buf[BUFFER_SIZE]; // Define send buffer
	char tmp_buf[BUFFER_SIZE];

	int ret = -1;
	memset(send_buf, 0, BUFFER_SIZE); // Initialize send buffer to NULL

	if (tag == 'b') {
		struct msg_P m;
		m.tag = 'b';
		m.id = ID;
		m.block_id = block_id;
		memcpy(m.hash, block_hash, HASH_SIZE); // Copy block hash

		// Prepare signature structure
		struct sign_struct tmp;
		tmp.tag = tag;
		tmp.id = ID;
		tmp.block_id = block_id;
		tmp.vote = 1;
		memcpy(tmp.hash, block_hash, HASH_SIZE); // Copy block hash

		__uint8_t hash[32];
		__uint8_t sig[64];

		// Sign the hash
		hash_sign_struct(hash, &tmp);
		if (!uECC_sign(private_key[ID], hash, 32, sig, uECC_secp192r1())) {
			fprintf(fp, "uECC_sign() failed\n");
			return;
		}
		memcpy(m.sig, sig, SIG_SIZE); // Copy signature

		// Send proposal and message to all clients
		for (int i = 0; i < client_num; i++) {
			if (sendMsg(sh[i].socket, proposal, sizeofp) == -1) {
				perror("Failed to send data");
				_exit(-1);
			}
			if (sendMsg(sh[i].socket, (char*)&m, sizeof(m)) == -1) {
				perror("Failed to send data");
				_exit(-1);
			}
		}
	} else if (tag == 'p' || tag == 'c') {
		struct msg m;
		m.tag = tag;
		m.id = ID;
		m.block_id = block_id;
		m.vote = (tag == 'p') ? my_prepare : my_commit;
		memcpy(m.hash, block_hash, HASH_SIZE); // Copy block hash

		// Prepare signature structure
		struct sign_struct tmp;
		tmp.tag = m.tag;
		tmp.id = m.id;
		tmp.block_id = m.block_id;
		tmp.vote = m.vote;
		memcpy(tmp.hash, m.hash, HASH_SIZE); // Copy block hash

		__uint8_t hash[32];
		__uint8_t sig[64];

		// Sign the hash
		hash_sign_struct(hash, &tmp);
		if (!uECC_sign(private_key[ID], hash, 32, sig, uECC_secp192r1())) {
			fprintf(fp, "uECC_sign() failed\n");
			return;
		}
		memcpy(m.sig, sig, SIG_SIZE); // Copy signature

		// Send message to all clients
		for (int i = 0; i < client_num; i++) {
			if (sendMsg(sh[i].socket, (char*)&m, sizeof(m)) == -1) {
				perror("Failed to send data");
				_exit(-1);
			}
		}
	} else if (tag == 's' || tag == 'r') {
		if (tag == 's') {
			strcpy(send_buf, "ready?");
			for (int i = 0; i < client_num; i++) {
				if (sendMsg(sh[i].socket, (char*)send_buf, strlen(send_buf)) == -1) {
					perror("Failed to send data");
					_exit(-1);
				}
			}
		} else if (tag == 'r' && ID == LEADER_ID) {
			strcpy(send_buf, "start!");
			for (int i = 0; i < client_num; i++) {
				if (sendMsg(sh[i].socket, (char*)send_buf, strlen(send_buf)) == -1) {
					perror("Failed to send data");
					_exit(-1);
				}
			}
		}
	}
}

void *network_listen(void){
	int ret = -1;
	int sockfd = -1;  	// Define socket file descriptor
	int clifd = -1;   	// Define accept file descriptor
	pthread_t th = -1;   // Define a thread handle
	
	struct sockaddr_in servaddr = {0};  // Server sockaddr_in defined as IPv4 type
	struct sockaddr_in cliaddr = {0};   // Client sockaddr_in
	socklen_t address_len = 0;         // Client address length
	
	// 1. Create a socket file descriptor
	sockfd = socket(AF_INET, SOCK_STREAM, 0);   // IPv4, TCP, system auto-select protocol
	if(sockfd < 0)
	{
		fprintf(fp,"Failed to create socket file descriptor\n");
		_exit(-1);
	}

	fprintf(fp,"sockfd =  %d \n",sockfd);

	// Solve the problem of TCP socket state TIME_WAIT causing bind failure
	int on = 1;
	ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	// 2. Bind the socket file descriptor with related parameters
	servaddr.sin_family = AF_INET;             // Define servaddr's domain address family as IPv4
	servaddr.sin_port = htons(LISTEN_PORT);      // Define servaddr's port number as LISTEN_PORT
	servaddr.sin_addr.s_addr = inet_addr(ADDRs[ID-1]);  // Define servaddr's address as ADDRs[ID-1]
	memset(servaddr.sin_zero, 0, sizeof(servaddr.sin_zero));   // Set servaddr's sin_zero area to 0
	ret = bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr));   // Bind the socket file descriptor with related parameters
	if(ret < 0)
	{
		fprintf(fp,"Bind failed\n");
		_exit(-1);
	}
	fprintf(fp,"Bind successful\n");

	// 3. Listen for incoming connections
	ret = listen(sockfd, BACKLOG);     // sockfd, backlog queue, max BACKLOG
	if(ret < 0)
	{
		fprintf(fp,"Listen error\n");
		_exit(-1);
	}
	fprintf(fp,"Listen successful\n");
	
	while(1)
	{
		// 4. Block and wait for client connections
		address_len = sizeof(struct sockaddr);  // Assign value to client_len
		clifd = accept(sockfd, (struct sockaddr *)&cliaddr, &address_len);     // Block here to listen for client connections
		if(clifd < 0)
		{
			fprintf(fp,"Accept failed\n");
			_exit(-1);
		}
		fprintf(fp,"Listen successful, clifd = %d client port= %d client ip= %s\n", clifd, ntohs(cliaddr.sin_port), inet_ntoa(cliaddr.sin_addr));

		// Create a new thread to handle data transmission after receiving a successful client connection
		sh[client_num].socket = clifd;
		client_num++;    // Increase the current number of clients

		ret = pthread_create(&th, NULL, client_func1, (void *)(&clifd)); // Create a thread client_func1, passing the client descriptor clifd as a parameter

		if(ret == 0)
		{
			fprintf(fp,"Thread %d created successfully, client %d connected successfully, thread created successfully\r\n", (int)th, clifd);
			pthread_detach(th);   // Detach the thread after successful creation, so it can automatically reclaim resources after exiting
		}
		else
		{
			fprintf(fp,"Thread creation failed\r\n");
			_exit(-1);
		}
	}
}
void *network_connect(void){
	pthread_t th = -1;
	for(int i = 1; i < ID ; i++){
		char IP[16];
		strncpy(IP, ADDRs[i-1], 15);
		IP[15] = '\0';
		int port = PORTs[i-1];

		struct sockaddr_in serverAddr;
		char buffer[BUFFER_SIZE];

		// Create a socket
		tmp_socket[client_num] = socket(AF_INET, SOCK_STREAM, 0);
		if (tmp_socket[client_num] == -1) {
			perror("Failed to create socket");
			_exit(-1);
		}

		// Initialize server address structure
		memset(&serverAddr, 0, sizeof(serverAddr));
		serverAddr.sin_family = AF_INET;
		serverAddr.sin_port = htons(port);
		if (inet_pton(AF_INET, IP, &(serverAddr.sin_addr)) <= 0) {
			perror("Failed to set server IP");
			_exit(-1);
		}

		// Connect to the server
		if (connect(tmp_socket[client_num], (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1) {
			perror("Failed to connect to server");
			_exit(-1);
		}

		// Store the socket descriptor
		sh[client_num].socket = tmp_socket[client_num];
		fprintf(fp,"Connected to server %s:%d\n", IP, port);

		// Send a message to the server
		strcpy(buffer, "Hello, Server!");
		if (sendMsg(tmp_socket[client_num], buffer, strlen(buffer)) == -1) {
			perror("Failed to send data");
			_exit(-1);
		}

		// Create a thread to handle communication with the server
		int ret = pthread_create(&th, NULL, client_func1, (void *)(&tmp_socket[client_num]));
		if(ret == 0) {
			fprintf(fp,"Thread %d created successfully, client %d connected successfully, thread created successfully\r\n", (int)th, tmp_socket[client_num]);
			pthread_detach(th); // Detach the thread to reclaim resources automatically
		} else {
			fprintf(fp,"Thread creation failed\r\n");
			_exit(-1);
		}
		client_num++; // Increment the client count
	}
}
