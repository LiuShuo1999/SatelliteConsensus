#include "comm.h"
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

int sendMsg(int cfd, char* msg, int len)
{
	if(msg == NULL || len <= 0 || cfd <=0)
	{
		return -1;
	}

	char* data = (char*)malloc(len+4);
	int bigLen = htonl(len);
	memcpy(data, &bigLen, 4);
	memcpy(data+4, msg, len);

	int ret = writen(cfd, data, len+4);
	
	free(data);
	return ret;
}

int readn(int fd, char* buf, int size)
{
	char* pt = buf;
	int count = size;
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

int recvMsg(int cfd, char** msg)
{

	int len = 0;
	readn(cfd, (char*)&len, 4);
	len = ntohl(len);
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

void *client_func(void *clifd_recv)
{
	int ret = -1;
	char recv_buf[BUFFER_SIZE];       
	char send_buf[BUFFER_SIZE];        
	int clifd = *(int *)clifd_recv;   
	fprintf(fp,"New client %d connect success,thread start work\r\n",clifd);
	char **msg;
	msg = (char**)malloc(sizeof(char*));
	while(1)
	{	
		// Receive message from client
		ret = recvMsg(clifd,msg);
		if(ret < 1)
		{
			fprintf(fp,"client %d close",clifd);
			close(clifd);      
			client_num--;    
			pthread_exit(NULL);  
		}
		
		// Handle received proposal
		if(ret == sizeofp){
			if(debug_flag){
				gettimeofday(&end_block,NULL);
				double tmp_time = (end_block.tv_sec-start_block.tv_sec) + (end_block.tv_usec-start_block.tv_usec) / 1000000.0;
				fprintf(fp,"\033[31m Block Time:%f \033[0m\n",tmp_time);
			}
			for(int i=0;i<sizeofp;i++)
				proposal[i] = (*msg)[i];		
		}
		// Handle received msg_P
		else if(ret == sizeof(struct msg_P)){
			struct msg_P m;
			memcpy(&m,*msg,ret);
			if(m.tag == 'b'){
				// Verify signature
				struct sign_struct tmp;
				tmp.tag = m.tag;
				tmp.id = m.id;
				tmp.block_id = m.block_id;
				tmp.vote = 1;
				for(int i=0;i<HASH_SIZE;i++)tmp.hash[i] = m.hash[i];

				char tmphash[32];
				if(debug_flag){
					sha2(proposal,sizeofp,tmphash,0);
					fprintf(fp,"recv: block_hash\n");
					for(int i=0;i<HASH_SIZE;i++)fprintf(fp,"%02x ",tmp.hash[i]);fprintf(fp,"\n");

					fprintf(fp,"my block_hash\n");
					for(int i=0;i<HASH_SIZE;i++)fprintf(fp,"%02x ",tmphash[i]);fprintf(fp,"\n");

					for(int i=0;i<HASH_SIZE;i++)
						if(tmphash[i] != tmp.hash[i]){
							fprintf(fp,"Wrong Block\n");
							_exit(-1);
						}
				}
				
				__uint8_t hash[32];
				__uint8_t sig[64];
				for(int i=0;i<SIG_SIZE;i++)sig[i] = m.sig[i];

				hash_sign_struct(hash,&tmp);
				if(block_id != m.block_id){
					fprintf(fp,"block_id != m.block_id %d %d\n",block_id, m.block_id);
					continue;
				}

				if (!uECC_verify(public_key[m.id], hash, 32, sig, uECC_secp192r1())) {
					fprintf(fp,"uECC_verify() failed28\n");
					return 1;
				}else {
					block_id = m.block_id;
					for(int i=0;i<HASH_SIZE;i++)block_hash[i] = m.hash[i];
					consensus_state = 'p';
				}
			}

		}
		// Handle received msg
		else if(ret == sizeof(struct msg)){
			struct msg m;
			memcpy(&m,*msg,ret);
			
			if(m.tag == 'p' || m.tag == 'c' || m.tag == 'd' || m.tag == 'v' ){
				if(block_id != m.block_id){
					fprintf(fp,"block_id != m.block_id1\n");
					continue;
				}
				// Verify signature
				struct sign_struct tmp;
				tmp.tag = m.tag;
				tmp.id = m.id;
				tmp.block_id = m.block_id;
				tmp.vote = m.vote;
				for(int i=0;i<HASH_SIZE;i++)tmp.hash[i] = m.hash[i];
				__uint8_t hash[32];
				__uint8_t sig[64];
				for(int i=0;i<SIG_SIZE;i++)sig[i] = m.sig[i];
				hash_sign_struct(hash,&tmp);

				if (!uECC_verify(public_key[m.id], hash, 32, sig, uECC_secp192r1())) {
					fprintf(fp,"uECC_verify() failed32\n");
					return 1;
				}else{
					if(m.tag == 'p'){
						if(ID == LEADER_ID){
							for(int i=0;i<SIG_SIZE;i++)precommit_sig[m.id][i] = m.sig[i];
							
							if(debug_flag){
								fprintf(fp,"get a precommit msg;\n");
								fprintf(fp,"tot_precommit::%d\n",tot_precommit);
								fprintf(fp,"id:%d\n",m.id);
								fprintf(fp,"block_id:%d\n",m.block_id);
								fprintf(fp,"sig:\n");
								for(int k=0;k<SIG_SIZE;k++)fprintf(fp,"%02x ",precommit_sig[m.id][k]);fprintf(fp,"\n");
								fprintf(fp,"hash:\n");
								for(int k=0;k<HASH_SIZE;k++)fprintf(fp,"%02x ",hash[k]);fprintf(fp,"\n");
							}
							
							down(mtx_sem);
							precommit_id[tot_precommit] = m.id;
							tot_precommit++;

							up(mtx_sem);
							if(tot_precommit >= thres_hold){
								consensus_state = 'p';
							}
							
						}
					}else if(m.tag == 'c'){
						if(ID == LEADER_ID){
							for(int i=0;i<SIG_SIZE;i++)commit_sig[m.id][i] = m.sig[i];
							if(debug_flag){
								fprintf(fp,"get a commit msg; block_id:%d\n",m.block_id);
							}
							
							down(mtx_sem);
							commit_id[tot_commit] = m.id;
							tot_commit++;
							up(mtx_sem);
							if(tot_commit >= thres_hold){
								consensus_state = 'c';
							}
							
						}
					}else if(m.tag == 'd'){
						if(ID == LEADER_ID){
							for(int i=0;i<SIG_SIZE;i++)decide_sig[m.id][i] = m.sig[i];
							if(debug_flag){
								fprintf(fp,"get a decide msg; block_id:%d\n",m.block_id);
							}
							
							down(mtx_sem);
							decide_id[tot_decide] = m.id;
							tot_decide++;
							up(mtx_sem);
							if(tot_decide >= thres_hold){
								consensus_state = 'd';
							}
							
						}
					}else if(m.tag == 'v'){
						if(ID == LEADER_ID){
							for(int i=0;i<SIG_SIZE;i++)viewchange_sig[m.id][i] = m.sig[i];
							down(mtx_sem);
							viewchange_id[tot_viewchange] = m.id;
							if(debug_flag){
								fprintf(fp,"get a viewchange msg; block_id:%d\n",m.block_id);
							}
							
							tot_viewchange++;
							up(mtx_sem);
							if(tot_viewchange >= thres_hold){
								consensus_state = 'v';
							}
							
						}
					}
				}
			}
		}
		// Handle received msg_L
		else if(ret == sizeof(struct msg_L)){
			struct msg_L m;
			memcpy(&m,*msg,ret);
			
			if(m.tag == 'p' || m.tag == 'c' || m.tag == 'd' || m.tag == 'v' ){
				if(block_id != m.block_id){
					fprintf(fp,"block_id != m.block_id2\n");
					continue;
				}
				// Verify signature
				struct sign_struct2 tmp;
				tmp.tag = m.tag;
				tmp.id = m.id;
				tmp.block_id = m.block_id;
				tmp.vote = m.vote;
				for(int i=0;i<HASH_SIZE;i++)tmp.hash[i] = m.hash[i];
				for(int i=0;i<2*f;i++)for(int j=0;j<SIG_SIZE;j++)tmp.sigs[i][j] = m.sigs[i][j];

				__uint8_t hash[32];
				__uint8_t sig[64];
				for(int i=0;i<SIG_SIZE;i++)sig[i] = m.sig[i];
				hash_sign_struct2(hash,&tmp);
				
				if (!uECC_verify(public_key[m.id], hash, 32, sig, uECC_secp192r1())) {
					fprintf(fp,"uECC_verify() failed33\n");
					return 1;
				}else{
					for(int i=0;i<2*f;i++){
						struct sign_struct tmp;
						tmp.tag = m.tag;
						tmp.id = m.ids[i];
						tmp.block_id = m.block_id;
						tmp.vote = m.vote;
						for(int k=0;k<HASH_SIZE;k++)tmp.hash[k] = m.hash[k];
						__uint8_t hash[32];
						hash_sign_struct(hash,&tmp);

						for(int j=0;j<SIG_SIZE;j++)
							sig[j] = m.sigs[i][j];
						if(debug_flag){
							fprintf(fp,"\033[33m Recv from leader \033[0m\n");
							fprintf(fp,"tag:%c\nid:%d\nblock_id:%d\nvote:%d\n",tmp.tag,tmp.id,tmp.block_id,tmp.vote);
							fprintf(fp,"hash:\n");
							for(int k=0;k<HASH_SIZE;k++)fprintf(fp,"%02x ",tmp.hash[k]);fprintf(fp,"\n");

							fprintf(fp,"i:%c:%d\n",m.tag,i);
							fprintf(fp,"id:%d\n",m.ids[i]);
							fprintf(fp,"sig:\n");
							for(int k=0;k<SIG_SIZE;k++)fprintf(fp,"%02x ",sig[k]);fprintf(fp,"\n");
							fprintf(fp,"hash:\n");
							for(int k=0;k<HASH_SIZE;k++)fprintf(fp,"%02x ",hash[k]);fprintf(fp,"\n");
						}
						
						if (!uECC_verify(public_key[m.ids[i]], hash, 32, sig, uECC_secp192r1())) {
							fprintf(fp,"uECC_verify() failed3x\n");
							_exit(-1);
						}
					}
					if(m.tag == 'p'){
						if(ID != LEADER_ID){
							consensus_state = 'c';
						}
					}else if(m.tag == 'c'){
						if(ID != LEADER_ID){
							consensus_state = 'd';
						}
					}else if(m.tag == 'd'){
						if(ID != LEADER_ID){
							consensus_state = 'v';
						}
					}else if(m.tag == 'v'){
						if(ID != LEADER_ID){
							consensus_state = 'x';
						}
					}
				}
			}
		}
		// Handle ready and start messages
		else if(ret == 6){
			if(strcmp(*msg,"ready?")==0 && commit == 1){
				sprintf(send_buf,"ready%d",ID);
				if (sendMsg(clifd, (char*)send_buf, strlen(send_buf)) == -1) {
					perror("Failed to send data");
					_exit(-1);
				}
			}else if(strcmp(*msg,"start!")==0){
				ready=1;
			}else{
				int id = (*msg)[5]-'0';
				down(mtx_sem);
				if(ready_node[id]==0xff){
					ready_number++;
					ready_node[id]=1;
				}
				up(mtx_sem);
			}
		}
		memset(recv_buf,0,sizeof(recv_buf));   
		memset(send_buf,0,sizeof(send_buf));   
	}
}


void broadcast(char tag) { // b->proposal p->prepare c->commit
	char send_buf[BUFFER_SIZE];
	char tmp_buf[BUFFER_SIZE];

	int ret = -1;
	memset(send_buf, 0, BUFFER_SIZE);

	if (tag == 'b') {
		struct msg_P m;
		m.tag = 'b';
		m.id = ID;
		m.block_id = block_id;
		for (int i = 0; i < HASH_SIZE; i++) m.hash[i] = block_hash[i];

		// Sign the message
		struct sign_struct tmp;
		tmp.tag = m.tag;
		tmp.id = m.id;
		tmp.block_id = m.block_id;
		tmp.vote = 1;
		for (int i = 0; i < HASH_SIZE; i++) tmp.hash[i] = m.hash[i];
		__uint8_t hash[32];
		__uint8_t sig[64];
		hash_sign_struct(hash, &tmp);
		if (!uECC_sign(private_key[ID], hash, 32, sig, uECC_secp192r1())) {
			fprintf(fp, "uECC_sign() failed\n");
			return;
		}

		for (int i = 0; i < SIG_SIZE; i++) m.sig[i] = sig[i];

		if (!uECC_verify(public_key[ID], hash, 32, m.sig, uECC_secp192r1())) {
			fprintf(fp, "uECC_verify() failed2111\n");
			return;
		}

		// Broadcast the proposal and message to all clients
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

void *network_listen(void) {
	int ret = -1;
	int sockfd = -1;
	int clifd = -1;
	pthread_t th = -1;

	struct sockaddr_in servaddr = {0};
	struct sockaddr_in cliaddr = {0};
	socklen_t address_len = 0;

	// Create socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		fprintf(fp, "socket establish failed\n");
		_exit(-1);
	}

	fprintf(fp, "sockfd =  %d \n", sockfd);

	int on = 1;
	ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	// Bind socket
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(LISTEN_PORT);
	servaddr.sin_addr.s_addr = inet_addr(ADDRs[ID - 1]);
	memset(servaddr.sin_zero, 0, sizeof(servaddr.sin_zero));
	ret = bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr));
	if (ret < 0) {
		fprintf(fp, "bind fail\n");
		_exit(-1);
	}
	fprintf(fp, "bind success\n");

	// Listen on socket
	ret = listen(sockfd, BACKLOG);
	if (ret < 0) {
		fprintf(fp, "listen error\n");
		_exit(-1);
	}
	fprintf(fp, "listen success\n");

	while (1) {
		address_len = sizeof(struct sockaddr);
		clifd = accept(sockfd, (struct sockaddr *)&cliaddr, &address_len);
		if (clifd < 0) {
			fprintf(fp, "accept fail\n");
			_exit(-1);
		}
		fprintf(fp, "listen success, clifd = %d client port= %d client ip= %s\n", clifd, ntohs(cliaddr.sin_port), inet_ntoa(cliaddr.sin_addr));

		sh[client_num].socket = clifd;
		client_num++;

		// Create a new thread for each client
		ret = pthread_create(&th, NULL, client_func, (void *)(&clifd));
		if (ret == 0) {
			fprintf(fp, "Thread %d recv a client, client %d \r\n", (int)th, clifd);
			pthread_detach(th);
		} else {
			fprintf(fp, "Thread establish failed\r\n");
			_exit(-1);
		}
	}
}

void *network_connect(void) {
	pthread_t th = -1;
	for (int i = 1; i < ID; i++) {
		char IP[16];
		strncpy(IP, ADDRs[i - 1], 15);
		IP[15] = '\0';
		int port = PORTs[i - 1];

		struct sockaddr_in serverAddr;
		char buffer[BUFFER_SIZE];

		temp_socket[client_num] = socket(AF_INET, SOCK_STREAM, 0);
		if (temp_socket[client_num] == -1) {
			perror("Failed to create socket");
			_exit(-1);
		}

		memset(&serverAddr, 0, sizeof(serverAddr));
		serverAddr.sin_family = AF_INET;
		serverAddr.sin_port = htons(port);
		if (inet_pton(AF_INET, IP, &(serverAddr.sin_addr)) <= 0) {
			perror("Failed to set server IP");
			_exit(-1);
		}

		if (connect(temp_socket[client_num], (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1) {
			perror("Failed to connect to server");
			_exit(-1);
		}

		sh[client_num].socket = temp_socket[client_num];

		if (i == 1)
			leader_socket = temp_socket[client_num];

		fprintf(fp, "Connected to server %s:%d\n", IP, port);

		strcpy(buffer, "Hello, Server!");
		if (sendMsg(temp_socket[client_num], buffer, strlen(buffer)) == -1) {
			perror("Failed to send data");
			_exit(-1);
		}
		
		int ret = pthread_create(&th, NULL, client_func, (void *)(&temp_socket[client_num]));

		if (ret == 0) {
			fprintf(fp, "Thread %d connect to nodes, client %d \r\n", (int)th, temp_socket[client_num]);
			pthread_detach(th);
		} else {
			fprintf(fp, "thread establish fail\r\n");
			_exit(-1);
		}
		client_num++;
	}

	while (1);

	//close(clientSocket);
}

