#include "comm.h"

void *client_func(void *clifd_recv)
{
	int ret = -1;
	char recv_buf[BUFFER_SIZE];       
	char send_buf[BUFFER_SIZE];        
	int clifd = *(int *)clifd_recv;   
	fprintf(fp,"New client %d connect success, thread start work\r\n",clifd);
	char **msg;
	msg = (char**)malloc(sizeof(char*));
	while(1)
	{	
		// Receive message from client
		ret = recvMsg(clifd, msg);
		if(ret < 1)
		{
			fprintf(fp,"client %d close",clifd);
			close(clifd);      
			client_num--;    
			pthread_exit(NULL);  
		}
		//fprintf(fp,"\033[32m Recv client data %d len= %d  buf= %s\033[0m\n",clifd,ret,*msg);
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
		// Handle received msg_P structure
		else if(ret == sizeof(struct msg_P)){
			struct msg_P m;
			memcpy(&m, *msg, ret);
			if(m.tag == 'b'){
				struct sign_struct tmp;
				tmp.tag = m.tag;
				tmp.id = m.id;
				tmp.block_id = m.block_id;
				tmp.vote = 1;
				memcpy(tmp.hash, m.hash, HASH_SIZE);

				__uint8_t hash[32];
				__uint8_t sig[64];
				memcpy(sig, m.sig, SIG_SIZE);

				hash_sign_struct(hash, &tmp);
				
				if(block_id != m.block_id) continue;

				if (!uECC_verify(public_key[m.id], hash, 32, sig, uECC_secp192r1())) {
					fprintf(fp,"uECC_verify() failed28\n");
					return 1;
				} else {
					block_id = m.block_id;
					memcpy(block_hash, m.hash, HASH_SIZE);
					if(debug_flag){
						fprintf(fp,"recv block hash:\n");
						for(int i=0;i<HASH_SIZE;i++) fprintf(fp,"%02x ",block_hash[i]);
						fprintf(fp,"\n");
					}
					consensus_state = 'p';
					if(debug_flag)
						fprintf(fp," become consensus_state:%c\n",consensus_state);	
				}
			}

		}
		// Handle received msg structure
		else if(ret == sizeof(struct msg)){
			struct msg m;
			memcpy(&m, *msg, ret);
			
			if(m.tag == 'p' || m.tag == 'c' || m.tag == 'd' || m.tag == 'v' ){
				if(block_id != m.block_id) continue;
				// Verify signature
				struct sign_struct2 tmp;
				tmp.tag = m.tag;
				tmp.id = m.id;
				tmp.block_id = m.block_id;
				tmp.vote = m.vote;
				memcpy(tmp.hash, m.hash, HASH_SIZE);
				memcpy(tmp.thres_ch, m.thres_ch, THRES_SIG_SIZE);

				__uint8_t hash[32];
				__uint8_t sig[64];
				memcpy(sig, m.sig, SIG_SIZE);
				hash_sign_struct2(hash, &tmp);
				
				if (!uECC_verify(public_key[m.id], hash, 32, sig, uECC_secp192r1())) {
					fprintf(fp,"uECC_verify() failed31\n");
					return 1;
				} else {
					if(m.tag == 'p'){
						// Verify threshold-signature
						unsigned char ch[100];
						octet o = {0, sizeof(ch), ch};
						memset(ch, 0, sizeof(ch));
						o.len = THRES_SIG_SIZE;
						memcpy(ch, m.thres_ch, THRES_SIG_SIZE);

						ECP_BN254 point;
						hash2point(&point, block_hash);

						if(ID == LEADER_ID){
							down(mtx_sem);
							ECP_BN254_fromOctet(&Sigs_p[tot_precommit], &o);
							S_p[tot_precommit] = m.id-1;

							if(debug_flag){
								fprintf(fp,"\033[33m Recv from the follower %d \033[0m\n",m.id);
								fprintf(fp,"block_hash:\n");
								for(int i=0;i<HASH_SIZE;i++) fprintf(fp,"%02x ",block_hash[i]);
								fprintf(fp,"\nSig\n");
								for(int k=0;k<o.len;k++) fprintf(fp,"%02x ",ch[k]);
								fprintf(fp,"\n");
							}

							if(PK_verify_sig_share(m.id, &Sigs_p[tot_precommit], &point)){
								tot_precommit++;
							} else {
								if(debug_flag){
									fprintf(fp,"\033[33m Recv from the follower %d \033[0m\n",m.id);
									fprintf(fp,"block_hash:\n");
									for(int i=0;i<HASH_SIZE;i++) fprintf(fp,"%02x ",block_hash[i]);
									fprintf(fp,"\nSig\n");
									for(int k=0;k<o.len;k++) fprintf(fp,"%02x ",ch[k]);
									fprintf(fp,"\n");
								}

								fprintf(fp,"verify signature fail %d, tot_precommit:%d,\n\n",m.id, tot_precommit);
								_exit(-1);
							}
							up(mtx_sem);
							if(tot_precommit >= k){
								PK_sig_combine_share(&SIG_p, Sigs_p, S_p);
								if(PK_verify_sig(&SIG_p, &point)){
									consensus_state = 'p';
								} else {
									fprintf(fp,"Combine fail p.\n");
									_exit(-1);
								}
							}
						} else if(ID != LEADER_ID){
							ECP_BN254_fromOctet(&SIG_p, &o);	
							if(PK_verify_sig(&SIG_p, &point)){
								consensus_state = 'c';
							} else {
								if(debug_flag){
									fprintf(fp,"Precommit sig\n");
									for(int i=0;i<32;i++) fprintf(fp," %02x",o.val[i]);
									fprintf(fp,"\n");
								}
								
								fprintf(fp,"Combine fail.1\n");
								_exit(-1);
							}
						}
					} else if(m.tag == 'c'){
						// Verify threshold-signature
						unsigned char ch[100];
						octet o = {0, sizeof(ch), ch};
						memset(ch, 0, sizeof(ch));
						o.len = THRES_SIG_SIZE;
						memcpy(ch, m.thres_ch, THRES_SIG_SIZE);

						__uint8_t hash[32];
						struct sign_struct ttmp;
						ttmp.tag = m.tag;
						ttmp.id = LEADER_ID;
						ttmp.block_id = m.block_id;
						ttmp.vote = 1;
						memcpy(ttmp.hash, m.hash, HASH_SIZE);
						hash_sign_struct(hash, &ttmp);

						ECP_BN254 point;
						hash2point(&point, hash);

						if(ID == LEADER_ID){
							down(mtx_sem);
							ECP_BN254_fromOctet(&Sigs_c[tot_commit], &o);
							S_c[tot_commit] = m.id-1;
							if(PK_verify_sig_share(m.id, &Sigs_c[tot_commit], &point)){
								tot_commit++;
							} else {
								fprintf(fp,"verify signature fail1 %d, tot_commit:%d,\n\n",m.id, tot_commit);
								_exit(-1);
							}
							up(mtx_sem);
							if(tot_commit >= k){
								PK_sig_combine_share(&SIG_c, Sigs_c, S_c);
								if(PK_verify_sig(&SIG_c, &point)){
									consensus_state = 'c';
								} else {
									fprintf(fp,"Combine fail.2\n");
									_exit(-1);
								}
							}
						} else if(ID != LEADER_ID){
							ECP_BN254_fromOctet(&SIG_c, &o);	
							if(PK_verify_sig(&SIG_c, &point)){
								consensus_state = 'd';
							} else {
								fprintf(fp,"Combine fail.3\n");
								_exit(-1);
							}
						}
					} else if(m.tag == 'd'){
						// Verify threshold-signature
						unsigned char ch[100];
						octet o = {0, sizeof(ch), ch};
						memset(ch, 0, sizeof(ch));
						o.len = THRES_SIG_SIZE;
						memcpy(ch, m.thres_ch, THRES_SIG_SIZE);

						__uint8_t hash[32];
						struct sign_struct ttmp;
						ttmp.tag = m.tag;
						ttmp.id = LEADER_ID;
						ttmp.block_id = m.block_id;
						ttmp.vote = 1;
						memcpy(ttmp.hash, m.hash, HASH_SIZE);
						hash_sign_struct(hash, &ttmp);

						ECP_BN254 point;
						hash2point(&point, hash);

						if(ID == LEADER_ID){
							down(mtx_sem);
							ECP_BN254_fromOctet(&Sigs_d[tot_decide], &o);
							S_d[tot_decide] = m.id-1;
							if(PK_verify_sig_share(m.id, &Sigs_d[tot_decide], &point)){
								tot_decide++;
							} else {
								fprintf(fp,"verify signature fail1 %d, tot_decide:%d,\n\n",m.id, tot_decide);
								_exit(-1);
							}
							up(mtx_sem);
							if(tot_decide >= k){
								PK_sig_combine_share(&SIG_d, Sigs_d, S_d);
								if(PK_verify_sig(&SIG_d, &point)){
									consensus_state = 'd';
								} else {
									fprintf(fp,"Combine fail.4\n");
									_exit(-1);
								}
							}
						} else if(ID != LEADER_ID){
							ECP_BN254_fromOctet(&SIG_d, &o);	
							if(PK_verify_sig(&SIG_d, &point)){
								consensus_state = 'v';
							} else {
								fprintf(fp,"Combine fail.5\n");
								_exit(-1);
							}
						}
					} else if(m.tag == 'v'){
						// Verify threshold-signature
						unsigned char ch[100];
						octet o = {0, sizeof(ch), ch};
						memset(ch, 0, sizeof(ch));
						o.len = THRES_SIG_SIZE;
						memcpy(ch, m.thres_ch, THRES_SIG_SIZE);

						__uint8_t hash[32];
						struct sign_struct ttmp;
						ttmp.tag = m.tag;
						ttmp.id = LEADER_ID;
						ttmp.block_id = m.block_id;
						ttmp.vote = 1;
						memcpy(ttmp.hash, m.hash, HASH_SIZE);
						hash_sign_struct(hash, &ttmp);

						ECP_BN254 point;
						hash2point(&point, hash);

						if(ID == LEADER_ID){
							down(mtx_sem);
							ECP_BN254_fromOctet(&Sigs_v[tot_viewchange], &o);
							S_v[tot_viewchange] = m.id-1;
							if(PK_verify_sig_share(m.id, &Sigs_v[tot_viewchange], &point)){
								tot_viewchange++;
							} else {
								fprintf(fp,"verify signature fail1 %d, tot_viewchange:%d,\n\n",m.id, tot_viewchange);
								_exit(-1);
							}
							up(mtx_sem);
							if(tot_viewchange >= k){
								PK_sig_combine_share(&SIG_v, Sigs_v, S_v);
								if(PK_verify_sig(&SIG_v, &point)){
									consensus_state = 'v';
								} else {
									fprintf(fp,"Combine fail.6\n");
									_exit(-1);
								}
							}
						} else if(ID != LEADER_ID){
							ECP_BN254_fromOctet(&SIG_v, &o);	
							if(PK_verify_sig(&SIG_v, &point)){
								consensus_state = 'x';
							} else {
								fprintf(fp,"Combine fail.7\n");
								_exit(-1);
							}
						}
					}
				}
			}
		} else if(ret == 6){
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
		
		memset(recv_buf, 0, sizeof(recv_buf));   
		memset(send_buf, 0, sizeof(send_buf));   
	}
}

void *network_listen(void){
	int ret = -1;
	int sockfd = -1;  	
	int clifd = -1;   	
	pthread_t th = -1;  
	
	struct sockaddr_in servaddr = {0};  
	struct sockaddr_in cliaddr = {0};   
	socklen_t address_len = 0;         
	
	// Create socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);   
	if(sockfd < 0)
	{
		fprintf(fp,"socket establish failed\n");
		_exit(-1);
	}

	fprintf(fp,"sockfd =  %d \n",sockfd);

	int on = 1;
	ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	servaddr.sin_family = AF_INET;             
	servaddr.sin_port = htons(LISTEN_PORT);      
	servaddr.sin_addr.s_addr = inet_addr(ADDRs[ID-1]);  
	memset(servaddr.sin_zero, 0, sizeof(servaddr.sin_zero));   
	ret = bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr));   
	if(ret < 0)
	{
		fprintf(fp,"bind fail\n");
		_exit(-1);
	}
	fprintf(fp,"bind success\n");

	ret = listen(sockfd, BACKLOG);     
	if(ret < 0)
	{
		fprintf(fp,"listen error\n");
		_exit(-1);
	}
	fprintf(fp,"listen success\n");
	
	while(1)
	{
		address_len = sizeof(struct sockaddr);  
		clifd = accept(sockfd, (struct sockaddr *)&cliaddr, &address_len);     
		if(clifd < 0)
		{
			fprintf(fp,"accept fail\n");
			_exit(-1);
		}
		fprintf(fp,"listen success, clifd = %d client port= %d client ip= %s\n", clifd, ntohs(cliaddr.sin_port), inet_ntoa(cliaddr.sin_addr));

		sh[client_num].socket = clifd;
		client_num++;    

		ret = pthread_create(&th, NULL, client_func, (void *)(&clifd)); 
		if(ret == 0)
		{
			fprintf(fp,"Thread %d recv a client, client %d \r\n", (int)th, clifd);
			pthread_detach(th);   
		}
		else
		{
			fprintf(fp,"Thread establish failed\r\n");
			_exit(-1);
		}
	}
}

void *network_connect(void){
	pthread_t th = -1;
	for(int i = 1; i < ID ; i++){
		char IP[16];
		for(int j = 0; j < 15; j++) IP[j] = ADDRs[i-1][j]; 
		IP[15] = '\0';
		int port = PORTs[i-1];
		
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
		
		if(i == 1)
			leader_socket = temp_socket[client_num];

		fprintf(fp,"Connected to server %s:%d\n", IP, port);
	
		strcpy(buffer, "Hello, Server!");

		if (sendMsg(temp_socket[client_num], buffer, strlen(buffer)) == -1) {
			perror("Failed to send data");
			_exit(-1);
		}

		int ret = pthread_create(&th, NULL, client_func, (void *)(&temp_socket[client_num])); 

		if(ret == 0)
		{
			fprintf(fp,"Thread %d connect to nodes, client %d \r\n", (int)th, temp_socket[client_num]);
			pthread_detach(th);   
		}
		else
		{
			fprintf(fp,"Thread establish fail\r\n");
			_exit(-1);
		}
		client_num++;
	}

	while(1);

}


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

void broadcast(char tag) { // b->proposal p->prepare c->commit
	char send_buf[BUFFER_SIZE];        
	char tmp_buf[BUFFER_SIZE];

	int ret = -1;
	memset(send_buf, 0, BUFFER_SIZE); // Initialize send buffer to zero

	if (tag == 'b') {
		struct msg_P m;
		m.tag = 'b';
		m.id = ID;
		m.block_id = block_id;
		memcpy(m.hash, block_hash, HASH_SIZE); // Copy block hash

		// Prepare signature structure
		struct sign_struct tmp;
		tmp.tag = m.tag;
		tmp.id = m.id;
		tmp.block_id = m.block_id;
		tmp.vote = 1;
		memcpy(tmp.hash, m.hash, HASH_SIZE); // Copy hash to signature structure

		__uint8_t hash[32];
		__uint8_t sig[64];
		hash_sign_struct(hash, &tmp); // Generate hash for signature

		// Sign the hash
		if (!uECC_sign(private_key[ID], hash, 32, sig, uECC_secp192r1())) {
			fprintf(fp, "uECC_sign() failed\n");
			return;
		}

		memcpy(m.sig, sig, SIG_SIZE); // Copy signature to message

		// Verify the signature
		if (!uECC_verify(public_key[ID], hash, 32, m.sig, uECC_secp192r1())) {
			fprintf(fp, "uECC_verify() failed2111\n");
			return;
		}

		// Broadcast proposal and message to all clients
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
			// Send "ready?" message to all clients
			for (int i = 0; i < client_num; i++) {
				if (sendMsg(sh[i].socket, (char*)send_buf, strlen(send_buf)) == -1) {
					perror("Failed to send data");
					_exit(-1);
				}
			}
		} else if (tag == 'r' && ID == LEADER_ID) {
			strcpy(send_buf, "start!");
			// Send "start!" message to all clients if current node is the leader
			for (int i = 0; i < client_num; i++) {
				if (sendMsg(sh[i].socket, (char*)send_buf, strlen(send_buf)) == -1) {
					perror("Failed to send data");
					_exit(-1);
				}
			}
		}
	}
	return;
}