#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <gmp.h>
#include <openssl/sha.h>

#define MAX_ID_LENGTH 32
#define MAX_PASSWORD_LENGTH 32
#define NODE_B_PORT 9999
#define NONCE_LENGTH 32
#define HASH_LENGTH 32
#define MAX_PU_KEY_LENGTH 32

char ipaddr[16];
char my_id[MAX_ID_LENGTH + 1];//IDs are in char type and also store \0 at the end , these will be converted into unsigned char type when required in the code
int port;

void print(unsigned char buff[],int len){
	
	for(int i=0;i<len;i++){
		printf("%02X ",buff[i]);
	}
	printf("\n");
}

void IPLookUp(char* id,char* ipaddr){
	FILE* file = fopen("IPs.txt", "r");

    	if (file == NULL) {
        	perror("Error opening file");
        	return;
    	}

    	char temp_id[MAX_ID_LENGTH + 1];
    	char temp_ip[16];
	char line[100];

    	while (fgets(line, sizeof(line), file) != NULL) {
        	if (sscanf(line, "%32s %15[^\n]", temp_id, temp_ip) == 2) {
        	    if (strcmp(temp_id, id) == 0) {
        	        strcpy(ipaddr, temp_ip);
        	        fclose(file);
        	        return;
        	    }
        	}
    	}

    	fclose(file);
}

// Function to compute SHA-256 hash
void computeSHA256(const unsigned char input[], size_t input_len, unsigned char output[]) {
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, input, input_len);
	SHA256_Final(output, &ctx);
}

// Function to print hash value
void printHash(const unsigned char hash[]) {
	printf("hash Value : ");
    	for (size_t i = 0; i < HASH_LENGTH; i++) {
        	printf("%02x", hash[i]);
    	}
    	printf("\n");
}

int checkIfHashMatch(unsigned char h1[],unsigned char h2[]){
	for(int i=0;i<HASH_LENGTH;i++){
		if(h1[i] != h2[i]){
			return 0;
		}
	}
	return 1;
}

void copyTo(unsigned char* dest,unsigned char* source,int bytes){
	for(int i=0;i<bytes;i++){
		dest[i] = source[i];
	}
}

void extract_nonce(unsigned char nonce_xor_password[],unsigned char nonce[]){
	int bytes_read,bytes_sent;
	
	printf("Nonce XOR Password rcvd from server : ");
	print(nonce_xor_password,NONCE_LENGTH);
	printf("\n");
	    	
    	//extracting nonce
    	printf("Enter your password to continue : ");
    	fflush(stdout);
    	
    	char password[MAX_PASSWORD_LENGTH + 1];
    	bytes_read = read(0,password,sizeof password);
    	if(bytes_read == -1){
    		perror("read");
    		return;
    	}
    	password[bytes_read - 1] = '\0';
    	printf("\n");
    	//printf("Your Password is : ");
    	//print((unsigned char*)password,strlen(password));
    	
    	int p_index = strlen(password) - 1;
    	
    	for(int i=31;i>=0;i--){
		if(p_index != -1){
			nonce[i] = nonce_xor_password[i] ^ (unsigned char)(password[p_index--]);
		}else{
			nonce[i] = nonce_xor_password[i];
		}
	}
	
	//printing nonce extracted
	printf("Nonce : ");
    	print(nonce,NONCE_LENGTH);
    	
}

void D_puKey(unsigned char *Y) {
	for(int i = 0; i < MAX_PU_KEY_LENGTH; i++) {
	        Y[i] = 0; 
	        for (int j = 0; j < 8; j++) {
	            Y[i] |= (rand() & 1) << j; 
	        }
	}
}

void* node_as_A(void* args){

	printf("Executing as Node - A\n\n");
	
	int bytes_read,bytes_sent;

	//IDs input
	char id_b[MAX_ID_LENGTH + 1];
	//IDs are in char type and also store \0 at the end , these will be converted into unsigned char type when required in the code
	char ipaddr_b[16];
		
	//Connecting to server
	int sfd = socket(AF_INET,SOCK_STREAM,0);
	
	struct sockaddr_in serveraddr;
	
	memset(&serveraddr,0,sizeof serveraddr);	
	serveraddr.sin_family=AF_INET;
	if (inet_pton(AF_INET, "127.0.0.5", &serveraddr.sin_addr) != 1) {
		perror("inet_pton");
	}
	serveraddr.sin_port=htons(9898);
	
	int st = connect(sfd,(struct sockaddr*)&serveraddr,sizeof serveraddr);
	if(st<0){
		perror("connect ");
	}else{
		printf("Connection established with server\n\n");
		
		printf("Enter ID of Node - B : ");
		fflush(stdout);
		
		bytes_read = read(0,id_b,MAX_ID_LENGTH + 1);
		if(bytes_read == -1){
			perror("read");
		}else{
			id_b[bytes_read -1] = '\0';
			//printf("Node-B ID %s ...\n",id_b);
		}
	
		//find node-B ipaddr
		IPLookUp(id_b,ipaddr_b);
		//printf("Node-B IP..%s\n\n",ipaddr_b);
	
		//send ids
		char ids__ip[2*MAX_ID_LENGTH + 20];
		sprintf(ids__ip,"%s||%s||%s",my_id,id_b,ipaddr_b);
		//printf("Sending IDs,IP : %s\n",ids__ip);
		bytes_sent = send(sfd,ids__ip,strlen(ids__ip),0);
		if(bytes_sent != strlen(ids__ip)){
			perror("send");
		}else{
			printf("Sent IDs to the server\n\n");
		}
		
		unsigned char nonce[NONCE_LENGTH];		
		unsigned char nonce_xor_password[NONCE_LENGTH];
		
		printf("Extracting nonce..\n");
		//rcv nonce_xor_password
		bytes_read = recv(sfd,nonce_xor_password,sizeof nonce_xor_password,0);
		if(bytes_read != NONCE_LENGTH){
			//when nonce_xor_password is not of 32 bytes!!
			printf("Did not receive 32 bytes!\n");
			return NULL;
		}
		extract_nonce(nonce_xor_password,nonce);
		
		//Start Key exchange process
		
		//A sends YA||H(YA||N1)||IDA to B
		unsigned char Ya[MAX_PU_KEY_LENGTH];
		unsigned char Ya__nonce[MAX_PU_KEY_LENGTH + 2 + NONCE_LENGTH];
		unsigned char hash_Ya__nonce[HASH_LENGTH];
		//buffer to be sent to node B
		unsigned char Ya__hash_Ya__nonce__ida[MAX_PU_KEY_LENGTH + 2 + HASH_LENGTH + 2 + MAX_ID_LENGTH];
		
		//computing YA to be done later
		D_puKey(Ya);
		
		//fill Ya||Nonce
		copyTo(Ya__nonce,Ya,MAX_PU_KEY_LENGTH);
		Ya__nonce[MAX_PU_KEY_LENGTH] = Ya__nonce[MAX_PU_KEY_LENGTH + 1] = '|';
		copyTo(Ya__nonce + MAX_PU_KEY_LENGTH + 2,nonce,NONCE_LENGTH);
		
		//printing Ya||Nonce content
		//printf("YA||Nonce : ");
		//print(Ya__nonce,sizeof Ya__nonce);
		
		//find H(YA||Nonce)
		computeSHA256(Ya__nonce,sizeof Ya__nonce,hash_Ya__nonce);
		//printf("YA||Nonce ");
		//printHash(hash_Ya__nonce);
		
		//fill YA||H(Ya||NOnce)||IDA
		copyTo(Ya__hash_Ya__nonce__ida,Ya,MAX_PU_KEY_LENGTH);
		Ya__hash_Ya__nonce__ida[MAX_PU_KEY_LENGTH] = Ya__hash_Ya__nonce__ida[MAX_PU_KEY_LENGTH + 1] = '|';
		copyTo(Ya__hash_Ya__nonce__ida + MAX_PU_KEY_LENGTH + 2,hash_Ya__nonce,HASH_LENGTH);
		Ya__hash_Ya__nonce__ida[MAX_PU_KEY_LENGTH + 2 + HASH_LENGTH] = Ya__hash_Ya__nonce__ida[MAX_PU_KEY_LENGTH + 2 + HASH_LENGTH + 1] = '|';
		copyTo(Ya__hash_Ya__nonce__ida + MAX_PU_KEY_LENGTH + 2 + HASH_LENGTH + 2, (unsigned char*)my_id , strlen(my_id));
		
		//Connect to Node - B
		int bsfd = socket(AF_INET,SOCK_STREAM,0);
	    	
	    	struct sockaddr_in b_addr;
	
		memset(&b_addr,0,sizeof b_addr);	
		b_addr.sin_family=AF_INET;
		if (inet_pton(AF_INET, ipaddr_b, &b_addr.sin_addr) != 1) {
			perror("inet_pton");
		}
		b_addr.sin_port=htons(NODE_B_PORT);
		
		int st = connect(bsfd,(struct sockaddr*)&b_addr,sizeof b_addr);
		if(st<0){
			perror("connect ");
			return NULL;
		}
		printf("\nConnection with Node-B successful\n");
		
		//print the buffer we are sending - Ya__hash_Ya__nonce__ida
		printf("\nSending YA||(H(YA||Nonce)||IDA) to Node-B :\n");
		print(Ya__hash_Ya__nonce__ida,sizeof Ya__hash_Ya__nonce__ida);
		printf("\n");
		
		bytes_sent = send(bsfd,Ya__hash_Ya__nonce__ida,sizeof Ya__hash_Ya__nonce__ida,0);
		if(bytes_sent != sizeof Ya__hash_Ya__nonce__ida){
			perror("send ");
			return NULL;
		}
		
		//rcv YB||H(YB||f(Nonce))||IDB from B
		unsigned char rcvd_Yb__hash_Yb__f_nonce__idb[MAX_PU_KEY_LENGTH + 2 + HASH_LENGTH + 2 + MAX_ID_LENGTH];
		unsigned char comp_Yb__f_nonce[MAX_PU_KEY_LENGTH + 2 + HASH_LENGTH];
		unsigned char comp_hash_Yb__f_nonce[HASH_LENGTH];
		
		bytes_read = recv(bsfd,rcvd_Yb__hash_Yb__f_nonce__idb,sizeof rcvd_Yb__hash_Yb__f_nonce__idb,0);
		
		printf("Rcvd YB||H(YB||f(Nonce))||IDB from Node-B : \n");
		print(rcvd_Yb__hash_Yb__f_nonce__idb,sizeof rcvd_Yb__hash_Yb__f_nonce__idb);
		
		//find YB||f(Nonce) from rcvd YB and Nonce from Server
		copyTo(comp_Yb__f_nonce,rcvd_Yb__hash_Yb__f_nonce__idb,MAX_PU_KEY_LENGTH);
		comp_Yb__f_nonce[MAX_PU_KEY_LENGTH] = comp_Yb__f_nonce[MAX_PU_KEY_LENGTH + 1] = '|';
		for(int i=0;i<NONCE_LENGTH;i++){
			comp_Yb__f_nonce[MAX_PU_KEY_LENGTH + 2 + i] = (nonce[i] + i)%256;
		}
		
		//find H(YB||f(Nonce))
		computeSHA256(comp_Yb__f_nonce,sizeof comp_Yb__f_nonce,comp_hash_Yb__f_nonce);
		printf("\nComputed YB||f(Nonce) ");
		printHash(comp_hash_Yb__f_nonce);
		
		int is_hash_Yb__f_nonce_matched = checkIfHashMatch(comp_hash_Yb__f_nonce,rcvd_Yb__hash_Yb__f_nonce__idb + MAX_PU_KEY_LENGTH + 2);
		if(is_hash_Yb__f_nonce_matched){
			printf("\nRcvd and computed H(YB||f(Nonce)) MATCHED!!\n\n");
		}else{
			printf("MISMATCH IN HASHES!!TERMINATED..\n");
			return NULL;
		}
		
		//compute secret key
		
		//send H(Nonce) to B
		unsigned char hash_nonce[HASH_LENGTH];
		computeSHA256(nonce,sizeof nonce,hash_nonce);
		printf("Nonce ");
		printHash(hash_nonce);
		
		bytes_sent = send(bsfd,hash_nonce,sizeof hash_nonce,0);
		if(bytes_sent != sizeof hash_nonce){
			perror("send ");
			return NULL;
		}
		printf("Sent H(Nonce) to Node-B successfully...\n");
		printf("\nKey Exchange Successful....\nTerminating the session..\n");
		
		close(bsfd);
		close(sfd);
	}
}

void* node_as_B(void* args){
	
	printf("Executing as Node - B\n\n");

	int bytes_read,bytes_sent;

	int sfd = socket(AF_INET,SOCK_STREAM,0);
	
	int option=1;
	setsockopt(sfd,SOL_SOCKET,SO_REUSEADDR|SO_REUSEPORT,&option,sizeof option);
	
	struct sockaddr_in addr;
	memset(&addr,0,sizeof addr);
	
	addr.sin_family=AF_INET;
	
	if (inet_pton(AF_INET, ipaddr, &addr.sin_addr) != 1) {
		perror("inet_pton");
	}
	addr.sin_port=htons(NODE_B_PORT);
	
	if(bind(sfd,(struct sockaddr*)&addr,sizeof addr)==-1){
		perror("bind ");
	}
	
	listen(sfd,3);
	
	//accept req from server
	int nsfd = accept(sfd,NULL,NULL);
	if(nsfd != -1){
		printf("Server established connection!\n\n");
		
		unsigned char nonce_xor_p__hash_nonce_xor_p__ida[NONCE_LENGTH + 2 + HASH_LENGTH];//rcvd
		unsigned char nonce_xor_password[NONCE_LENGTH];//rcvd
		unsigned char nonce[NONCE_LENGTH];
		unsigned char rcvd_hash_nonce_xor_p__ida[HASH_LENGTH];
		
		printf("Extracting nonce..\n");
		//rcv nonce_xor_password
		bytes_read = recv(nsfd,nonce_xor_p__hash_nonce_xor_p__ida,sizeof nonce_xor_p__hash_nonce_xor_p__ida,0);
		if(bytes_read == -1){
			perror("recv");
			return NULL;
		}
		
		//extract Nonce XOR Password from rcvd buffer
		copyTo(nonce_xor_password,nonce_xor_p__hash_nonce_xor_p__ida,NONCE_LENGTH);
		extract_nonce(nonce_xor_password,nonce);
		
		//extract H(Nonce XOR PB || IDA)
		copyTo(rcvd_hash_nonce_xor_p__ida,nonce_xor_p__hash_nonce_xor_p__ida + NONCE_LENGTH + 2, HASH_LENGTH);
		
		printf("\nRcvd(from Server) (Nonce XOR password)||IDA ");
		printHash(rcvd_hash_nonce_xor_p__ida);
		
		//accept connection request from Node - A
		int nsfd_a = accept(sfd,NULL,NULL);
		if(nsfd_a != -1){
			printf("\nAccepted Node - A's connection request!\n\n");
			
			unsigned char rcvd_Ya__hash_Ya__nonce__ida[MAX_PU_KEY_LENGTH + 2 + HASH_LENGTH + 2 + MAX_ID_LENGTH];
			unsigned char rcvd_Ya[MAX_PU_KEY_LENGTH];
			unsigned char rcvd_hash_Ya__nonce[HASH_LENGTH];
			unsigned char rcvd_ida[MAX_ID_LENGTH];
			unsigned char comp_Ya__nonce[MAX_PU_KEY_LENGTH + 2 + NONCE_LENGTH];
			unsigned char comp_hash_Ya__nonce[HASH_LENGTH];
			
			bytes_read = recv(nsfd_a,rcvd_Ya__hash_Ya__nonce__ida,sizeof rcvd_Ya__hash_Ya__nonce__ida,0);
			if(bytes_read == -1){
				perror("recv ");
				return NULL;
			}
			
			printf("Rcvd YA||(H(YA||nonce))||IDA from Node-A : \n");
			print(rcvd_Ya__hash_Ya__nonce__ida,sizeof rcvd_Ya__hash_Ya__nonce__ida);
			printf("\n");
			
			//Extract YA
			copyTo(rcvd_Ya,rcvd_Ya__hash_Ya__nonce__ida,MAX_PU_KEY_LENGTH);
			//print rcvd YA
			//printf("Rcvd YA : ");
			//print(rcvd_Ya,sizeof rcvd_Ya);
			
			//Extract H(YA||nonce)
			copyTo(rcvd_hash_Ya__nonce,rcvd_Ya__hash_Ya__nonce__ida + MAX_PU_KEY_LENGTH + 2,HASH_LENGTH);
			//printing hash of YA||nonce
			//printf("Rcvd YA||Nonce ");
			//printHash(rcvd_hash_Ya__nonce);
			
			//Extract IDA
			copyTo(rcvd_ida,rcvd_Ya__hash_Ya__nonce__ida + MAX_PU_KEY_LENGTH + 2 + HASH_LENGTH + 2,MAX_ID_LENGTH);
			//print rcvd IDA (from A)
			//printf("Rcvd IDA from A : ");
			//print(rcvd_ida,sizeof rcvd_ida);
			
			
			//Find YA||Nonce
			copyTo(comp_Ya__nonce,rcvd_Ya__hash_Ya__nonce__ida,MAX_PU_KEY_LENGTH);
			comp_Ya__nonce[MAX_PU_KEY_LENGTH] = comp_Ya__nonce[MAX_PU_KEY_LENGTH + 1] = '|';
			copyTo(comp_Ya__nonce + MAX_PU_KEY_LENGTH + 2,nonce,NONCE_LENGTH);
			
			//find H(YA||Nonce)
			computeSHA256(comp_Ya__nonce,sizeof comp_Ya__nonce,comp_hash_Ya__nonce);
			//print H(YA||Nonce) which is calculated
			printf("Computed YA||Nonce ");
			printHash(comp_hash_Ya__nonce);
			
			//check if rcvd hash(from A) and computed hash of : YA(rcvd from A) || nonce(rcvd from server) match!
			int hash_Ya__nonce_matched = checkIfHashMatch(comp_hash_Ya__nonce,rcvd_hash_Ya__nonce);
			
			if(!hash_Ya__nonce_matched){
				printf("HASH MISMATCH!!\nTerminated\n");
				return NULL;
			}
			printf("Received and Computed Hash of YA||Nonce MATCHED..\n");
			
			//check if Nonce XOR Password (rcvd from server) || ida (rcvd from A) hash value match with the H(Nonce XOR Password || IDA) (sent by)
			unsigned char comp_nonce_xor_p__ida[NONCE_LENGTH + 2 + MAX_ID_LENGTH];
			unsigned char comp_hash_nonce_xor_p__ida[HASH_LENGTH];
			
			//find Nonce XOR P || IDA, with nonce XOR P rcvd from AS, IDA rcvd from A
			copyTo(comp_nonce_xor_p__ida,nonce_xor_password,NONCE_LENGTH);
			comp_nonce_xor_p__ida[NONCE_LENGTH] = comp_nonce_xor_p__ida[NONCE_LENGTH + 1] = '|';
			copyTo(comp_nonce_xor_p__ida + NONCE_LENGTH + 2,rcvd_ida,MAX_ID_LENGTH);
			
			//find H(Nonce XOR P || IDA)
			computeSHA256(comp_nonce_xor_p__ida,sizeof comp_nonce_xor_p__ida,comp_hash_nonce_xor_p__ida);
			printf("\nComputed Nonce XOR Password || IDA ");
			printHash(comp_hash_nonce_xor_p__ida);
			
			int hash_nonce_xor_p__ida_matched = checkIfHashMatch(comp_hash_nonce_xor_p__ida,rcvd_hash_nonce_xor_p__ida);
			
			if(!hash_nonce_xor_p__ida_matched){
				printf("HASH MISMATCH!!\nTERMINATED\n");
			}
			printf("Hashes of Nonce XOR Password || IDA MATCHED..\n");
			
			//B sending YB||H(YB|| f(N1))||IDB  to A
			
			unsigned char Yb[MAX_PU_KEY_LENGTH];
			unsigned char Yb__f_nonce[MAX_PU_KEY_LENGTH + 2 + NONCE_LENGTH];
			unsigned char hash_Yb__f_nonce[HASH_LENGTH];
			unsigned char Yb__hash_Yb__f_nonce__idb[MAX_PU_KEY_LENGTH + 2 + HASH_LENGTH + 2 + MAX_ID_LENGTH];
			// Compute YB,later
			D_puKey(Yb);
			
			//print YB
			//printf("YB : ");
			//print(Yb,sizeof Yb);
			
			//compute YB||f(Nonce)
			copyTo(Yb__f_nonce,Yb,MAX_PU_KEY_LENGTH);
			Yb__f_nonce[MAX_PU_KEY_LENGTH] = Yb__f_nonce[MAX_PU_KEY_LENGTH + 1] = '|';
			//manipulate nonce with function f => f(x) = (x + x.index)%256
			for(int i=0;i<NONCE_LENGTH;i++){
				Yb__f_nonce[MAX_PU_KEY_LENGTH + 2 + i] = (nonce[i] + i)%256;
			}
			
			//print YB||f(nonce)
			//printf("YB || f(Nonce) : ");
			//print(Yb__f_nonce,sizeof Yb__f_nonce);
			
			//find H(YB||f(Nonce))
			computeSHA256(Yb__f_nonce,sizeof Yb__f_nonce,hash_Yb__f_nonce);
			//printf("YB || f(Nonce) ");
			//printHash(hash_Yb__f_nonce);
			
			//compute YB||H(YB||f(Nonce))||IDB
			copyTo(Yb__hash_Yb__f_nonce__idb,Yb,MAX_PU_KEY_LENGTH);
			Yb__hash_Yb__f_nonce__idb[MAX_PU_KEY_LENGTH] = Yb__hash_Yb__f_nonce__idb[MAX_PU_KEY_LENGTH + 1] = '|';
			copyTo(Yb__hash_Yb__f_nonce__idb + MAX_PU_KEY_LENGTH + 2,hash_Yb__f_nonce,HASH_LENGTH);
			Yb__hash_Yb__f_nonce__idb[MAX_PU_KEY_LENGTH + 2 + HASH_LENGTH] = Yb__hash_Yb__f_nonce__idb[MAX_PU_KEY_LENGTH + 2 + HASH_LENGTH + 1] = '|';
			copyTo(Yb__hash_Yb__f_nonce__idb + MAX_PU_KEY_LENGTH + 2 + HASH_LENGTH + 2,(unsigned char*)my_id,strlen(my_id));
			
			printf("\nSending YB||H(YB||f(Nonce))||IDB to Node-A : \n");
			print(Yb__hash_Yb__f_nonce__idb,sizeof Yb__hash_Yb__f_nonce__idb);
			
			//send YB||H(YB||f(Nonce))||IDB to A
			bytes_sent = send(nsfd_a,Yb__hash_Yb__f_nonce__idb,sizeof Yb__hash_Yb__f_nonce__idb,0);
			if(bytes_sent != sizeof Yb__hash_Yb__f_nonce__idb){
				perror("Send ");
				return NULL;
			}
			
			//compute secret key
			
			//rcv H(Nonce)
			unsigned char rcvd_hash_nonce[HASH_LENGTH];
			unsigned char comp_hash_nonce[HASH_LENGTH];
			bytes_read = recv(nsfd_a,rcvd_hash_nonce,sizeof rcvd_hash_nonce,0);
			if(bytes_read == -1){
				perror("recv ");
				return NULL;
			}
			computeSHA256(nonce,sizeof nonce,comp_hash_nonce);
			
			if(checkIfHashMatch(rcvd_hash_nonce,comp_hash_nonce)){
				printf("\nKey Exchange Successful....\nTerminating the session..\n");
			}else{
				printf("Unsuccessful Key Exchange..\nRestart the process..\nSession Terminated\n\n");
			}
			close(nsfd_a);
			close(nsfd);
			
		}
	}
}


int main(){

	int bytes_read,bytes_sent;

	printf("Enter your ID : ");
	fflush(stdout);
	
	bytes_read = read(0,my_id,MAX_ID_LENGTH + 1);
	if(bytes_read == -1){
		perror("read");
	}else{
		my_id[bytes_read -1] = '\0';
		//printf("Your ID is : %s\n",my_id);
	}
	
	//perform ip-lookup
	IPLookUp(my_id,ipaddr);
	//printf("Your IP..%s\n\n",ipaddr);
		
	printf("Enter Y if you want to start key exchange ! [Y \\ n] ");
	pthread_t A,B;
	char c = getchar();
	getchar();
	if(c != 'Y'){
		pthread_create(&B,NULL,node_as_B,NULL);
		pthread_join(B,NULL);
	}else{
		pthread_create(&A,NULL,node_as_A,NULL);
		pthread_join(A,NULL);
	}
	
	
}
