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

#define MAX_ID_LENGTH 32
#define MAX_PASSWORD_LENGTH 32


int main(){

	int bytes_read,bytes_sent;

	//IDs input
	char my_id[MAX_ID_LENGTH + 1];
	char req_id[MAX_ID_LENGTH + 1];
	
	printf("Enter your id : ");
	fflush(stdout);
	
	bytes_read = read(0,my_id,MAX_ID_LENGTH + 1);
	if(bytes_read == -1){
		perror("read");
	}else{
		my_id[bytes_read -1] = '\0';
		printf("Your id : %s\n",my_id);
	}
	
	printf("Enter id of other node : ");
	fflush(stdout);
	
	bytes_read = read(0,req_id,MAX_ID_LENGTH + 1);
	if(bytes_read == -1){
		perror("read");
	}else{
		req_id[bytes_read -1] = '\0';
		printf("Requesting id : %s\n",req_id);
	}
	
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
		printf("Connection established\n");
		
		//send ids
		char ids[2*MAX_ID_LENGTH + 3];
		sprintf(ids,"%s||%s",my_id,req_id);
		printf("Sending ids : %s\n",ids);
		bytes_sent = send(sfd,ids,strlen(ids),0);
		if(bytes_sent != strlen(ids)){
			perror("send");
		}else{
			printf("Sent ids to the server\n");
		}
			
		//rcv nonce
		unsigned char nonce[32];
		bytes_read = recv(sfd,nonce,sizeof nonce,0);
		if(bytes_read == -1){
			perror("recv ");
		}else{
			printf("Nonce content: ");
		    	for (size_t i = 0; i < bytes_read; i++) {
				printf("%02X ", nonce[i]);
		    	}
		    	printf("\n");
		}
	}
	
	while(1){}
}
