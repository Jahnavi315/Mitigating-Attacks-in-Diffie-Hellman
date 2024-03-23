#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include<arpa/inet.h>
#include<pthread.h>
#include <sys/poll.h>
#include <sys/time.h>
#include<sys/wait.h>
#include <gmp.h>

int main(){
	int sfd = socket(AF_INET,SOCK_STREAM,0);
	
	struct sockaddr_in serveraddr;
	
	memset(&serveraddr,0,sizeof serveraddr);	
	serveraddr.sin_family=AF_INET;
	serveraddr.sin_addr.s_addr=htonl(INADDR_ANY);
	serveraddr.sin_port=htons(9898);
	
	int st = connect(sfd,(struct sockaddr*)&serveraddr,sizeof serveraddr);
	if(st<0){
		perror("connect ");
	}else{
		printf("Connection established\n");
		unsigned char nonce[32];
		int count = recv(sfd,nonce,sizeof nonce,0);
		if(count == -1){
			perror("recv ");
		}else{
			printf("Nonce content: ");
		    	for (size_t i = 0; i < count; i++) {
				printf("%02X ", nonce[i]);
		    	}
		    	printf("\n");
		}
	}
	
	while(1){}
}
