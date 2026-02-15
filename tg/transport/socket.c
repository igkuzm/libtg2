/**
 * File              : socket.c
 * Author            : Igor V. Sementsov <ig.kuzm@gmail.com>
 * Date              : 21.11.2024
 * Last Modified Date: 13.02.2026
 * Last Modified By  : Igor V. Sementsov <ig.kuzm@gmail.com>
 */
#include "../../libtg.h"
#include "../tg.h"
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include "../../essential/alloc.h"
#include "../../essential/endian.h"
#include "progress.h"
#include "socket.h"
#include "header.h"

#define TIMEOUT_SECONDS 2

int tg_socket_open(tg_t *tg, const char *ip, int port)
{
  struct sockaddr_in serv_addr;
  struct hostent * server;
	int sockfd;
	struct timeval tv;

  sockfd = 
		socket(AF_INET, SOCK_STREAM, 0);

  if (sockfd < 0) {
		ON_ERR(tg, "%s: can't open socket", __func__);
    return -1;
  }
	
	tv.tv_sec  = TIMEOUT_SECONDS;
	tv.tv_usec = 0;

	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, 
			&tv, sizeof(tv));
	setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, 
			&tv, sizeof(tv));


  server = gethostbyname(ip);
 
  if (server == 0) {
		ON_ERR(tg, "%s: no host with ip: '%s'", __func__, ip);
    return -1;
  }

  bzero((char *) &serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  bcopy(
			(char *)server->h_addr_list[0],
		 	(char *)&serv_addr.sin_addr.s_addr,
		 	server->h_length);
  serv_addr.sin_port = htons(port);

  if (connect(
				sockfd, 
				(struct sockaddr *) &serv_addr, 
				sizeof(serv_addr)) < 0) 
	{
    ON_ERR(tg, "%s: can't connect", __func__);
    return -1;
  }

	// send intermediate protocol
	char init[] = {0xee, 0xee, 0xee, 0xee};
	send(sockfd, init, 4, 0);

	return sockfd;
}

void tg_socket_close(tg_t *tg, int sockfd)
{
  close(sockfd);
}

static size_t tg_socket_receive(
		tg_t *tg, int sockfd, buf_t *answer, 
		void *progressp, tg_progress_fun *progress)
{
	ON_LOG(tg, "%s", __func__);
	
	// get length of the package
	uint32_t len;
	int s = recv(sockfd, &len, 4, 0);
	if (s<0){
		ON_ERR(tg, "%s: %d: socket error: %d", 
				__func__, __LINE__, s);
		return 0;
	}
	printf("LEN: %d\n", len);
	len = le32toh(len);
	printf("LEN: %d\n", len);

	if (len < 0) {
		// this is error - report it
		ON_ERR(tg, "%s: received wrong length: %d", __func__, len);
		return 0;
	}
	
	ON_LOG(tg, "%s: prepare to receive len: %d", __func__, len);
	// realloc buf to be enough size
	if (buf_enlarge_to(answer, len)){
		// handle error
		ON_ERR(tg, "%s: error buf realloc to size: %d", __func__, len);
		return 0;
	}

	// get data
	uint32_t received = 0; 
	while (received < len){
		int s = recv(
				sockfd, 
				&(answer->data[received]), 
				len - received, 
				0);	
		if (s<0){
			ON_ERR(tg, "%s: %d: socket error: %d", 
					__func__, __LINE__, s);
			return 0;
		}
		if (s==0){
			ON_ERR(tg, "%s: %d: nothing to receive", 
				   __func__, __LINE__);
			return received;			
		}
		received += s;
		
		ON_LOG(tg, 
				"%s: expected: %d, received: %d, total: %d (%d%%)", 
				__func__, len, s, received, received*100/len);

		if (progress){
			if(progress(progressp, 0, 0, received, len)){
				buf_free(*answer);
				ON_LOG(tg, "%s: download canceled", __func__);
				// drop
				//tg_add_todrop(queue->tg, queue->msgid);
				return 0;
			}
		}
	}

	return received;
}

buf_t tg_socket_receive_query(tg_t *tg, int socket)
{
	return tg_socket_receive_query_with_progress(
			tg, socket, NULL, NULL);
}

buf_t tg_socket_receive_query_with_progress(
		          tg_t *tg, int socket,
		          void *progressp, tg_progress_fun *progress)
{
	buf_t answer = buf_new();

	answer.size = tg_socket_receive(
			tg, socket, &answer, progressp, progress);

	return answer;
}

int tg_socket_send_query_with_progress(
		tg_t *tg, int socket, buf_t *query,
		void *progressp, tg_progress_fun *progress)
{
	// send query
	buf_t pack = tg_transport_pack(tg, query);
	int s = 
		send(socket, pack.data, pack.size, 0);
	if (s < 0){
		ON_ERR(tg, "%s: socket error: %d", __func__, s);
		return s;
	}
	ON_LOG(tg, "%s: sent: %d", __func__, s);

	buf_free(pack);
	return s;	
}

int tg_socket_send_query(tg_t *tg, int socket, buf_t *query)
{
	return tg_socket_send_query_with_progress(
			tg, socket, query, NULL, NULL);
}
