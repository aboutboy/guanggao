#ifndef __MSOCKET_H__
#define __MSOCKET_H__

int connect_socket(char* ip , int port);

int send_data(void* data , int len);

int recv_data(void* data , int len);

int is_connect();

#endif 
