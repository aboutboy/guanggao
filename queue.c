#include "main.h"
#include <semaphore.h>

struct _shm_queue
{
	struct list_head list;
	unsigned short len;
	unsigned char data[BUFSIZE+1];
};

#define MAX_QUEUE_NUM 10
static sem_t mutex,full,empty;
static struct list_head queue_head;
static struct _shm_queue *front,*rear;

struct _shm_queue* get_next_queue(
	struct _shm_queue *cur)
{
	cur=list_entry(cur->list.next, typeof(*cur), list);
	if(&cur->list==&queue_head)
	{
		cur=list_entry(queue_head.next, typeof(*cur), list);
	}
	return cur;
	
}

int set_queue(void *data , int dlen)
{
	sem_wait(&empty);
	sem_wait(&mutex);	
	front->len=dlen;
	if(front->len>BUFSIZE)
	{
		front->len=BUFSIZE;
	}
	memcpy(front->data,data ,front->len);
	front=get_next_queue(front);
	sem_post(&mutex);
	sem_post(&full);
	return 0;
}

int get_queue(void *data)
{
	sem_wait(&full);
	sem_wait(&mutex);
	memcpy(data,rear->data,rear->len);
	rear=get_next_queue(rear);
	sem_post(&mutex);
	sem_post(&empty);
	return 0;
}

int init_queue()
{
	int i;
	struct _shm_queue *sq;
	
	sem_init(&mutex,0,1);
	sem_init(&empty,0,MAX_QUEUE_NUM);		 
	sem_init(&full,0,0);
	INIT_LIST_HEAD(&queue_head);
	
	for(i=0;i<MAX_QUEUE_NUM;i++)
	{
		sq=(struct _shm_queue*)new_page(sizeof(struct _shm_queue));
		if(!sq)
			return -1;
		la_list_add_tail(&(sq->list), &queue_head);
		if(i==0)
			front=rear=sq;
	}
	return 0;
}

