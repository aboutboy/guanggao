#include "mpool.h"
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <semaphore.h>


#define PAGE_SIZE 256
#define MAX_PAGE_NUM  4*1024*1024 // 1G
 
struct mpool
{
	struct mpool* next;
	char is_used;
	char page_num;
	void* data;
};

static void* pool_cache=NULL;
static struct mpool* mp_head=NULL;
static sem_t* pool_mutex;
static int current_page_num=0;

/***
	this mmap only used in fork process father-child
***/
void* new_mmap(int size)
{

	void* new=mmap(NULL, size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED |MAP_ANONYMOUS, -1, 0);
	if(new==MAP_FAILED)
	{
		perror("new mmap error");
		return NULL;
	}
	memset(new , '\0' , size);
	return new;
}

void free_mmap(void *o ,int size)
{
	if(o)
	{
		munmap(o , size);
		o=NULL;
	}
}

void* new_page(int size)
{
	int i,j,page_num;
	page_num=size/PAGE_SIZE+1;
	
	sem_wait(pool_mutex);	
	for(i=0;i+page_num<current_page_num;i+=page_num)
	{
		for(j=0;j<page_num;j++)
		{
			if(mp_head[i+j].is_used)
			{
				break;
			}
		}

		if(j==page_num)
		{
			mp_head[i].is_used=1;
			mp_head[i].page_num=page_num;
			memset(mp_head[i].data , '\0' ,page_num*PAGE_SIZE);
			for(j=0;j<page_num;j++)
			{
				mp_head[i+j].is_used=1;
				mp_head[i+j].page_num=page_num;
			}
			sem_post(pool_mutex);
			return mp_head[i].data;
		}
	}
	
	sem_post(pool_mutex);
	return NULL;

}
void free_page(void* o)
{
	int i,j,page_num;
	sem_wait(pool_mutex);	
	for(i=0;i<current_page_num;i++)
	{
		if(mp_head[i].data==o)
		{
			mp_head[i].is_used=0;
			page_num=mp_head[i].page_num;
			mp_head[i].page_num=0;
			for(j=0;j<page_num;j++)
			{
				mp_head[i+j].is_used=0;
				mp_head[i+j].page_num=0;
			}
			break;
		}
	}
	sem_post(pool_mutex);

}
/*
static void mpool_test()
{
	int i;
	void *a,*b ,*c;
	a=new_page(PAGE_SIZE-1);
	b=new_page(2*PAGE_SIZE+1);
	c=new_page(PAGE_SIZE);
	
	for(i=0;i<current_page_num;i++)
	{
		printf("new num %d is_used %d page_num %d\n" ,i , mp_head[i].is_used ,mp_head[i].page_num);
	}
	free_page(a);
	free_page(b);
	free_page(c);
	for(i=0;i<current_page_num;i++)
	{
		printf("free num %d is_used %d page_num %d\n" ,i , mp_head[i].is_used ,mp_head[i].page_num);
	}
	
}
*/

int init_mpool(int page_num)
{
	int i;

	if(page_num>MAX_PAGE_NUM)
		page_num=MAX_PAGE_NUM;
	
	pool_cache=new_mmap(PAGE_SIZE*page_num);
	if(!pool_cache)
		return -1;

	
	mp_head=(struct mpool*)new_mmap(sizeof(struct mpool)*page_num);
	if(!mp_head)
		return -1;
	
	for(i=0;i<page_num;i++)
	{
		mp_head[i].data=pool_cache+i*PAGE_SIZE;	
	}

	current_page_num=page_num;
	
	pool_mutex=(sem_t*)new_mmap(sizeof(sem_t));
	
	if(!pool_mutex)
			return -1;
	
	sem_init(pool_mutex,1,1);
	//mpool_test();
	return 0;

}

void fini_mpool()
{
	if(pool_cache)
		free_mmap(pool_cache ,PAGE_SIZE*current_page_num);

	if(mp_head)
		free_mmap(mp_head,sizeof(struct mpool)*current_page_num);

	if(pool_mutex)
		free_mmap(pool_mutex,sizeof(sem_t));
	
}

