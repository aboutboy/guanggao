#include "thpool.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <semaphore.h>
#include <pthread.h>

struct th_pool_job
{
	pthread_t threads;
	void (*fun)(void*);
	void* arg;
	sem_t mutex;
};

#define MAX_THREAD_NUM 2048
static struct th_pool_job gth_job[MAX_THREAD_NUM];
static int gth_job_num;

static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;

int thread_lock()
{
	return pthread_mutex_lock(&mutex);
}

int thread_unlock()
{
	return pthread_mutex_unlock(&mutex);
}

static void* thpool_thread_do(struct th_pool_job* th_job)
{
	while(1)
	{	
		//printf("thread %lu is working" ,pthread_self());
		if(th_job->fun)
			th_job->fun(th_job->arg);
		sem_wait(&th_job->mutex);
	}
	return NULL;
}

int thpool_add_job(void (*fun)(void*) , void* arg)
{
	int i;
	int reval;  
 
	for(i = 0;i< gth_job_num ;i++)  
    {	
    	sem_getvalue(&gth_job[i].mutex,&reval); 
		
    	if(!reval)
		{
			gth_job[i].fun=fun;
			gth_job[i].arg=arg;
			sem_post(&gth_job[i].mutex);
			return 0;
		}
    }
	return -1;
}

int init_thpool(int job_num)
{
	int i;
	
	if(job_num>MAX_THREAD_NUM)
		job_num=MAX_THREAD_NUM;
	
	for(i = 0;i< job_num ;i++)  
    {  
    	memset(&gth_job[i] , '\0' , sizeof(struct th_pool_job));
    	sem_init(&(gth_job[i].mutex),0,0);
        if(0!=pthread_create(&(gth_job[i].threads),NULL,(void *)thpool_thread_do,&gth_job[i]))
        {
        	printf("thpool pthread_create failed %d %s" ,errno ,strerror(errno));
			break;
		}
		
	}  
	gth_job_num=i;
	return 0;
}
void fini_thpool()
{
	int i;
	
	for(i = 0;i< gth_job_num ;i++)  
	{  
		pthread_join(gth_job[i].threads,NULL);  
	} 

}

