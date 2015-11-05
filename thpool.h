#ifndef __THPOLL_H__
#define __THPOLL_H__

int thread_lock();
int thread_unlock();
int thpool_add_job(void (*fun)(void*) , void* arg);
int init_thpool(int job_num);
void fini_thpool();

#endif

