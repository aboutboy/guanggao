#ifndef __MPOLL_H__
#define __MPOLL_H__

/****
	share memory pool 
	use page manage
*****/

void* new_mmap(int size);
void free_mmap(void *o ,int size);
void* new_page(int size);
void free_page(void *o);
int init_mpool(int page_num);
void fini_mpool();

#endif

