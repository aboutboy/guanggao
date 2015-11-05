#ifndef __PLUG_H__
#define __PLUG_H__

enum 
{
	CHECK_PLUG_PRE,
	CHECK_PLUG_POST
};

void new_check_plug(int (*check_hook)(void *) , int type);
int check_plug_hook(void *data , int type);
int init_plug();
void fini_plug();

#endif 
