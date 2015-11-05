
#include "main.h"

struct plug_info
{
	struct list_head list;
	int (*plug)(void*);
};

PRIVATE struct list_head* check_pre_list;
PRIVATE struct list_head* check_post_list;

PRIVATE void new_check_pre(int (*check_hook)(void *))
{

	struct plug_info* new;

	new=(struct plug_info*)new_page(sizeof(struct plug_info));
	if(!new)
		return;
	
	
	new->plug=check_hook;
	la_list_add_tail(&(new->list), check_pre_list);
	
}

PRIVATE void new_check_post(int (*check_hook)(void *))
{

	struct plug_info* new;

	new=(struct plug_info*)new_page(sizeof(struct plug_info));
	if(!new)
		return;
	
	
	new->plug=check_hook;
	la_list_add_tail(&(new->list), check_post_list);
	
}


PRIVATE int check_pre_hook(void *data)
{
	struct plug_info *pi,*tmp;
	
	list_for_each_entry_safe(pi, tmp, check_pre_list, list) 
	{
		if(ERROR==pi->plug(data))
		{
			return ERROR;
		}
	}
	return OK;
}

PRIVATE int check_post_hook(void *data)
{
	struct plug_info *pi,*tmp;
	list_for_each_entry_safe(pi, tmp, check_post_list, list) 
	{
		if(ERROR==pi->plug(data))
		{
			return ERROR;
		}
	}
	return OK;
}

void new_check_plug(int (*check_hook)(void *) , int type)
{
	switch(type)
	{
		case CHECK_PLUG_PRE:
			new_check_pre(check_hook);
			break;
		case CHECK_PLUG_POST:
			new_check_post(check_hook);
			break;
		default:
			break;
	}
}

int check_plug_hook(void *data , int type)
{
	switch(type)
	{
		case CHECK_PLUG_PRE:
			return check_pre_hook(data);
		case CHECK_PLUG_POST:
			return check_post_hook(data);
		default:
			break;
	}
	return OK;
}


int init_plug()
{

	check_pre_list=(struct list_head*)new_page(sizeof(struct list_head));
	if(!check_pre_list)
		return -1;
	
	INIT_LIST_HEAD(check_pre_list);

	check_post_list=(struct list_head*)new_page(sizeof(struct list_head));
	if(!check_post_list)
		return -1;
	
	INIT_LIST_HEAD(check_post_list);

	return 0;
}

void fini_plug()
{

}

