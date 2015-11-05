#include "main.h"

struct list_head tcpc_list;
struct ipq_msg ipqm;

unsigned short in_cksum(unsigned short *addr, int len)    /* function is from ping.c */
{
    register int nleft = len;
    register u_short *w = addr;
    register int sum = 0;
    u_short answer =0;
 
    while (nleft > 1)
        {
        sum += *w++;
        nleft -= 2;
        }
    if (nleft == 1)
        {      
        *(u_char *)(&answer) = *(u_char *)w;
        sum += answer;
        }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return(answer);
}

unsigned short tcp_chsum(struct iphdr *iph , struct tcphdr *tcp ,int tcp_len)
{
	char check_buf[BUFSIZE]={0};
	unsigned short check;
	
    struct pseudo_header
    {
        unsigned int source_address;
        unsigned int dest_address;
        unsigned char placeholder;
        unsigned char protocol;
        unsigned short tcp_length;
    } pseudo;
	
	tcp->check=0;

    // set the pseudo header fields 
    pseudo.source_address = iph->saddr;
    pseudo.dest_address = iph->daddr;
    pseudo.placeholder = 0;
    pseudo.protocol = IPPROTO_TCP;
    pseudo.tcp_length = htons(tcp_len);
	memcpy(check_buf,&pseudo,sizeof(struct pseudo_header));
	memcpy(check_buf+sizeof(struct pseudo_header),tcp,tcp_len);
    check = in_cksum((unsigned short *)&check_buf, sizeof(struct pseudo_header)+tcp_len);
	
	return check;
	
}

int insert_guanggao(struct http_conntrack *httpc)
{
	char* src;
	char* body;

	if(!httpc->http_data)
		goto send;
	body=strstr(httpc->http_data , "<center>");
	if(!body)
		goto send;
	body=body+8;
	memcpy(body , "hello" ,5);
	debug_log(body);
	
	httpc->tcp->check=tcp_chsum(httpc->iph , httpc->tcp , httpc->tcp_len);
	send:
	ipq_set_verdict(ipqm.h, httpc->m->packet_id,
			 NF_ACCEPT, httpc->m->data_len, httpc->m->payload);
	return 0;
}

void http_stream(void* arg)
{
	struct tcp_conntrack *tcp_cursor , *tcp_tmp;
	struct http_conntrack *http_cursor , *http_tmp;
		
	while(1)
	{	
		if(ipqm.current_http_num==0 || ipqm.current_tuple_num==0)
		{
			sleep(2);
			continue;
		}
	
		list_for_each_entry_safe(tcp_cursor, tcp_tmp, &tcpc_list, list)
		{
			list_for_each_entry_safe(http_cursor, http_tmp, &(tcp_cursor->http_conntrack_list), list)
			{
				insert_guanggao(http_cursor);
				thread_lock();
				la_list_del(&http_cursor->list);
				free_page(http_cursor);
				http_cursor=NULL;
				ipqm.current_http_num--;
				thread_unlock();
				
			}
			/*thread_lock();
			la_list_del(&tcp_cursor->list);
			free_page(tcp_cursor);
			tcp_cursor=NULL;
			ipqm.current_tuple_num--;
			thread_unlock();*/
		}
	}
}

struct tcp_conntrack* find_by_tuple(struct tcp_conntrack *tcpc)
{
	struct tcp_conntrack *cursor , *tmp;
	list_for_each_entry_safe(cursor, tmp, &tcpc_list, list)
	{
		if((cursor->sip==tcpc->sip && cursor->dip==tcpc->dip && 
			cursor->sp==tcpc->sp && cursor->dp==tcpc->dp)||
			(cursor->sip==tcpc->dip && cursor->dip==tcpc->sip &&
			cursor->sp==tcpc->dp && cursor->dp==tcpc->sp))
		{
			return cursor;
		}
	}	
	return NULL;
}

int decode_http(struct tcp_conntrack *tcpc ,
	struct http_conntrack *httpc)
{
	char **toks = NULL;
	int num_toks=0,tmp_num_toks=0;
	int i = 0;
	char **opts;
	int num_opts=0;
	char req_post[][16]={"5" ,"POST " };
	char req_get[][16]={"4" ,"GET " };
	char res[][16]={"7" ,"HTTP/1."};
	char http_head_end[][16]={"4" ,"\r\n\r\n"};
	
	httpc->http_len=httpc->ip_len-httpc->iph_len-httpc->tcph_len;
	if(httpc->http_len<=0)
		return -1;
	
	httpc->http_head=(char*)(httpc->m->payload +httpc->iph_len+httpc->tcph_len);
	if(!httpc->http_head)
		return -1;

	//debug_log("~~~~~~~~~~~~~~~~~~~~\n%s\n" , httpc->http_heard);
	//////////////http_head_end///////////
	httpc->http_data=strstr(httpc->http_head, http_head_end[1]);
	if(!httpc->http_data)
	{
		return -1;
	}
	
	httpc->httph_len=strlen(httpc->http_head)-strlen(httpc->http_data);
	//////////////http_head_start///////////
	if(!memcmp(httpc->http_head,req_post[1],atoi(req_post[0])))
	{
		httpc->hhdr.http_type=HTTP_TYPE_REQUEST_POST;
	}
	else if(!memcmp(httpc->http_head,req_get[1],atoi(req_get[0])))
	{
		httpc->hhdr.http_type=HTTP_TYPE_REQUEST_GET;
	}
	else if(!memcmp(httpc->http_head,res[1],atoi(res[0])))
	{
			
		httpc->hhdr.http_type=HTTP_TYPE_RESPONSE;
	}
	else 
	{
		httpc->hhdr.http_type=HTTP_TYPE_OTHER;
		return -1;
	}
	
	toks = mSplit(httpc->http_head, "\r\n", MAX_PATTERN_NUM, &num_toks,'\\');

	tmp_num_toks=num_toks;
	num_toks--;
	while(num_toks)
	{ 
		if(i==0)
		{
			opts = mSplit(toks[i], " ", 2, &num_opts,'\\');
			while(isspace((int)*opts[0])) opts[0]++;
			if(httpc->hhdr.http_type==HTTP_TYPE_RESPONSE)
			{
				strncpy(httpc->hhdr.error_code, opts[1] ,COMM_MAX_LEN);
			}
			else if(httpc->hhdr.http_type==HTTP_TYPE_REQUEST_GET||
				httpc->hhdr.http_type==HTTP_TYPE_REQUEST_POST)
			{
				strncpy(httpc->hhdr.uri , opts[1] , COMM_MAX_LEN);
			}
		}
		else
		{
			opts = mSplit(toks[i], ": ", 2, &num_opts,'\\');
			while(isspace((int)*opts[0])) opts[0]++;
			if(!strcasecmp(opts[0], "host"))
			{
				strncpy(httpc->hhdr.host , opts[1] ,COMM_MAX_LEN);
			}
			else if(!strcasecmp(opts[0], "accept-encoding"))
			{
				strncpy(httpc->hhdr.accept_encoding , opts[1],COMM_MAX_LEN);
			}
			else if(!strcasecmp(opts[0], "accept"))
			{
				strncpy(httpc->hhdr.accept , opts[1],COMM_MAX_LEN);
			}
			else if(!strcasecmp(opts[0], "accept-charset"))
			{
				strncpy(httpc->hhdr.accept_charset , opts[1],COMM_MAX_LEN);
			}
			else if(!strcasecmp(opts[0], "accept-language"))
			{
				strncpy(httpc->hhdr.accept_language , opts[1],COMM_MAX_LEN);
			}
			else if(!strcasecmp(opts[0], "authorization"))
			{
				strncpy(httpc->hhdr.authorization , opts[1],COMM_MAX_LEN);
			}
			else if(!strcasecmp(opts[0], "cache-control"))
			{
				strncpy(httpc->hhdr.cache_control , opts[1],COMM_MAX_LEN);
			}
			else if(!strcasecmp(opts[0], "connection"))
			{
				strncpy(httpc->hhdr.connection , opts[1],COMM_MAX_LEN);
			}
			else if(!strcasecmp(opts[0], "content-encoding"))
			{
				strncpy(httpc->hhdr.content_encoding , opts[1],COMM_MAX_LEN);
			}
			else if(!strcasecmp(opts[0], "content-language"))
			{
				strncpy(httpc->hhdr.content_language , opts[1],COMM_MAX_LEN);
			}
			else if(!strcasecmp(opts[0], "content-length"))
			{
				strncpy(httpc->hhdr.content_length , opts[1],COMM_MAX_LEN);
			}
			else if(!strcasecmp(opts[0], "content-type"))
			{
				strncpy(httpc->hhdr.content_type , opts[1],COMM_MAX_LEN);
			}
			else if(!strcasecmp(opts[0], "content-range"))
			{
				strncpy(httpc->hhdr.content_range , opts[1],COMM_MAX_LEN);
			}
			else if(!strcasecmp(opts[0], "connection"))
			{
				strncpy(httpc->hhdr.connection , opts[1],COMM_MAX_LEN);
			}
			else if(!strcasecmp(opts[0], "user-agent"))
			{
				strncpy(httpc->hhdr.user_agent , opts[1],COMM_MAX_LEN);
			}
			else if(!strcasecmp(opts[0], "transfer-encoding"))
			{
				strncpy(httpc->hhdr.transfer_encoding , opts[1],COMM_MAX_LEN);
			}
		}
		mSplitFree(&opts ,num_opts);
		--num_toks;
		i++;
	}
	mSplitFree(&toks ,tmp_num_toks);
	
	return 0;
}

int decode_tcp(struct tcp_conntrack *tcpc ,
	struct http_conntrack *httpc)
{
	httpc->tcp = (struct tcphdr *)(httpc->m->payload +httpc->iph_len);
	if(!httpc->tcp)
		return -1;
	httpc->tcph_len = 4 * httpc->tcp->doff;
	httpc->tcp_len = httpc->ip_len-httpc->iph_len;
	httpc->seq=ntohl(httpc->tcp->seq);
	httpc->ack_seq=ntohl(httpc->tcp->ack_seq);
	
	tcpc->sp=ntohs(httpc->tcp->source);
	tcpc->dp=ntohs(httpc->tcp->dest);
	
	if(-1==decode_http(tcpc ,httpc))
		return -1;

	return 0;

}

int decode_ip(struct tcp_conntrack *tcpc ,
	struct http_conntrack *httpc)
{
	
	httpc->m = ipq_get_packet(httpc->buf);
	httpc->iph = (struct iphdr *)(httpc->m->payload);
	if(!httpc->iph)
		return -1;
	if(httpc->iph->ihl < 5 || httpc->iph->version != 4)
		return -1;
	httpc->ip_len = ntohs(httpc->iph->tot_len);
	if(httpc->ip_len != httpc->m->data_len)
		return -1;
	httpc->iph_len=4 * httpc->iph->ihl;
	if (httpc->ip_len < httpc->iph_len)
		return -1;
	tcpc->sip=ntohl(httpc->iph->saddr);
	tcpc->dip=ntohl(httpc->iph->daddr);
	
	
	if(httpc->iph->protocol!=IPPROTO_TCP)
		return -1;
	
	if(-1==decode_tcp(tcpc ,httpc))
		return -1;
	
	
	return 0;
}

void decode(void* arg)
{
	
	struct tcp_conntrack *tcpc,*tcpc_tmp;
	struct http_conntrack *httpc;
	char buffer[BUFSIZE];
	char sip[20],dip[20];
	while(1)
	{
		memset(&buffer , '\0' , sizeof(buffer));
		get_queue(buffer);
		tcpc=(struct tcp_conntrack*)new_page(sizeof(struct  tcp_conntrack));
		if(!tcpc)
			continue;
		httpc=(struct http_conntrack*)new_page(sizeof(struct  http_conntrack));
		if(!httpc)
			continue;
		
		memset(tcpc , '\0' ,sizeof(struct  tcp_conntrack));
		memset(httpc , '\0' ,sizeof(struct  http_conntrack));
		
		memcpy(httpc->buf , buffer , BUFSIZE);
		decode_ip(tcpc ,httpc);
		/*ip2addr(sip , tcpc->sip);
		ip2addr(dip , tcpc->dip);
		debug_log("%s:%d-->%s:%d seq:%lu , ack_seq:%lu , ip_len:%d,tcp_len:%d,http_len:%d,httph_len:%d,http_data_len:%d\n\
			http_type:%d \n uri:%s\ncontent_length:%s\nhost:%s\ncontent_encoding:%s \ntransfer_encoding:%s\n" , 
			sip,tcpc->sp ,dip,tcpc->dp,
			httpc->seq , httpc->ack_seq , httpc->ip_len,httpc->tcp_len ,
			httpc->http_len , httpc->httph_len ,httpc->http_len-httpc->httph_len,
			httpc->hhdr.http_type ,httpc->hhdr.uri , httpc->hhdr.content_length , 
			httpc->hhdr.host ,httpc->hhdr.content_encoding , httpc->hhdr.transfer_encoding);
		*/
		tcpc_tmp=find_by_tuple(tcpc);
		if(tcpc_tmp)
		{
			free_page(tcpc);
			tcpc=NULL;
			thread_lock();
			la_list_add_tail(&(httpc->list), &(tcpc_tmp->http_conntrack_list));
			ipqm.current_http_num++;
			thread_unlock();
		}
		else
		{
			thread_lock();
			la_list_add_tail(&(tcpc->list), &tcpc_list);
			INIT_LIST_HEAD(&(tcpc->http_conntrack_list));
			la_list_add_tail(&(httpc->list), &(tcpc->http_conntrack_list));
			ipqm.current_tuple_num++;
			ipqm.current_http_num++;
			thread_unlock();
		}
	}

}

static void die(struct ipq_handle *h) 
{
    ipq_perror("passer");
    ipq_destroy_handle(h);
    exit(1);
}

int main(int argc, char **argv) 
{
	init_mpool(1*1024*1024);//256M
	
	INIT_LIST_HEAD(&tcpc_list);
	init_queue();
	init_thpool(3);
	thpool_add_job(decode , NULL);
	thpool_add_job(http_stream , NULL);

	memset(&ipqm , '\0' , sizeof(struct ipq_msg));
	
    ipqm.h = ipq_create_handle(0, NFPROTO_IPV4);
    if (!ipqm.h)
        die(ipqm.h);
    ipqm.status = ipq_set_mode(ipqm.h, IPQ_COPY_PACKET, BUFSIZE);
    if (ipqm.status < 0)
        die(ipqm.h);
    do{
        ipqm.status = ipq_read(ipqm.h, ipqm.buf, BUFSIZE, 0);
        if (ipqm.status < 0)//Failed to receive netlink message: No buffer space available
            continue;
		
        switch (ipq_message_type(ipqm.buf)) {
            case NLMSG_ERROR:
                debug_log("Received error message %d\n",
                        ipq_get_msgerr(ipqm.buf));
                break;
            case IPQM_PACKET: {
				set_queue(ipqm.buf , sizeof(ipqm.buf));              
                if (ipqm.status < 0)
                    continue;
                break;
            }
            default:
                debug_log("Unknown message type!\n");
                break;
        }
    } while (1);
    ipq_destroy_handle(ipqm.h);
	fini_thpool();
    return 0;
}
