#include "main.h"

/****************************************************************
 *  
 *  Function: mSplit()
 * 
 *  Purpose: Splits a string into tokens non-destructively.
 *
 *  Parameters: 
 *      char *str => the string to be split
 *      char *sep => a string of token seperaters
 *      int max_strs => how many tokens should be returned
 *      int *toks => place to store the number of tokens found in str
 *
 *  Returns:
 *      2D char array with one token per "row" of the returned
 *      array.
 *
 ****************************************************************/
char **mSplit(char *str, char *sep, int max_strs, int *toks, char meta)
{
	char **retstr;		
	char *str_idx,*start_idx,*end_str,*sep_idx,*end_sep;	
	int sep_len,sep_num=0,len;

	if(!str||!sep)
		return NULL;
	
	if((retstr = (char **) new_page(sizeof(char *) * max_strs)) == NULL)
	{
	    debug_log("mSplit new_page error");
	    return NULL;
	}
	
	start_idx=str_idx=str;
	end_str=str_idx+strlen(str);
	sep_idx=sep;
	sep_len=strlen(sep);
	end_sep=sep_idx+sep_len;
	
	while(str_idx<end_str)
	{
		while(str_idx<end_str&&sep_idx<end_sep)
		{
			if(*str_idx != *sep_idx)
			{
				break;
			}
			sep_idx++;
			str_idx++;
		}
		
		if(sep_idx==end_sep)
		{
			if(sep_num>=max_strs-1)
			{
				break;
			}
			len=str_idx-start_idx-sep_len;
			if((retstr[sep_num] = (char *)
					new_page((sizeof(char) * len) + 1)) == NULL)
			{
				debug_log("mSplit new_page error");
	  			return NULL;
			}
			memcpy(retstr[sep_num] , start_idx , len);
			
			start_idx=str_idx;
			sep_num++;
		}
		sep_idx=sep;
		str_idx++;
		
	}

	if((retstr[sep_num] = (char *)
				new_page((sizeof(char) * (end_str-start_idx)) + 1)) == NULL)
	{
	    debug_log("mSplit new_page error");
	  			return NULL;
	}
	memcpy(retstr[sep_num] , start_idx , end_str-start_idx);

	
	*toks=sep_num+1;
	
	/* return the token list */
	return retstr;
}

	  
	  
/****************************************************************
*
* Free the buffer allocated by mSplit().
*
* char** toks = NULL;
* int num_toks = 0;
* toks = (str, " ", 2, &num_toks, 0);
* mSplitFree(&toks, num_toks);
*
* At this point, toks is again NULL.
*
****************************************************************/
void mSplitFree(char ***pbuf, int num_toks)
{
	int i;
	char** buf;  /* array of string pointers */

	if( pbuf==NULL || *pbuf==NULL )
	{
	return;
	}

	buf = *pbuf;

	for( i=0; i<num_toks; i++ )
	{
		if( buf[i] != NULL )
		{
		    free_page( buf[i] );
		    buf[i] = NULL;
		}
	}

	free_page(buf);
	*pbuf = NULL;
}




/****************************************************************
 *
 *  Function: mContainsSubstr(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex) 
 *           substring.
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      b_len => data buffer length
 *      pat => pattern to find 
 *      p_len => length of the data in the pattern buffer
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/
int mContainsSubstr(char *buf, int b_len, char *pat, int p_len)
{
   char *b_idx;    /* index ptr into the data buffer */
   char *p_idx;    /* index ptr into the pattern buffer */
   char *b_end;    /* ptr to the end of the data buffer */
   char *p_end;    /* ptr to end of the pattern buffer */
   int m_cnt = 0;  /* number of pattern matches so far... */
 

   
   /* mark the end of the strs */
   b_end = (char *) (buf + b_len);
   p_end = (char *) (pat + p_len);

   /* init the index ptrs */
   b_idx = buf;
   p_idx = pat;

   do
   { 

      if(*p_idx == *b_idx)
      {

         if(m_cnt == (p_len-1))
         {
 
            return 1;
         }

         m_cnt++;
         b_idx++;
         p_idx++;
      }
      else
      {
         if(m_cnt == 0)
         {
            b_idx++;
         }
         else
         {
            b_idx = b_idx - (m_cnt - 1);
         }
         
         p_idx = pat;

         m_cnt = 0;
      }

   } while(b_idx < b_end);
          

   /* if we make it here we didn't find what we were looking for */
   return 0;
}

char *copy_argv(char **argv)
{
  char **p;
  u_int len = 0;
  char *buf;
  char *src, *dst;
  void ftlerr(char *, ...);

  p = argv;
  if (*p == 0) return 0;

  while (*p)
    len += strlen(*p++) + 1;

  buf = (char *) new_page (len);
  if(buf == NULL)
  {
     debug_log("new_page() failed: %s\n", strerror(errno));
     return NULL;
  }
  p = argv;
  dst = buf;
  while ((src = *p++) != NULL)
    {
      while ((*dst++ = *src++) != '\0');
      dst[-1] = ' ';
    }
  dst[-1] = '\0';

  return buf;
}

int strip(char *data)
{
   int size;
   char *end;
   char *idx;

   idx = data;
   end = data + strlen(data);
   size = end - idx;

   while(idx != end)
   {
      if((*idx == '\n') ||
         (*idx == '\r'))
      {
         *idx = 0;
         size--;
      }

      if(*idx == '\t')
      {
         *idx = ' ';
      }

      idx++;
   }

   return size;
}

void ts_print(long sec, char *timebuf)
{               
   struct tm *lt;   /* place to stick the adjusted clock data */

   lt = localtime(&sec);

   (void)sprintf(timebuf, "%04d-%02d-%02d %02d:%02d:%02d",1900 + lt->tm_year, lt->tm_mon + 1, lt->tm_mday,
                lt->tm_hour, lt->tm_min, lt->tm_sec);

}
void ts_print1(long sec, char *timebuf)
{               
   struct tm *lt;   /* place to stick the adjusted clock data */

   lt = localtime(&sec);

   (void)sprintf(timebuf, "%04d%02d%02d%02d%02d%02d",1900 + lt->tm_year, lt->tm_mon + 1, lt->tm_mday,
                lt->tm_hour, lt->tm_min, lt->tm_sec);

}

void mac2str(char* dmac , unsigned char* smac)
{
	sprintf(dmac , "%02x:%02x:%02x:%02x:%02x:%02x" ,
		smac[0],smac[1],smac[2],smac[3],smac[4],smac[5]);
}


void ip2addr(char* addr , unsigned long ip)
{
	struct in_addr ina;
	ina.s_addr= htonl(ip);
	strncpy(addr, inet_ntoa(ina), 15);
}


int digital(const char* s) {
  while(*s) {
    if(!isdigit(*s++))
      return 0;
  }
  return 1;
}

int del_end_enter(char* src , int len)
{
	int i=len;
	while(i-->0)
	{
		if(src[i]=='\n')
		{
			src[i]='\0';
			break;
		}
	}
	return 1;
}

void debug_log(const char *fmt, ...)
{
	va_list va;
	char timebuf[20];
	char info[2048];
	time_t timep;
	struct tm st_tm;
	FILE * logfp = NULL;
	va_start(va, fmt);
	struct stat statbuff;
	if(stat(LOG_FILE_NAME, &statbuff) >= 0)
	{  
		if(statbuff.st_size>=MAX_DEBUG_FILE_SIZE)
		{
			 remove(LOG_FILE_NAME);
		}
	}
	logfp = fopen(LOG_FILE_NAME, "a+");
	if (!logfp) {
		perror("fopen");
		return;
	}
	

	memset(timebuf, 0, sizeof(timebuf));
	

    time(&timep);
    localtime_r(&timep, &st_tm);

    sprintf(timebuf, "%04d-%02d-%02d %02d:%02d:%02d",
                         (1900 + st_tm.tm_year),
                         (1 + st_tm.tm_mon),
                         st_tm.tm_mday,
                         st_tm.tm_hour,
                         st_tm.tm_min,
                         st_tm.tm_sec);

	memset(info, 0, sizeof(info));
	vsnprintf(info, sizeof(info), fmt, va);

	fprintf(logfp,"%s-----: %s\n", timebuf, info);
	fflush(logfp);
	fclose(logfp);
	va_end(va);
	return;
}


int get_client_mac(char* eth ,char* mac)
{
	struct ifreq ifreq;
	int sock;

	if((sock=socket(AF_INET,SOCK_STREAM,0))<0)
	{
		perror("socket");
		return -1;
	}
	if(!eth)
	{
		strcpy(ifreq.ifr_ifrn.ifrn_name,"eth0");
	}
	else
	{
		strcpy(ifreq.ifr_ifrn.ifrn_name,eth);

	}
	if(ioctl(sock,SIOCGIFHWADDR,&ifreq)<0)
	{
		perror("ioctl");
		close (sock);
		return -1;
	}

	memcpy(mac , ifreq.ifr_hwaddr.sa_data , 6);
	close (sock);
	return 0;
}

float get_pcpu()
{
	FILE* fp;
	char line[1024];
	float idle;
	int i=0;
	fp=popen("top -bn 2 |grep Cpu|sed -n '2p'|awk '{print $5}'" ,"r");
	if(!fp)
		return 0;
	if(fgets(line,sizeof(line),fp)!=NULL)
	{
		//90.23%id
		while(i<sizeof(line))
		{
			if(line[i]=='%')
			{
				line[i]='\0';
				break;
			}
			i++;
		}
		idle=atof(line);
	}
	pclose(fp);
	return (1-(idle/100))*100;
}
float get_pmem()
{
	FILE* fp;
	char line[1024];
	unsigned int used_mem , free_mem;
	
	fp=popen("cat /proc/meminfo|grep MemTotal|awk '{print $2}'" ,"r");
	if(!fp)
		return 0;
	if(fgets(line,sizeof(line),fp)!=NULL)
	{
		used_mem=atoi(line);
	}
	pclose(fp);
	fp=popen("cat /proc/meminfo|grep MemFree|awk '{print $2}'" ,"r");
	if(!fp)
		return 0;
	if(fgets(line,sizeof(line),fp)!=NULL)
	{
		free_mem=atoi(line);
	}
	pclose(fp);
	
	return ((float)used_mem)/((float)used_mem+free_mem);
	
}

float get_pdev()
{
	FILE* fp;
	char line[1024];
	float wa;
	int i=0;
	fp=popen("top -bn 2 |grep Cpu|sed -n '2p'|awk '{print $6}'" ,"r");
	if(!fp)
		return 0;
	if(fgets(line,sizeof(line),fp)!=NULL)
	{
		//11%wa
		while(i<sizeof(line))
		{
			if(line[i]=='%')
			{
				line[i]='\0';
				break;
			}
			i++;
		}
		wa=atof(line);
	}
	pclose(fp);
	return wa;
	
}

int proto2str(char proto , char* str)
{
	switch(proto)
	{
		case IPPROTO_TCP:
			strcpy(str , "TCP");
	        break;
		case IPPROTO_UDP:
	       strcpy(str , "UDP");
	        break;
		case IPPROTO_ICMP:
	        strcpy(str , "ICMP");
	        break;
		default:
		    strcpy(str , "TCP");
		    break;
	}
	return 0;
}
/**
	eth0{#}eth1{#}lo
**/
int get_all_ifdev(char* re_str ,char* split_str)
{
    int inter_fd;
    int i=0,if_len;
    struct ifconf ifc;
    struct ifreq buf[16];

    if ((inter_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        perror("socket(AF_INET, SOCK_DGRAM, 0)");
        return -1;
    }

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = (caddr_t) buf;

    if (ioctl(inter_fd, SIOCGIFCONF, (char *) &ifc) == -1)
    {
        perror("SIOCGIFCONF ioctl");
		close(inter_fd);
        return -1;
    }

    if_len = ifc.ifc_len / sizeof(struct ifreq);

    while (i<if_len)
    {   
    	if(i==0)
    	{
			sprintf(re_str ,"%s" ,buf[i].ifr_name);
		}
		else
		{
			strcat(re_str ,split_str);
			strcat(re_str ,buf[i].ifr_name);
		}
    	
		i++;
    }
	close(inter_fd);
    return 0;

}

int get_operationsys_name(char* name)
{
	FILE* fp;
	char line[1024];
	fp=popen("cat /etc/issue" ,"r");
	if(!fp)
		return -1;
	if(fgets(line,sizeof(line),fp)!=NULL)
	{
		memcpy(name , line , strlen(line));
		del_end_enter(name , strlen(line));
	}
	pclose(fp);
	return 0;
}

int get_kernel_version(char* version)
{
	FILE* fp;
	char line[1024];
	fp=popen("uname -r" ,"r");
	if(!fp)
		return -1;
	if(fgets(line,sizeof(line),fp)!=NULL)
	{
		memcpy(version , line , strlen(line));
		del_end_enter(version , strlen(line));
	}
	pclose(fp);
	return 0;
}


int get_computer_name(char* name)
{
	FILE* fp;
	char line[1024];
	fp=popen("uname -n" ,"r");
	if(!fp)
		return -1;
	if(fgets(line,sizeof(line),fp)!=NULL)
	{
		memcpy(name , line , strlen(line));
		del_end_enter(name , strlen(line));
	}
	pclose(fp);
	return 0;
}

int get_machine(char* name)
{
	FILE* fp;
	char line[1024];
	fp=popen("uname -m" ,"r");
	if(!fp)
		return -1;
	if(fgets(line,sizeof(line),fp)!=NULL)
	{
		memcpy(name , line , strlen(line));
		del_end_enter(name , strlen(line));
	}
	pclose(fp);
	return 0;
}

int get_total_mem(char* mem)
{
	FILE* fp;
	char line[1024];
	fp=popen("free |grep Mem|awk '{print $2}'" ,"r");
	if(!fp)
		return -1;
	if(fgets(line,sizeof(line),fp)!=NULL)
	{
		memcpy(mem , line , strlen(line));
		del_end_enter(mem , strlen(line));
	}
	pclose(fp);
	return 0;
}

long long htonll(long long s) {  
	union { int lv[2]; long long llv; } u;	
	if (__BYTE_ORDER == __BIG_ENDIAN)
		return s;
	u.lv[0] = htonl(s >> 32);  
	u.lv[1] = htonl(s & 0xFFFFFFFFULL);  
	return u.llv;  
}  
  
long long ntohll(long long s) {  
	union { int lv[2]; long long llv; } u;
	if (__BYTE_ORDER == __BIG_ENDIAN)
		return s;
	u.llv = s;	
	return ((long long)ntohl(u.lv[0]) << 32) | (long long)ntohl(u.lv[1]);  
}  

int how_many_digits(long s)
{
	int i = 0;
	long tmp=s;
	while(tmp!=0)
	{
		tmp /= 10;
		i++;
	}
	return i;

}

int mnanosleep(long nasec)
{
	struct timespec tspec;
	if(nasec<=0||nasec>=pow(10 , 9))
	{
		sleep(1);
		return -1;
	}
	tspec.tv_sec=0;
	tspec.tv_nsec=nasec;
	
	return nanosleep(&tspec , NULL);
}
//20140820110024--2014-08-20 11:00:24
void data_time_format(char* dtime , char* stime)
{
	char year[5]={0};
	char month[3]={0};
	char day[3]={0};
	char hour[3]={0};
	char min[3]={0};
	char sec[3]={0};
	
	sscanf(stime, "%4s%2s%2s%2s%2s%2s", 
		year, month, day,hour,min,sec); 

	sprintf(dtime,"%4s-%2s-%2s %2s:%2s:%2s", year, month, day,hour,min,sec);
	
}

long get_current_sec()
{
	struct  timeval    tv;
	gettimeofday(&tv,NULL);
	return tv.tv_sec;
}

