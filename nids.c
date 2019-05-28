#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include "nids.h"

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))
#define MaxL 256
#define NON_NUM '0'
// struct tuple4 contains addresses and port numbers of the TCP connections
// the following auxiliary function produces a string looking like
// 10.0.0.1,1024,10.0.0.2,23
int hex2num(char c)
{
    if (c>='0' && c<='9') return c - '0';
    if (c>='a' && c<='z') return c - 'a' + 10;//这里+10的原因是:比如16进制的a值为10
    if (c>='A' && c<='Z') return c - 'A' + 10;
    
    printf("unexpected char: %c", c);
    return NON_NUM;
}

struct packetinfo
{
	// Add more info here
	char s_source[MaxL];	// Source IP
	char s_des[MaxL];		// Dest IP
	char s_sport[MaxL];		// Source port
	char s_dport[MaxL];		// Dest port 
	char s_len[MaxL];		// Packet length
}packet;
// Filter for usrname & pwd & ip
char f_usr[][MaxL] = {"username=", "&"};
char f_pwd[][MaxL] = {"password=", "&"};
char f_ip[]              = "192.168.136.128";
char f_sub[MaxL]="subject";
char f_text[MaxL]="&text=";
char *adres (struct tuple4 addr)
{
  static char buf[256];
  strcpy (buf, int_ntoa (addr.saddr));
  sprintf (buf + strlen (buf), ",%i,", addr.source);
  strcat (buf, int_ntoa (addr.daddr));
  sprintf (buf + strlen (buf), ",%i", addr.dest);
  return buf;
}

int URLDecode(const char* str, const int strSize, char* result, const int resultSize)
{
    char ch,ch1,ch2;
    int i;
    int j = 0;//record result index
 
    if ((str==NULL) || (result==NULL) || (strSize<=0) || (resultSize<=0)) {
        return 0;
    }
 
    for ( i=0; (i<strSize) && (j<resultSize); ++i) {
        ch = str[i];
        switch (ch) {
            case '+':
                result[j++] = ' ';
                break;
            case '%':
                if (i+2<strSize) {
                    ch1 = hex2num(str[i+1]);//高4位
                    ch2 = hex2num(str[i+2]);//低4位
                    if ((ch1!=NON_NUM) && (ch2!=NON_NUM))
                        result[j++] = (char)((ch1<<4) | ch2);
                    i += 2;
                    break;
                } else {
                    break;
                }
            default:
                result[j++] = ch;
                break;
        }
    }
    
    result[j] = 0;
    return j;
}

void http_date_parse(char content[])
{
	if(strstr(content, f_pwd[0])||strstr(content, f_sub)||strstr(content, f_text))
	{
		const char s[2] = "&";
		char *token;
		char obj[3000] = {0};
		printf("==== Packet Info ====\n");	
		printf("source  : %s:%s\n", packet.s_source, packet.s_sport);
		printf("dest    : %s:%s\n", packet.s_des, packet.s_dport);
		printf("length  : %s\n",    packet.s_len);

		unsigned int len = strlen(content);
		int resultSize = URLDecode(content, len, obj, 3000);
		printf("捕获长度%d\n",resultSize);
		token = strtok(obj, s);
		/* 继续获取其他的子字符串 */
		while( token != NULL ) 
		{
			printf( "%s\n", token );
			token = strtok(NULL, s);
		}
		printf("\n\n");
		printf("Capture successfully!\n");
	}
}
void http_callback(struct tcp_stream *a_tcp, void** this_time_not_needed)
{
	static int num;
	char content[65535];
	struct tuple4 ip_and_port = a_tcp->addr;
	if (a_tcp->nids_state == NIDS_JUST_EST)
	{
		// HTTP port
		if (ip_and_port.dest != 80)
		{
			return ;
		}
		a_tcp->client.collect++;
		a_tcp->server.collect++;
	}
	else if (a_tcp->nids_state == NIDS_DATA)
	{
		struct half_stream *hlf;
		if (a_tcp->server.count_new)
		{
			hlf = &a_tcp->server;
		}
		else if (a_tcp->client.count_new)
		{
			hlf = &a_tcp->client;
		}		
		sprintf(packet.s_source, "%s",inet_ntoa(*((struct in_addr *)&(ip_and_port.saddr))));
		sprintf(packet.s_des, "%s",   inet_ntoa(*((struct in_addr *)&(ip_and_port.daddr))));
		sprintf(packet.s_sport, "%i", ip_and_port.source);
		sprintf(packet.s_dport, "%i", ip_and_port.dest);
		sprintf(packet.s_len, "%d",   hlf->count_new);
			// filter ip
		if(!strcmp(packet.s_source, f_ip))
		{		
			memcpy(content, hlf->data, hlf->count_new);
			content[hlf->count_new] = '\0';
			http_date_parse(content);
		}
	}
return;
}
int main()
{
	// here we can alter libnids params, for instance:
	// nids_params.n_hosts=256;

	if (!nids_init ())
	{
		//fprintf(stderr,"%s\n",nids_errbuf);
		printf("Error!\nDetail: %s\n", nids_errbuf);
	}
	else
	{
		printf("Start!\n");
		nids_register_tcp(http_callback);
		nids_run ();
	}
	return 0;
}