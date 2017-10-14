/**
SCE(Suspicious Check Engine)
*@Description: check whether the ip address/domain/url of the packet is suspicious and include some heuristics methods
*@Author: Chad
*@Date: 6 JUN 2017
*@Changelog:
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <error.h>
#include <unistd.h>
#include <time.h>
#include <dirent.h>
#include <syslog.h>
#include <stdarg.h>
    
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <poll.h>
#include <netdb.h>
#include <regex.h>
#include <math.h>

#include "suspicious_ip_domain_url_alert.h"
#include "port_flow_statistics.h"
#include "dbapi.h"
#include "common.h"

/*some statistics info for ip,domain,url,etc*/
static uint32_t black_ip_cnt; /*total count of black ip*/
static uint32_t black_domain_cnt; 
static uint32_t black_url_cnt;
static uint32_t white_ip_cnt; /*total count of white ip*/
static uint32_t white_domain_cnt; 
static uint32_t white_url_cnt;
static uint32_t webshell_cnt; /*total count of webshell(suspicious)*/
static uint32_t ua_cnt;/*total count of user agent(suspicious)*/
static uint32_t user_agents_len; /*the length of user agent regex*/
static uint32_t user_white_domain_cnt; /*the count of user defined domain,we use it as white*/
static uint32_t user_white_ip_cnt; /*the count of ip resovled by user defined domain,we use it as white too*/

static uint16_t max_black_url_len; /*maxmum length of black url*/
static uint16_t max_black_domain_len;
static uint32_t max_user_white_domain_len;
static uint16_t min_black_url_len = 1024; /*minimum length of black url*/
static uint16_t min_black_domain_len= 1024;

static uint32_t total_line_in_file;
static uint32_t total_line_in_list;
static int is_white;

/*array list to hold black and white domain,url,ip,etc*/
static match_str_list black_domain_array[MAX_DOMAIN_SIZE]; /*list array to save black domain*/
static match_str_list black_url_array[MAX_URL_SIZE]; /*list array to save black url*/
static match_str_list web_shell_array[MAX_WEBSHELL_SIZE]; /*list array to save webshell*/
static match_str_list white_domain_array[MAX_WHITE_DOMAIN_SIZE]; /*list array to save maltrail white domain*/
static match_str_list white_url_array[MAX_WHITE_URL_SIZE]; /*list array to save maltrail white url*/
static match_str_list user_white_domain_array[MAX_WHITE_DOMAIN_SIZE]; /*list array to save user white domain*/

static match_ip_list white_ip_list; /*list array to save maltrail whtie ip*/
static match_ip_list black_ip_array[MAX_IP_SIZE]; /*list array to save black ip*/
static match_ip_list user_white_ip_array[MAX_IP_SIZE]; /*list array to save user white ip*/

static match_str_list user_agents;
static char *puser_agent_regex;
static char response_matched_suspicious_str[256];

#define HTTP_ANOMALY_DETECTION 3
#define STATIC_MATCH_ALGORITHM 4
#define HEURISTICS_ALGORITHM 5
#define FREQUENCY_ANALYSIS_ALGORITHM 6

#define END_CHECK_OR_NOT(check_result,return_val) do{\
    if(check_result == 1)\
        return return_val;\
}while(0);
#define END_CHECK_RETURN(ret) do{\
        return ret;\
}while(0);

#define END_CHECK {return 1;}
#define SUSPICIOUS_FLOW_TABLE "suspicious_flow"
#define IP_WHITELIST_TABLE "ip_whitelist"

#ifndef USE_PLAIN_FILE
extern int _binary_maltrails_csv_start;
extern int _binary_maltrails_csv_end;
extern int _binary_web_shells_txt_start;
extern int _binary_web_shells_txt_end;
extern int _binary_ua_txt_start;
extern int _binary_ua_txt_end;
extern int _binary_whitelist_txt_start;
extern int _binary_whitelist_txt_end;
extern int _binary_user_white_domain_txt_start;
extern int _binary_user_white_domain_txt_end;
#endif
static int checkDomainListed(const char *domain,int domain_type);
static int suspicousUserAgentRegexCheck(char *ua);
static inline char* str2Lower(char *str);
static inline char* str2Upper(char *str);
static int gotStrMatch(const char *str,char **match);

struct alerts_keys {
    uint32_t property_ip;
    uint32_t remote_ip;
    u_short remote_port;
    short suspicious_type;
    char info[1024];
};
typedef struct _alerts_info{
	    struct alerts_keys key;
        time_t time;
	    UT_hash_handle hh;
}alerts_info;
alerts_info *alerts_list;

static int alertsGroup(uint32_t pip,uint32_t rip,u_short rport,int type,char *info)
{
	static int list_size = 0;
    struct alerts_keys key;
    memset(&key,0,sizeof(key));
    key.property_ip = pip;
    key.remote_ip = rip;
    key.remote_port = rport;
    key.suspicious_type = type;
    strncpy(key.info,info,sizeof(key.info)-1);
    alerts_info *node = NULL;
    int found = 1;
    time_t now = time(NULL);
	HASH_FIND(hh, alerts_list, &key, sizeof(key), node);
	if (NULL == node)
	{
	    found = 0;
		node = (alerts_info*)calloc(1,sizeof(alerts_info));
        if(node == NULL)
            return found;
		node->key = key;
        node->time = now;
        
        if(list_size > 1000){
            /*delete timeout record*/
            alerts_info *del_node = NULL;
            alerts_info *tmp_node = NULL;
        	HASH_ITER(hh, alerts_list,del_node,tmp_node) {
                if(now - del_node->time > 60){/*1 minute*/
            		HASH_DEL(alerts_list, del_node);
            		free(del_node);
                    list_size--;
                }
            }
        }
		HASH_ADD(hh, alerts_list, key, sizeof(key), node);
        list_size++;
	}
    else if(now - node->time > 60){/*this record is timeout*/
        found = 0;
        node->time = now;
    }
    return found;
}
static int whiteExtensionFilter(char *path)
{
    static char *white_extension[] = {
        "jpg",
        "png",
        "gif",
        "jpeg",
        "bmp",
        "js",
        "css",
        NULL
    };
    
    int match = 0;
    char *question_mark = strchr(path,'?');
    if(question_mark != NULL)
        *question_mark = 0;
    
    char *last_slash = strrchr(path,'/');
    
    if(question_mark != NULL)
        *question_mark = '?';
    
    if(last_slash){
        char *p = strrchr(last_slash+1,'.');
        if(p){
            match = gotStrMatch(p+1,white_extension);
        }
    }
    return match;
}

/**
*@Description: log suspicious flow to database.
*@Paras: pkt
                pointer to packet(msg_t)
              event_type
                event type
              suspicious_content
                pointer to suspicious flow content
*@Return: int
                0 on success and others means failure
*@Author: Chad
*/
static int logSuspiciousFlowEvent(msg_t *pkt,int event_type,char *event_detail,char *event_data,char *suspicious_content,int algorithm)
{
    LogMessage(LOG_DEBUG,"%s\n",__FUNCTION__);
    if(!pkt || !event_detail || !event_data || !suspicious_content)
        return -1;
    
    static MYSQL *pConn = NULL;
    uint32_t suspicious_host_ip = 0;
    uint32_t dst_ip = 0;
    u_short host_port = 0;
    u_short dst_port = 0;
    if(pkt->src_is_protected){
        suspicious_host_ip= ntohl(pkt->src_ip);
        host_port = ntohs(pkt->src_port);
        dst_ip = ntohl(pkt->dst_ip);
        dst_port = ntohs(pkt->dst_port);
    }
    else if(pkt->dst_is_protected){
        suspicious_host_ip = ntohl(pkt->dst_ip);
        host_port = ntohs(pkt->dst_port);
        dst_ip = ntohl(pkt->src_ip);
        dst_port = ntohs(pkt->src_port);
    }
    else{
        /*external suspicious flow?*/
        LogMessage(LOG_NOTICE,"%s:external suspicious flow,ignore\n",__FUNCTION__);
        return 1;
    }
    
    if(whiteExtensionFilter(event_data))
        return 1;
    
    size_t content_len = strlen(suspicious_content)+strlen(event_data)+strlen(event_detail);
    int sql_len = content_len + 512;
    char *sql = calloc(1,sql_len);
    if(sql == NULL){
        LogMessage(LOG_ERR,"%s:failed to alloc memeory:%s\n",__FUNCTION__,strerror(errno));
        return -1;
    }
    char *event_type_str;
    char proto[16] = {0};
    switch(pkt->protocol){
        case PROTO_TCP:
            strcpy(proto,"tcp");
            break;
        case PROTO_UDP:
            strcpy(proto,"udp");
            break;
        case PROTO_ICMP:
            strcpy(proto,"icmp");
            break;
        default:
            strcpy(proto,"ip");
            break;
    }
    switch(event_type){
        case SUSPICIOUS_IP_EVENT_NUM:
            event_type_str = IP_EVENT_STR;
            break;
        case SUSPICIOUS_DOMAIN_EVENT_NUM:
            event_type_str = DOMAIN_EVENT_STR;
            strcpy(proto,"dns");
            break;
        case SUSPICIOUS_URL_EVENT_NUM:
            event_type_str = URL_EVENT_STR;
            strcpy(proto,"http");
            break;
        default:
            event_type_str = UNKNOWN_EVENT_STR;
            break;
    }
    /*TODO:handle ' in event_data and suspicious_content*/
    snprintf(sql,sql_len,"insert into %s(property_ip,property_port,dst_ip,dst_port,protocol,\
    event_type,event_type_str,event_detail,event_data,suspicious_content,timestamp,date_num,month) \
        values(%u,%u,%u,%u,'%s',\
        %d,'%s','%s','%s','%s',now(),date_format(now(),'%%Y%%m%%d'),date_format(now(),'%%Y%%m'))",
        SUSPICIOUS_FLOW_TABLE,suspicious_host_ip,host_port,dst_ip,dst_port,proto,
        event_type,event_type_str,event_detail,event_data,suspicious_content);
    
    if(pConn == NULL){
        pConn = CreateDBConn();
        if(pConn == NULL){
            LogMessage(LOG_ERR,"%s:failed to create db connection,return\n",__FUNCTION__);
            return -1;
        }
    }
	else if (!IsDBConnActive(pConn))
	{
		CloseDBConn(pConn);
		pConn = CreateDBConn();
	}
    
    if(pConn == NULL){
        LogMessage(LOG_ERR,"%s:failed to create db connection,return\n",__FUNCTION__);
        return -1;
    }
    int ret = ExecuteSql(pConn,sql);
    free(sql);
    return ret;
}

static int excuteSqlOnce(char *sql)
{
    if(!sql)
        return -1;
    MYSQL *pConn = CreateDBConn();
    if(pConn == NULL){
        LogMessage(LOG_ERR,"%s:failed to create db connection,return\n",__FUNCTION__);
        return -2;
    }
    
    int ret = ExecuteSql(pConn,sql);
    if(ret != 0){
        LogMessage(LOG_ERR,"%s:SQL(%s) failed\n",__FUNCTION__,sql);
    }
	CloseDBConn(pConn);
    
    return ret;
}

static int cleanWhiteIpInDb()
{
    LogMessage(LOG_INFO,"%s\n",__FUNCTION__);
    char sql[256] = {0};
    snprintf(sql,sizeof(sql),"delete from %s where source = 1",IP_WHITELIST_TABLE);
    return excuteSqlOnce(sql);
}

static int updateWhiteIp2Db(uint32_t ip,const char *domain)
{
    LogMessage(LOG_INFO,"%s\n",__FUNCTION__);
    char sql[512] = {0};
    snprintf(sql,sizeof(sql),"insert into %s(ip,domain,source,timestamp) values(%u,'%s',1,now())",
        IP_WHITELIST_TABLE,ip,domain);
    excuteSqlOnce(sql);
}

/**
*@Description: fnv hash function,generate hash number as array index.
*@Paras: str
                string to hash
              max
                max size of hash array
*@Return: int
              hash number(array index)
*@Author: Chad
*/
unsigned int FNVHash(const char* str,uint32_t max)  
{  
    unsigned int hash = 2166136261; 
    
    while (*str)  
    {  
        hash *= 16777619;  
        hash ^= *str++;  
    }  
    
    return(hash % max);
} 


/**
*@Description: get hash number by str and max size of array,it is the wrapper function of FNVhash.
*@Paras: str
                string to hash
              max
                max size of hash array
*@Return: uint32_t
              hash number(array index)
*@Author: Chad
*/
static uint32_t getHashIndex(const char *str,uint32_t max)
{
    char hashStr[16] = "";
    int str_len = strlen(str);
    if(str_len < 4){
        return 0;
    }
    else if(str_len >=4 && str_len < 20){
        snprintf(hashStr,sizeof(hashStr),"%d%s",str_len,str);
    }
    else if(str_len >= 20 && str_len < 30){/*012 7 11 15 19*/
        snprintf(hashStr,sizeof(hashStr),"%d%c%c%c%c%c%c%c",
            str_len,*str,*(str+1),*(str+2),*(str+7),*(str+11),*(str+15),*(str+19));
    }
    else if(str_len >= 30 && str_len < 50){/*012 10 16 22 28*/
        snprintf(hashStr,sizeof(hashStr),"%d%c%c%c%c%c%c%c",
            str_len,*str,*(str+1),*(str+2),*(str+10),*(str+16),*(str+22),*(str+28));
    }
    else if(str_len >= 50 && str_len < 80){/*012 11 22 33 44*/
        snprintf(hashStr,sizeof(hashStr),"%d%c%c%c%c%c%c%c",
            str_len,*str,*(str+1),*(str+2),*(str+11),*(str+22),*(str+33),*(str+44));
    }
    else{/*0 15 30 40 55 70 80*/
        snprintf(hashStr,sizeof(hashStr),"%d%c%c%c%c%c%c%c",
            str_len,*str,*(str+15),*(str+30),*(str+40),*(str+55),*(str+70),*(str+80));
    }
    
    return FNVHash(hashStr,max);
}

/**
*@Description: add ip address(number address,network byte order) to list.
*@Paras: ipaddr
                number ip,network byte order
              list
                which list to add
*@Return: int
              0 on success and 1 on duplicated ip,others menas failure
*@Author: Chad
*/
static int addIp2List(uint32_t ipaddr,match_ip_list *list)
{
    int duplicated = 0;
    match_ip_list *node = (match_ip_list *)calloc(1,sizeof(match_ip_list));
    if(node == NULL){
        LogMessage(LOG_ERR,"calloc error:%s\n",strerror(errno));
        return -1;
    }
    
    node->ip = ipaddr;
    match_ip_list *tmp_node;
    list_for_each_entry(tmp_node, &(list->h_list), h_list) {
        if(tmp_node->ip == ipaddr){
            duplicated = 1;
            break;
        }
    }
    if(!duplicated){
        c_list_add(&(node->h_list),&(list->h_list));
    }
    else{
        free(node);
    }

    return duplicated;
}


static int addIpStr2WhiteList(const char *ipAddress)
{
    uint32_t ipaddr = 0;
    if(inet_pton(AF_INET,ipAddress,&ipaddr) <= 0){
        LogMessage(LOG_NOTICE,"bad ipaddress(%s):%s\n",ipAddress,strerror(errno));
        return -1;
    }
    
    if(white_ip_cnt >= MAX_WHITE_IP_SIZE)
        return -2;
    
    int ret = addIp2List(ipaddr,&white_ip_list);
    if(ret == 0)
        white_ip_cnt++;
    
    return ret;

}

static int addIpStr2BlackList(const char *ipAddress)
{
    uint32_t ipaddr = 0;
    if(inet_pton(AF_INET,ipAddress,&ipaddr) <= 0){
        LogMessage(LOG_NOTICE,"bad ipaddress(%s):%s\n",ipAddress,strerror(errno));
        return -1;
    }
    
    int array_index = ipaddr & 0xffff;
    if(array_index >= MAX_IP_SIZE){
        LogMessage(LOG_ERR,"**********something error**********\n");
        return -2;
    }
    
    int ret = addIp2List(ipaddr,&black_ip_array[array_index]);
    if(ret == 0)
        black_ip_cnt++;
    
    return ret;

}


/**
*@Description: add string(such as domain,url,webshell and so on) to list.
*@Paras: str
                string to add list
              list
                which list to add
              max_array_size
                the max size of list array,if it is 0,that means the list is not an array,it is simpliy a list
*@Return: int
              0 on success and 1 on duplicated string,others menas failure
*@Author: Chad
*/
static int addStr2List(const char *str,match_str_list *list,int max_array_size)
{
    if(!str || !list)
        return 0;
    
    int duplicated = 0;
    
    match_str_list *node = (match_str_list *)calloc(1,sizeof(match_str_list));
    if(node == NULL){
        LogMessage(LOG_ERR,"calloc error:%s\n",strerror(errno));
        return -1;
    }
    
    int str_len = strlen(str);
    node->match_str= (char *)calloc(1,str_len + 1);
    if(node->match_str == NULL){
        LogMessage(LOG_ERR,"calloc error:%s\n",strerror(errno));
        return -2;
    }
    
    strncpy(node->match_str,str,str_len);
    match_str_list *tmp_node;
    match_str_list *pList;
    if(max_array_size > 0){
        uint32_t array_index = getHashIndex(str,max_array_size);
        pList = list + array_index;
    }
    else{
        pList = list;
    }
    
    list_for_each_entry(tmp_node, &(pList->h_list), h_list) {
        if(strcasecmp(tmp_node->match_str,str) == 0){
            duplicated = 1;
            break;
        }
    }
    
    if(duplicated){
        free(node->match_str);
        free(node);
    }
    else{
        c_list_add(&(node->h_list),&(pList->h_list));
    }

    return duplicated;
    
}

static int addWhiteUrl2List(const char *url)
{
    int ret = addStr2List(url,white_url_array,MAX_WHITE_URL_SIZE);
    if(ret == 0)
        white_url_cnt++;

    return ret;
}

static int addBlackUrl2List(const char *url)
{
    int ret = addStr2List(url,black_url_array,MAX_URL_SIZE);
    if(ret == 0){
        size_t url_len = strlen(url);
        
        if(url_len > max_black_url_len)
            max_black_url_len = url_len;
        if(url_len < min_black_url_len)
            min_black_url_len = url_len;
        
        black_url_cnt++;
    }

    return ret;
}


static int addWhiteDomain2List(const char *domain)
{
    int ret = addStr2List(domain,white_domain_array,MAX_WHITE_DOMAIN_SIZE);
    if(ret == 0)
        white_domain_cnt++;

    return ret;
}

static int addUserWhiteDomain2List(const char *domain)
{
    int ret = addStr2List(domain,user_white_domain_array,MAX_WHITE_DOMAIN_SIZE);
    if(ret == 0){
        size_t domain_len = strlen(domain);
        if(domain_len > max_user_white_domain_len)
            max_user_white_domain_len = domain_len;
        user_white_domain_cnt++;
    }

    return ret;
}

static int addBlackDomain2List(const char *domain)
{
    int ret = addStr2List(domain,black_domain_array,MAX_DOMAIN_SIZE);
    if(ret == 0){
        size_t domain_len = strlen(domain);
        if(domain_len > max_black_domain_len)
            max_black_domain_len = domain_len;
        if(domain_len < min_black_domain_len)
            min_black_domain_len = domain_len;
        black_domain_cnt++;
    }

    return ret;
}

static int addWebshell2List(const char *webshell)
{
    int ret = addStr2List(webshell,web_shell_array,MAX_WEBSHELL_SIZE);
    if(ret == 0)
        webshell_cnt++;
    
    return ret;
    
}

/**
*@Description: check whether the domain is belong to user defined(static) whitelist.
*@Paras: domain
                a pointer to domain_segment structure
              parts
                how many part of this domain had,for example,if the domain is www.abc.com,then the parts should be three.
*@Return: int
              0:negative,the domain is NOT belong to this list, 1:positive
*@Author: Chad
*/
static int isDomainBelongToUserWhitelist(domain_segment *domain,int parts)
{
    if(parts < 2)
        return 0;

    int i = 0;
    if(parts > 4){
        i += parts - 4;
    }
    
    while(i<parts){
        if((domain+i)->len > max_user_white_domain_len)
            return 0;
        
        uint32_t array_index = getHashIndex((domain+i)->start,MAX_WHITE_DOMAIN_SIZE);
        match_str_list *tmp_node;
        
        if(c_list_empty(&(user_white_domain_array[array_index].h_list))){
            i++;
            continue;
        }
        
        list_for_each_entry(tmp_node, &(user_white_domain_array[array_index].h_list), h_list){
            if(strcasecmp(tmp_node->match_str,(domain+i)->start) == 0){
                return 1;
            }
        }
        i++;
    }
    
    return 0;
}


/**
*@Description: check whether the ip is belong to user defined(static) whitelist.
*@Paras: ip
                ip address, network byte order
*@Return: int
              0:negative,the ip is NOT belong to this list, 1:positive
*@Author: Chad
*/
static int isIpBelongToUserWhitelist(uint32_t ipaddr)
{
    uint32_t ip = ntohl(ipaddr);
    int array_index = ip & 0xffff;

    if(array_index > MAX_IP_SIZE)
        return 0;
    
    if(c_list_empty(&(user_white_ip_array[array_index].h_list))){
        return 0;
    }
    
    match_ip_list *tmp_node;
    list_for_each_entry(tmp_node, &(user_white_ip_array[array_index].h_list), h_list) {
        if(tmp_node->ip== ip){
            return 1;
        }
    }

    return 0;
}

/**
*@Description: add ip which resoved by white domain to whitelist.
*@Paras: ip
                ip address, network byte order
*@Return: int
              0 on success
*@Author: Chad
*/
static int addWhiteIpDynamicly(uint32_t ipaddr,const char *domain)
{
    uint32_t ip = ntohl(ipaddr);
    int array_index = ip & 0xffff;
    if(array_index >= MAX_IP_SIZE){
        LogMessage(LOG_ERR,"**********something error**********\n");
        return -2;
    }
    
    int ret = addIp2List(ip,&user_white_ip_array[array_index]);
    if(ret == 0){
        updateWhiteIp2Db(ip,domain);
        user_white_ip_cnt++;
    }
    
    return ret;
}

/*transfer \ and " to \\ and \"*/
static char *transferSlashChar(const char *str,char *new_string)
{
	if(!str || !new_string)
		return NULL;
	char c;
	while((c = *str) != '\0'){
		if(c != '\\' && c != '"'){
			*new_string++ = c;
			++str;
		}
		else{
			*new_string++ = '\\';
			*new_string++ = c;
			++str;
		}
	}
	return new_string;
}

static int addUserAgent2List(const char *ua)
{
    int duplicated = 0;
    match_str_list *node = (match_str_list *)calloc(1,sizeof(match_str_list));
    if(node == NULL){
        LogMessage(LOG_ERR,"calloc error:%s\n",strerror(errno));
        return -1;
    }
    
    size_t ua_len = strlen(ua);
    
    node->match_str= (char *)calloc(1,ua_len*2);
    if(node->match_str == NULL){
        LogMessage(LOG_ERR,"calloc error:%s\n",strerror(errno));
        return -2;
    }
    
    transferSlashChar(ua,node->match_str);
    match_str_list *tmp_node;
    list_for_each_entry(tmp_node, &(user_agents.h_list), h_list) {
        if(strcasecmp(tmp_node->match_str,node->match_str) == 0){
            duplicated = 1;
            break;
        }
    }
    
    if(!duplicated){
        c_list_add_tail(&(node->h_list),&(user_agents.h_list));
        user_agents_len += strlen(node->match_str);
        ua_cnt++;
    }
    else{
        free(node->match_str);
        free(node);
    }
    
    return duplicated;
}


/**
*@Description: get type of string,url or domain or ip address.
*@Paras: str
                string to check
*@Return: int
                NULL_STR,
                URL_STR,
                DOMAIN_STR,
                IP_STR
*@Author: Chad
*/
static int getStrType(const char *str)
{
    if(str == NULL)
        return NULL_STR;
    
    if(*str < 48 || *str > 57){/*not begin with number,so ,it is not ip address,domain or url*/
        return (strchr(str,'/') != NULL) ? URL_STR : DOMAIN_STR;
    }
    else{/*start with number,it is ip or url or domain,and we ignore ipv6 address*/
        uint32_t ipaddr = 0;
        if(strlen(str) >= INET_ADDRSTRLEN)
            return (strchr(str,'/') != NULL) ? URL_STR : DOMAIN_STR;
        else
            return inet_pton(AF_INET,str,&ipaddr) > 0 ? IP_STR : (strchr(str,'/') != NULL ? URL_STR : DOMAIN_STR);
    }
}


/**
*@Description: insert string(or line) into list array by resource file type and string type.
*@Paras: str
                string to insert
             file_type
                file type, such as whitelist blacklist webshell user agent
*@Return: int
*@Author: Chad
*/
static int addStr2ListArray(const char *str, int file_type)
{
    if(str == NULL)
        return -1;
    
    int str_type = NULL_STR;
    
    switch (file_type){
        case WEBSHELL:
            addWebshell2List(str);
            break;
        case USER_AGENT:
            addUserAgent2List(str);
            break;
        case WHITELIST:
            str_type = getStrType(str);
            switch(str_type){
                case DOMAIN_STR:
                    addWhiteDomain2List(str);
                    break;
                case URL_STR:
                    addWhiteUrl2List(str);
                    break;
                case IP_STR:
                    addIpStr2WhiteList(str);
                    break;
                case NULL_STR:
                default:
                    LogMessage(LOG_NOTICE,"unknown string type: %s\n",str);
                    break;
            }
            break;
        case BLACKLIST:
            str_type = getStrType(str);
            switch(str_type){
                case DOMAIN_STR:
                    addBlackDomain2List(str);
                    break;
                case URL_STR:
                    addBlackUrl2List(str);
                    break;
                case IP_STR:
                    addIpStr2BlackList(str);
                    break;
                case NULL_STR:
                default:
                    LogMessage(LOG_NOTICE,"unknown string type: %s\n",str);
                    break;
            }
            break;
        case USER_WHITE_DOMAIN:
            addUserWhiteDomain2List(str);
            break;
        default:
            LogMessage(LOG_NOTICE,"unknown file type: %s\n",str);
            break;
    }
    
    return 0;
}

/**
*@Description: validate the input line.
*@Paras: line
                string to validate
             file_type
                file type, such as whitelist blacklist webshell user agent
*@Return: int
*@Author: Chad
*/
static int validateLine(char *line,int file_type)
{
    if(line == NULL || strlen(line) == 0)
        return -1;
    
    /*trim the blank at the head and tail*/
    char *head = NULL;
    char *tail = NULL;
    head = line;
    tail = line + strlen(line)-1;
    /*remove new line char*/
    if(*tail == '\n'){
        *tail-- = '\0';
    }
    
    while(*tail == ' ' && tail > head){ 
        *tail = '\0';
        *tail--;
    }
    while(*head == ' ' && head < tail){
        head++;
    } 

    /*check line*/
    if(strlen(head) == 0){
        LogMessage(LOG_INFO,"blank line,skip\n");
        return 1;
    }
    if(*head == '#'){/*comment line*/
        LogMessage(LOG_INFO,"comment line:%s\n",head);
        return 2;
    }
    if(file_type != USER_AGENT && strchr(head,'.') == NULL){
        //LogMessage(LOG_INFO,"line is neither ip address nor domain or url,because no dot found:%s\n",head);
        return 3;
    }
    return 0;

}

static int loadResourceFile(const char *start,const char *end,int file_type)
{
    if(!start || !end)
        return -1;
    
    LogMessage(LOG_INFO,"%s\n",__FUNCTION__);
    
    int index;
    int ret;
    char line[1024];
    const char *s = start;
    
    while(s < end){
        total_line_in_file++;
        memset(&line,0,sizeof(line));
        index = 0;

        while(*s != '\n'){
            line[index++] = *s++; 
        }
        
        s++;
        ret = validateLine(line,file_type);
        if(ret == 0){
            if(file_type == USER_WHITE_DOMAIN){
                char *p = strchr(line,' ');
                if(p)
                    *p = 0;
                str2Lower(line);
            }
            addStr2ListArray(line,file_type);
        }
    }
    
    return 0;
}
/**
*@Description: read resource file line by line and add this line to related list array.
*@Paras: file_path
                resource file path
*@Return: int
                0:success to read file
                -1:failed to open resource file
*@Author: Chad
*/
static int lookupResourceFileAndAddResource2List(const char *file_path,int file_type)
{
    LogMessage(LOG_INFO,"read resource file %s**************************************\n",file_path);
    FILE *fp = fopen(file_path,"r");
    if(!fp){
       LogMessage(LOG_ERR,"failed to open file %s:%s\n",file_path,strerror(errno));
        return -1;
    }

    char line[512] = "";
    int ret = 0;
    
    while(fgets(line,sizeof(line),fp) != NULL){ /*max read 32-1 charactor and last char is 0*/
        total_line_in_file++;
        
        ret = validateLine(line,file_type);
        if(ret == 0){
            if(file_type == USER_WHITE_DOMAIN){
                char *p = strchr(line,' ');
                if(p)
                    *p = 0;
            }
            addStr2ListArray(line,file_type);
        }
        
    }
    
    fclose(fp);
    return 0;
}


static int initializeSuspiciousList()
{
    /*initialize black ip list*/
    int i = 0;
    while(i<MAX_IP_SIZE){
        INIT_LIST_HEAD(&(black_ip_array[i++].h_list));
    }
    
    /*initialize black domain list*/
    i = 0;
    while(i<MAX_DOMAIN_SIZE){
        INIT_LIST_HEAD(&(black_domain_array[i++].h_list));
    }
    
    /*initialize black url list*/
    i = 0;
    while(i<MAX_URL_SIZE){
        INIT_LIST_HEAD(&(black_url_array[i++].h_list));
    }
    
    return 0;
}


static int initializeWebshellList()
{
    /*initialize webshell list*/
    int i = 0;
    while(i<MAX_WEBSHELL_SIZE){
        INIT_LIST_HEAD(&(web_shell_array[i++].h_list));
    }
    return 0;
}


static int initializeUaList()
{
    /*initialize user agent list*/
    INIT_LIST_HEAD(&(user_agents.h_list));
    return 0;
}

static int initializeWhiteList()
{
    /*initialize white ip list*/
    INIT_LIST_HEAD(&(white_ip_list.h_list));
    int i = 0;
    while(i<MAX_WHITE_DOMAIN_SIZE){
        INIT_LIST_HEAD(&(white_domain_array[i++].h_list));
    }
    
    /*initialize white url list*/
    i = 0;
    while(i<MAX_WHITE_URL_SIZE){
        INIT_LIST_HEAD(&(white_url_array[i++].h_list));
    }
    
    /*initialize white domain list*/
    i = 0;
    while(i<MAX_WHITE_DOMAIN_SIZE){
        INIT_LIST_HEAD(&(user_white_domain_array[i++].h_list));
    }
    
    /*initialize white ip list*/
    i = 0;
    while(i<MAX_IP_SIZE){
        INIT_LIST_HEAD(&(user_white_ip_array[i++].h_list));
    }
    
    cleanWhiteIpInDb();
    
    return 0;
}


/*clean function*/
static void sceClean()
{
    /*do some clean action,such as free list*/
    if(puser_agent_regex != NULL)
        free(puser_agent_regex);
    /*the list data will keep untill sce exit,so ,no need to free it*/
}


static int isIpInList(uint32_t ip,match_ip_list *list,int max_array_size)
{
    match_ip_list *pList = NULL;
    if(max_array_size > 0){
        int array_index = ip & 0xffff;
        if(array_index >= max_array_size)
            return 0;
        pList = &list[array_index];
    }
    else{
        pList = list;
    }
    
    if(c_list_empty(&(pList->h_list))){
        return 0;
    }
    
    match_ip_list *tmp_node;
    int found = 0;
    list_for_each_entry(tmp_node, &(pList->h_list), h_list) {
        if(tmp_node->ip == ip){
            found = 1;
            break;
        }
    }
    
    return found;
}
/**
*@Description: check whether the ip in black ip list.
*@Paras: ip
                ip address to check
*@Return: int
                0:not found
                1:found it
*@Author: Chad
*/
inline int isIpInBlacklist(uint32_t ip)
{
    return black_ip_cnt == 0 ? 0 : isIpInList(ip,black_ip_array,MAX_IP_SIZE);
}

/*
check whether the ip is belong to whitelist
return 0: no=>ip not in the whitelist
1: yes=>ip in white list
*/
inline int isIpInWhitelist(uint32_t ip)
{
    return isIpInList(ip,&white_ip_list,0);
}


static int isStrInList(const char *str,match_str_list *list,int max_array_size)
{
    if(!str || !list)
        return 0;
    
    match_str_list *pList = NULL;
    if(max_array_size > 0){
        uint32_t array_index = getHashIndex(str,max_array_size);
        pList = &list[array_index];
    }
    else{
        pList = list;
    }
    
    if(c_list_empty(&(pList->h_list))){
        return 0;
    }
    
    match_str_list *tmp_node;
    int found = 0;
    list_for_each_entry(tmp_node, &(pList->h_list), h_list) {
        if(strcasecmp(tmp_node->match_str,str) == 0){
            found = 1;
            break;
        }
    }

    return found;
}
/**
*@Description: check whether the domain in black domain list.
*@Paras: domain
                domain to check
*@Return: int
                0:not found
                1:found it
*@Author: Chad
*/
int isDomainInBlacklist(const char *domain)
{
    if(domain == NULL)
        return 0;
    
    size_t len = strlen(domain);
    if(len < min_black_domain_len || len > max_black_domain_len || black_domain_cnt == 0)
        return 0;
    
    return isStrInList(domain,black_domain_array,MAX_DOMAIN_SIZE);
}

/*
check whether the domain is belong to whitelist
return 0: no=>domain not in the whitelist
1: yes=>domain in white list
*/
int isDomainInWhitelist(const char *domain)
{
    if(domain == NULL)
        return 0;
    
    size_t len = strlen(domain);
    if(len == 0)
        return 0;

    int is_white_domain = isStrInList(domain,white_domain_array,MAX_WHITE_DOMAIN_SIZE);
    #ifdef USE_USER_WHITE_DOMAIN
        if(!is_white_domain){
            is_white_domain = isStrInList(domain,user_white_domain_array,MAX_WHITE_DOMAIN_SIZE);
        }
    #endif
    if(is_white_domain)
        is_white = 1;
    return is_white_domain;
}


/*
check whether the filename is belong to webshell
return 0: no
1: yes
*/
int isFilenameInWebshell(const char *filename)
{
    if(filename == NULL)
        return 0;
    
    size_t len = strlen(filename);
    if(len == 0)
        return 0;
    
    return isStrInList(filename,web_shell_array,MAX_WEBSHELL_SIZE);
}



/**
*@Description: heuristic algorithm form domain.
*@Paras: domain
                domain address to check
*@Return: int
                -1:domain is null
                0:not match
                1:match heuristic algorithm
*@Author: Chad
*/
int domainHeuristic(const char *domain)
{
    //LogMessage(LOG_DEBUG,"%s\n",__FUNCTION__);
    static const char whitelist_long_domain_name_keywords[] = "blogspot";
    if(domain == NULL)
        return -1;
    
    const char *dot = strchr(domain,'.');
    if(dot == NULL)
        dot = domain;
    int main_domain_len = dot-domain;
    if(main_domain_len > SUSPICIOUS_DOMAIN_LENGTH_THRESHOLD && main_domain_len < MAX_SUSPICIOUS_DOMAIN_LENGTH){
        char *main_domain = calloc(1,main_domain_len+1);
        if(main_domain){
            strncpy(main_domain,domain,main_domain_len);
            if(strchr(main_domain,'-') != NULL){
                free(main_domain);
                return 0;
            }
            free(main_domain);
        }
        
        const char *pKeywords = whitelist_long_domain_name_keywords;
        const char *pDomain = domain;
        char match_heuristic = 1;
        while(*pKeywords != '\0'){
            while(*pDomain != '\0'){
                if(*pKeywords == *pDomain++){
                    match_heuristic = 0;
                    break;
                }
            }
            pKeywords++;
        }
        return match_heuristic;
    }

    return 0;
}


/*
desc:validate the domain format,
return 0:validate success*/
static int validateDomainFormat(const char *domain)
{
    /*domain format only contain letters,digit,'-' and '.'*/
    const char *p = domain;
    if(p == NULL)
        return -1;
    
    while(*p != '\0'){
        if(!((*p >= 48 && *p <= 57) /*digit*/
            || (*p >= 65 && *p <= 90) /*upper case*/
            || (*p >= 97 && *p <= 122) /*lower case*/
            || *p == '-' 
            || *p == '.'))return 1;
        p++;
    }
    
    return 0;
}

/**
*@Description: check domain
*@Paras: domain
                domain address to check
*@Return: int
                0:not match suspicious domain
                1:match suspicious domain
*@Author: Chad
*/
int checkDomain(const char *domain)
{
    int ret = validateDomainFormat(domain);
    if(ret != 0)
        return 0;
    
    ret = checkDomainListed(domain,WHITELIST);
    if(ret == 1)
        return 0;
    
    ret = checkDomainListed(domain,BLACKLIST);
    if(ret == 1)
        return 1;
    #ifdef USE_HEURISTICS
        return domainHeuristic(domain);
    #else
        return ret;
    #endif
}

/**
*@Description: check ip address
*@Paras: ip
                ip address to check
*@Return: int
                1:suspicious ip
*@Author: Chad
*/
int checkIpAddress(uint32_t ip)
{
    if(! isIpInWhitelist(ip)){
        if(isIpInBlacklist(ip)){
            return 1;
        }
    }
    
    return 0;
}

/**
*@Description: check whether the url in black url list.
*@Paras: url
                url address to check
*@Return: int
                0:not found
                1:found it
*@Author: Chad
*/
int isUrlInBlacklist(const char *url)
{
    if(url == NULL)
        return 0;
    
    size_t len = strlen(url);
    if(len < min_black_url_len || len > max_black_url_len || black_url_cnt == 0)
        return 0;
    
    return isStrInList(url,black_url_array,MAX_URL_SIZE);
}

/*return 0: no=>url not in the whitelist
1: yes=>url in white list
*/
int isUrlInWhitelist(const char *url)
{
    if(url == NULL)
        return 0;
    
    size_t len = strlen(url);
    if(len == 0)
        return 0;
    
    return isStrInList(url,white_url_array,MAX_WHITE_URL_SIZE);
}

static inline void logEvent(int event_type)
{
    switch(event_type){
        case IP_EVENT:
            LogMessage(LOG_NOTICE,"*********got suspicious ip**********\n");
            break;
        case DOMAIN_EVENT:
            LogMessage(LOG_NOTICE,"*********got suspicious domain**********\n");
            break;
        case URL_EVENT:
            LogMessage(LOG_NOTICE,"*********got suspicious url**********\n");
            break;
        default:
            break;
    }
}

static void strncpySafe(char *dst,const char *src,size_t n,size_t dst_size)
{
    if(dst == NULL || src == NULL || n == 0){
        return;
    }
    
    if(n<dst_size){
        memset(dst,0,n+1);
        memcpy(dst,src,n);
    }
    else{
        memset(dst,0,dst_size);
        memcpy(dst,src,dst_size-1);
    }
}

static char *strStrip(char *str)
{
    if(!str || strlen(str) == 0)
        return str;
    char *begin = str;
    char *end = str + strlen(str) - 1;
    /*blank*/
    while(*begin <= 32) begin++;
    while(*end <= 32){
        *end = 0;
        end--;
    }
    strcpy(str,begin);
    return str;
}

static inline char* str2Upper(char *str)
{
    char *orign=str;
    for (; *str!='\0'; str++)
        *str = toupper(*str);
    return orign;
}

static inline char* str2Lower(char *str)
{
    char *orign=str;
    for (; *str!='\0'; str++){
        if(isalpha(*str))
            *str = tolower(*str);
    }
    return orign;
}

/*notice:not thread-safe*/
static char *getSubstring(const char *str,const char *from,const char *end)
{
    if(!str)
        return NULL;
    static char substring[1500] = {0};
    const char *pFrom;
    const char *pEnd;
    
    if(from == NULL){
        pFrom = str;
    }
    else{
        pFrom = strcasestr(str,from);
        if(pFrom){
            pFrom = pFrom+strlen(from);
         }
    }
    if(pFrom){
        if(end == NULL){
            pEnd = str + strlen(str);
        }
        else{
            pEnd = strcasestr(pFrom,end);
        }
        if(pEnd){
            if(pEnd - pFrom >= sizeof(substring))
                return NULL;
            else{
                strncpySafe(substring,pFrom,pEnd-pFrom,sizeof(substring));
                return substring;
            }    
        }
    }
    return NULL;
}

void urldecode(char *p)  
{  
    int i=0;
    char *end = p + strlen(p);
    while((p+i)<end)  
    {  
       if ((*p=*(p+i)) == '%')  
       {  
        *p=*(p+i+1) >= 'A' ? ((*(p+i+1) & 0XDF) - 'A') + 10 : (*(p+i+1) - '0');  
        *p=(*p) * 16;  
        *p+=*(p+i+2) >= 'A' ? ((*(p+i+2) & 0XDF) - 'A') + 10 : (*(p+i+2) - '0');  
        i+=2;  
       }  
       else if (*(p+i)=='+')  
       {  
        *p=' ';  
       }  
       p++;  
    }  
    *p='\0';  
} 

/*
return 0:not in whitelist
1:in whitelist
*/
static int checkDomainListed(const char *domain,int domain_type)
{
    if(domain == NULL || strlen(domain) == 0)
        return 1;
    
    if(domain_type == WHITELIST){
        if(isDomainInWhitelist(domain))
            return 1;
    }
    else if(domain_type == BLACKLIST){
        if(isDomainInBlacklist(domain))
            return 1;
    }
    
    char *dot = strchr(domain,'.');
    while(dot){
        dot++;
        if(domain_type == WHITELIST){
            if(isDomainInWhitelist(dot)){
                return 1;
            }
        }
        else if(domain_type == BLACKLIST){
            if(isDomainInBlacklist(dot))
                return 1;
        }
        
        dot = strchr(dot,'.');
    }
    return 0;
}

/*
return 0:not in whitelist
1:in whitelist
*/
static int checkDomainBlacklisted(const char *domain)
{
    if(domain == NULL || strlen(domain) == 0)
        return 1;
    char tmp_domain[MAX_DOMAIN_LEN] = {0};
    strncpySafe(tmp_domain,domain,strlen(domain),MAX_DOMAIN_LEN);
    if(isDomainInBlacklist(tmp_domain))
        return 1;
    
    char *dot = strchr(tmp_domain,'.');
    while(dot){
        dot++;
        if(isDomainInBlacklist(dot)){
            return 1;
        }
        dot = strchr(dot,'.');
    }
    return 0;
}


static int checkTitle(const char *http_response)
{
    static char *suspicous_title[] = {
        "this domain",
        "has been seized",
        NULL
    };
    if(http_response == NULL)
        return 0;
    char *title = getSubstring(http_response,"<title>","</title>");
    if(title != NULL){
        int i = 0;
        title = strStrip(title);
        while(suspicous_title[i] != NULL){
            if(strcasecmp(suspicous_title[i],title) == 0){
                logEvent(URL_EVENT);
                strcpy(response_matched_suspicious_str,suspicous_title[i]);
                return 1;
            }
            i++;
        }
    }
    return 0;
}

/*
return 0:ok
1: suspicious content type
*/
static int checkContentType(const char *http_response)
{
    static char *suspicous_content_type[] = {
        "application/x-sh",
        "application/x-shellscript",
        "text/x-sh",
        "text/x-shellscript",
        NULL
    };
    if(http_response == NULL || strlen(http_response) == 0)
        return 0;
    char *content_type = getSubstring(http_response,"\r\nContent-Type:","\r\n");
    if(content_type != NULL){
        int i = 0;
        content_type = strStrip(content_type);
        while(suspicous_content_type[i] != NULL){
            if(strcasecmp(suspicous_content_type[i],content_type) == 0){
                logEvent(URL_EVENT);
                strcpy(response_matched_suspicious_str,suspicous_content_type[i]);
                END_CHECK
            }
            i++;
        }   
    }
    return 0;
}

/*check host of http request
1)host is not ip address but dst ip is suspicious=>suspicious
2)host is not ip address but host is suspicious => suspicious
*/
static int checkRequestHost(char *host,uint32_t dst_ip)
{
    uint32_t host_ip = 0;
    if(strlen(host) > 3 && strcmp(host + strlen(host) - 3,":80") == 0){
        host[strlen(host)-3] = 0;
    }
    #if 0
    if(isalpha(host[0]) && checkIpAddress(dst_ip)){/*host not ip, and destination ip of the packet is suspicious*/
        logEvent(URL_EVENT);
        return 1;
    }
    else 
    #endif
    if(inet_pton(AF_INET,host,&host_ip) <= 0){/*host not ipaddress,check domain*/
        if(checkDomain(host)){
            logEvent(DOMAIN_EVENT);
            return 1;
        }
    }
    return 0;
}
/*
notice:not thread-safe
get host from path,if path is http://www.baidu.com:80/index.html
the host should be www.baidu.com
*/
static char *getHostFromPath(const char *path)
{
    //LogMessage(LOG_DEBUG,"%s\n",__FUNCTION__);
    static char host[MAX_HOST_LEN] = {0};
    if(!path)
        return NULL;
    size_t path_len = strlen(path);
    if(path_len > MAX_URL_LEN)
        return NULL;
    char *double_slash;
    char *single_slash;
    const char *host_begin = path;
    const char *host_end = path + path_len;
    double_slash = strstr(path,"://");
    if(double_slash){
        host_begin = double_slash + 3;/*:3 is strlen("://")*/
        if((single_slash = strchr(host_begin,'/')) != NULL){
            host_end = single_slash;
        }
    }

    strncpySafe(host,host_begin,host_end-host_begin,MAX_HOST_LEN);
    char *colon = NULL;
    if((colon = strchr(host,':')) != NULL){
        *colon = 0;
    }
    return host;
}

static int checkRequestPath(http_header_info *pheader)
{
    /*http path might have domain or ip,suspicious,check it*/
    char *host_in_path = getSubstring(pheader->request.path,"://","/");
    if(host_in_path){
        strncpySafe(pheader->request.host,host_in_path,strlen(host_in_path),sizeof(pheader->request.host));
        if(strlen(pheader->request.host) > 3 && strcmp(pheader->request.host + strlen(pheader->request.host) - 3,":80") == 0){
            pheader->request.host[strlen(pheader->request.host)-3] = 0;
        }
        char *p = strtok(host_in_path,":");
        if(p){
            return checkDomain(p);
        }
    }
    return 0;
}

static int checkRequestPathWithMethod(http_header_info *phttp_header)
{
    char path[MAX_DOMAIN_LEN] = {0};
    strncpySafe(path,phttp_header->request.path,strlen(phttp_header->request.path),sizeof(path));
    char *pSingleSlash = strchr(path,'/');
    char *path_end = path + strlen(path);
    if(pSingleSlash){
        strncpySafe(phttp_header->request.host,path,pSingleSlash - path,sizeof(phttp_header->request.host));
        strncpySafe(phttp_header->request.path,pSingleSlash,path_end - pSingleSlash,sizeof(phttp_header->request.path));
    }
    else{
        strncpySafe(phttp_header->request.host,path,strlen(path),sizeof(phttp_header->request.host));
        strcpy(phttp_header->request.path,"/");
    }
    snprintf(phttp_header->request.url,sizeof(phttp_header->request.url),"%s%s",phttp_header->request.host,phttp_header->request.path);
    if(strlen(phttp_header->request.host) > 3 && strcmp(phttp_header->request.host + strlen(phttp_header->request.host) - 3,":80") == 0){
        phttp_header->request.host[strlen(phttp_header->request.host)-3] = 0;
    }
    char *proxy_domain = strchr(phttp_header->request.host,':');
    if(proxy_domain){
        char domain[MAX_DOMAIN_LEN] = {0};
        strncpySafe(domain,phttp_header->request.host,proxy_domain - phttp_header->request.host,sizeof(domain));
        return checkDomain(domain);
    }
    else{
        return checkDomain(phttp_header->request.host);
    }
}

static int gotStrMatch(const char *str,char **match)
{
    int i = 0;
    while(*(match+i) != NULL){
        if(strcasestr(str,*(match+i))){
            return ++i;
        }
        i++;
    }
    return 0;
    
}
static int checkHttpUserAgent(char *agent)
{
    if(agent == NULL)
        return 0;
    
    static char *white_ua[] = {
        "AntiVir-NGUpd",
        "TMSPS",
        "AVGSETUP",
        "SDDS",
        "Sophos",
        "Symantec",
        "internal dummy connection",
        NULL
    };
    
    int match = gotStrMatch(agent,white_ua);

    if(!match){
        int match_regex = 0;
        /*TODO:check regex,too much regex...so*/
        match_regex = suspicousUserAgentRegexCheck(agent);
        if(match_regex){
            logEvent(URL_EVENT);
            return 1;
        }
    }
    return 0;
}

/*
return 0:response is ok
1: suspicious content_type
2: got sinkhole
3: suspicious title
*/
static int checkHttpResponse(const char *http_response)
{
    if(!http_response || strlen(http_response) == 0)
        return 0;
    
    static char *sinkhole[] = {
        "X-Sinkhole:",
        "X-Malware-Sinkhole:",
        "Server: You got served",
        "Server: Apache 1.0/SinkSoft",
        "sinkdns.org",
        NULL
    };
    
    int match = gotStrMatch(http_response,sinkhole);
    
    if(match){
        strcpy(response_matched_suspicious_str,sinkhole[--match]);
        END_CHECK_RETURN(2)
    }
    else if(checkTitle(http_response)){
        END_CHECK_RETURN(3)
    }
    
    return checkContentType(http_response);
}

static char * replacement(const char *str)
{
    if(!str || strlen(str) == 0)
        return NULL;
    char *new_str = calloc(1,strlen(str)*3 + 32);
    if(!new_str){
        LogMessage(LOG_ERR,"%s:%s\n",__FUNCTION__,strerror(errno));
        return NULL;
    }
    char *org = new_str;
    static char org_char[] = "( )\r\n";
    static char *replace_char[] = {
        "%29",
        "%20",
        "%28",
        "%0D",
        "%0A",
        NULL
    };
    int i,found;
    while(*str){
        i = found = 0;
        while(org_char[i]){
            if(org_char[i] == *str){
                strcat(new_str,replace_char[i]);
                new_str += 3;
                found = 1;
                break;
            }
            i++;
        }
        if(!found){
            *new_str = *str;
            new_str++;
        }
        str++;
    }
    return org;
    
}

/*
desc: check whether the the path in whitelist is part of request_path
return 0:no,
1:yes,
*/
static int httpRequestWhitelisted(const char *request_path)
{
    if(!request_path || strlen(request_path) == 0)
        return 0;
    
    static char *whitelist_http_path[] = {
        "fql",
        "yql",
        "ads",
        "../images/",
        "../themes/",
        "../design/",
        "../scripts/",
        "../assets/",
        "../core/",
        "../js/",
        "/gwx/",
        NULL
    };
    
    return gotStrMatch(request_path,whitelist_http_path);
}

static int httpRequestSuspiciousStr(const char *request_path)
{
    if(!request_path || strlen(request_path) == 0)
        return 0;
    
    static char *suspicious_http_path[] = {
        "?",
        "..",
        ".ht",
        "=",
        " ",
        "'",
        NULL
    };
    
    return gotStrMatch(request_path,suspicious_http_path);

}

static int checkExtension(const char *extension)
{
    if(!extension || strlen(extension) == 0)
        return 0;
    
    static char *suspicious_extension[] = {
        "apk",
        "exe",
        "scr",
        NULL
    };
    
    return gotStrMatch(extension,suspicious_extension);

}

static int checkDirectDownloadKeywords(const char *path)
{
    if(!path || strlen(path) == 0)
        return 0;
    
    static char *whitelist_direct_download_keywords[] = {
        "cgi",
        "/scripts/",
        "/_vti_bin/",
        "/bin/",
        "/pub/softpaq/",
        "/bios/",
        "/pc-axis/",
        NULL
    };
    
    return gotStrMatch(path,whitelist_direct_download_keywords);
}


static int suspicousHttpPathRegexCheck(const char *http_path)
{
    #ifdef SUPPORT_REGEX_CHECK
    static char *suspicious_http_path_regex[] = {
        "defaultwebpage\\.cgi",
        "inexistent_file_name\\.inexistent|test-for-some-inexistent-file|long_inexistent_path|some-inexistent-website\\.acu",
        NULL
    };
    regex_t reg;
    regmatch_t match[1];
    int i = 0;
    while(suspicious_http_path_regex[i]){
        if (regcomp(&reg, suspicious_http_path_regex[i], REG_EXTENDED) < 0){
            regfree(&reg);
            return 0;
        }
        int err = regexec(&reg, http_path, 1, match, 0);
        regfree(&reg);
        if(err == 0){
            return 1;
        }
        else if (err != 0 && err != REG_NOMATCH) {
            LogMessage(LOG_ERR,"REGEX ERROR\n");
        }
        i++;
    }
    #endif
    return 0;
}

static int suspicousHttpRequestRegexCheck(const char *http_request)
{
    #ifdef SUPPORT_REGEX_CHECK
    static char *suspicious_http_request_regex[] = {
        "information_schema|sysdatabases|sysusers|floor\\(rand\\(|ORDER BY \\d+|\\bUNION\\s+(ALL\\s+)?SELECT\\b|\\b(UPDATEXML|EXTRACTVALUE)\\(|\\bCASE[^\\w]+WHEN.*THEN\\b|\\bWAITFOR[^\\w]+DELAY\\b|\bCONVERT\\(|VARCHAR\\(|\\bCOUNT\\(\\*\\)|\\b(pg_)?sleep\\(|\\bSELECT\\b.*\bFROM\\b.*\\b(WHERE|GROUP|ORDER)\\b|\\bSELECT \\w+ FROM \\w+|\\b(AND|OR|SELECT)\\b.*/\\*.*\\*/|/\\*.*\\*/.*\\b(AND|OR|SELECT)\\b|\\b(AND|OR)[^\\w]+\\d+['\\\") ]?[=><]['\\\"( ]?\\d+|ODBC;DRIVER|\\bINTO\\s+(OUT|DUMP)FILE",
        "/text\\(\\)='",
        "<\\?php",
        "\\(\\|\\(\\w+=\\*",
        "<script.*?>|\\balert\\(|(alert|confirm|prompt)\\((\\d+|document\\.|response\\.write\\(|[^\\w]*XSS)|on(mouseover|error|focus)=[^&;\n]+\\(",
        "\\[<!ENTITY",
        //"im[es]i=\\d{15}|(mac|sid)=([0-9a-f]{2}:){5}[0-9a-f]{2}|sim=\\d{20}|([a-z0-9_.+-]+@[a-z0-9-.]+\\.[a-z]+\\b.{0,100}){4}",
        "\\.ht(access|passwd)|\\bwp-config\\.php",
        "\\$_(REQUEST|GET|POST)\\[|xp_cmdshell|\\bping(\\.exe)? -[nc] \\d+|timeout(\\.exe)? /T|cmd\\.exe|/bin/bash|2>&1|\\b(cat|ls) /|nc -l -p \\d+|>\\s*/dev/null|-d (allow_url_include|safe_mode|auto_prepend_file)",
        "(\\.{2,}[/\\\\]+){3,}|/etc/(passwd|shadow|issue|hostname)|[/\\\\](boot|system|win)\\.ini|[/\\\\]system32\\b|%SYSTEMROOT%",
        "(acunetix|injected_by)_wvs_|SomeCustomInjectedHeader|some_inexistent_file_with_long_name|testasp\\.vulnweb\\.com/t/fit\\.txt|www\\.acunetix\\.tst|\\.bxss\\.me|thishouldnotexistandhopefullyitwillnot|OWASP%\\d+ZAP|chr\\(122\\)\\.chr\\(97\\)\\.chr\\(112\\)|Vega-Inject|VEGA123|vega\\.invalid|PUT-putfile|w00tw00t|muieblackcat",
        NULL
    };
    regex_t reg;
    regmatch_t match[19];
    int i = 0;
    while(suspicious_http_request_regex[i]){
        memset(&reg,0,sizeof(reg));
        if (regcomp(&reg, suspicious_http_request_regex[i], REG_EXTENDED) < 0){
            regfree(&reg);
            return 0;
        }
        int err = regexec(&reg, http_request, 19, match, 0);
        regfree(&reg);
        if(err == 0){
            return 1;
        }
        else if (err != 0 && err != REG_NOMATCH) {
            LogMessage(LOG_ERR,"REGEX ERROR\n");
        }
        i++;
    }
    #endif
    return 0;
}

static int suspicousUserAgentRegexCheck(char *ua)
{
    #ifdef SUPPORT_REGEX_CHECK
    if(!ua || !puser_agent_regex)
        return 0;
    
    regex_t reg;
    regmatch_t match[1];
    match_str_list *tmp_node;
    
    if (regcomp(&reg, puser_agent_regex, REG_EXTENDED) < 0){
        regfree(&reg);
        return 0;
    }

    str2Lower(ua);
    int err = regexec(&reg, ua, 1, match, 0);
    regfree(&reg);
    if(err == 0){
        return 1;
    }
    else if (err != 0 && err != REG_NOMATCH) {
        LogMessage(LOG_ERR,"REGEX ERROR\n");
    }
    #endif
    return 0;
}


static int buildSuspicousUserAgentRegexStr()
{
    LogMessage(LOG_INFO,"%s\n",__FUNCTION__);
    int i = 0;
    match_str_list *tmp_node;
    uint32_t len = user_agents_len+ua_cnt+64;
    puser_agent_regex = calloc(1,len);
    if(puser_agent_regex == NULL){
        LogMessage(LOG_ERR,"%s:failed to alloc memeory:%s\n",__FUNCTION__,strerror(errno));
        return 1;
    }
    
    //strcpy(puser_agent_regex,"(?i)");
    strcpy(puser_agent_regex,"\\(?i\\)");
    list_for_each_entry(tmp_node, &(user_agents.h_list), h_list) {
        str2Lower(tmp_node->match_str);
        snprintf(puser_agent_regex+strlen(puser_agent_regex),len-strlen(puser_agent_regex),"|%s",tmp_node->match_str);
    }
    
    LogMessage(LOG_INFO,"%s,ua regex str len:%d,ua regex:%s\n",__FUNCTION__,strlen(puser_agent_regex),puser_agent_regex);
    return 0;
}

static int checkUrl(const char *host,char *url)
{
    if(!host || !url)
        return 0;
    
    char url_with_host[MAX_URL_LEN+MAX_HOST_LEN] = {0};
    if(url[strlen(url)-1] == '/')
        url[strlen(url)-1] = 0;
    if(isUrlInBlacklist(url)){
        logEvent(URL_EVENT);
        END_CHECK
    }
    
    snprintf(url_with_host,sizeof(url_with_host),"%s%s",host,url);
    if(isUrlInBlacklist(url_with_host)){
        logEvent(URL_EVENT);
        END_CHECK
    }
    return 0;
}

/*if the referer of this request belongs to whitelist,even the request host is malicious,
we will not log this request,because,this might be a Ad or something like that which embeded in
a normal website,if we log it,(it's ok to log it i think),it might make the user nervous*/
/*return value
0: no referer found or not whitelist
1: white referer
*/
static int requestRefererInWhitelist(const char *header)
{
    char *p_referer = getSubstring(header,"\r\nReferer:","\r\n");
    if(p_referer == NULL || strlen(p_referer) == 0 || strlen(p_referer) >= 1024)
        return 0;
    char refer[1024] = {0};
    strcpy(refer,p_referer);
    char *refer_domain = getSubstring(refer,"://","/");
    if(refer_domain == NULL || strlen(refer_domain) == 0)
        return 0;
    else
        return checkDomainListed(refer_domain,WHITELIST);
    /*check Orgin too?,orgin might not ends with '/' if the domain like www.xxx.com,
        usually,the orgin just like:http[s]://www.xxx.com or http[s]://www.xxx.com/yyy,and 
        the referer is just like:http[s]://www.xxx.com/ or http[s]://www.xxx.com/yyy.html,
        in most case,the request will attached the orgin and referer both and orgin (~)= referer,or,either of them.
    */
}

/*
return 0:ok, positive:suspicious
1:suspicious host
2:no host
3:path with http://xxx/,and xxx is not belong to whitelist
4:suspicious user agent
5:path with ://xxx/,and xxx is suspicious
6:connect method with suspicious path
7:suspicious url
8:path suspicious regex matched
9:suspicious filename
*/
static int checkHttpRequest(http_header_info *pheader)
{
    /*handle http request*/
    /*step 1:get host and check it*/
    int ret = 0;
    int suspicious_id = 0;
    char *host = getSubstring(pheader->request.header,"\r\nHost:","\r\n");
    if(host){/*fill host*/
        //host = str2Lower(host);
        host = strStrip(host);
        strncpySafe(pheader->request.host,host,strlen(host),sizeof(pheader->request.host));
        ret = checkRequestHost(pheader->request.host,pheader->dst_ip);
        suspicious_id = 1;
        END_CHECK_OR_NOT(ret,suspicious_id)
    }
    else{
        /*no host,suspicious*/
        #ifdef USE_HEURISTICS
        LogMessage(LOG_DEBUG,"************no host***********\n");
        logEvent(URL_EVENT);
        suspicious_id = 2;
        END_CHECK_RETURN(suspicious_id)
        #endif
    }
    if(is_white)
        return 0;
    if(requestRefererInWhitelist(pheader->request.header)){
        return 0;
    }
    #ifdef USE_HEURISTICS
    if(pheader->dst_port == 80 && strncmp(pheader->request.path,"http://",7) == 0){
        if(!strchr(pheader->request.path + 7,'/')){
            strcat(pheader->request.path,"/"); /*no '/' in path,make sure path is end with '/'*/
        }
        char *host_in_path = getSubstring(pheader->request.path,"://","/");
        if(host_in_path){
            char *p = strtok(host_in_path,":");
            if(p){
                strncpySafe(pheader->request.host,p,strlen(p),sizeof(pheader->request.host));
                //LogMessage(LOG_DEBUG,"path with http://? suspicious,check the host in path in whitelist?\n");
                if(!checkDomainListed(pheader->request.host,WHITELIST)){
                    logEvent(DOMAIN_EVENT);
                    suspicious_id = 3;
                    END_CHECK_RETURN(suspicious_id)
                }
                else{
                    return 0;
                }
            }
        }
    }
    
    /*check user agent*/
    #ifdef CHECK_USER_AGENT
    char *user_agent = getSubstring(pheader->request.header,"\r\nUser-Agent:","\r\n");
    if(user_agent){
        user_agent = strStrip(user_agent);
        strncpySafe(pheader->response.user_agent,user_agent,strlen(user_agent),sizeof(pheader->response.user_agent));
        ret = checkHttpUserAgent(user_agent);
        suspicious_id = 4;
        END_CHECK_OR_NOT(ret,suspicious_id)
    }
    #endif
    #endif
    /*http host and path and url
        if path is http://192.168.2.111:80/abc.html   or http://192.168.2.111:80
        then host is 192.168.2.111, path is /abc.html or /,url is 192.168.2.111:80/abc.html or 192.168.2.111:80/
    */
    char *pDoubleSlash;
    if((pDoubleSlash = strstr(pheader->request.path,"://")) != NULL){
        pDoubleSlash += 3;
        char *pSingleSlash;
        if((pSingleSlash = strchr(pDoubleSlash,'/')) == NULL){
            snprintf(pheader->request.url,sizeof(pheader->request.url),"%s/",pDoubleSlash);
            strcat(pheader->request.path,"/");
            ret = checkRequestPath(pheader);/*mofidy host,the host which in the path*/
            strcpy(pheader->request.path,"/");
        }
        else{
            ret = checkRequestPath(pheader);/*mofidy host,the host which in the path*/
            snprintf(pheader->request.url,sizeof(pheader->request.url),"%s",pDoubleSlash);
            snprintf(pheader->request.path,sizeof(pheader->request.path),"%s",pSingleSlash);
        }
        suspicious_id = 5;
        END_CHECK_OR_NOT(ret,suspicious_id)

    }
    else if(strcmp(pheader->request.method,"CONNECT") == 0){
        ret = checkRequestPathWithMethod(pheader);/*fill url*/
        suspicious_id = 6;
        END_CHECK_OR_NOT(ret,suspicious_id)
    }
    else{
        snprintf(pheader->request.url,sizeof(pheader->request.url),"%s%s",pheader->request.host,pheader->request.path);
    }
    
    //LogMessage(LOG_DEBUG,"method:%s,path:%s,host:%s,url:%s\n",
      //  pheader->request.method,pheader->request.path,pheader->request.host,pheader->request.url);
    /*TODO:check url*/
    char url[MAX_URL_LEN];
    char last_path[MAX_HOST_LEN];
    strncpySafe(url,pheader->request.path,strlen(pheader->request.path),sizeof(url));
    ret = checkUrl(pheader->request.host,url);
    suspicious_id = 7;
    END_CHECK_OR_NOT(ret,suspicious_id)
    char *index = strchr(url,'?');
    if(index){
        *index = 0;
        ret = checkUrl(pheader->request.host,url);
        END_CHECK_OR_NOT(ret,suspicious_id)
    }
    index = strrchr(url,'/');
    if(index){
        strncpySafe(last_path,index,strlen(index),sizeof(last_path));
    }
    index = strrchr(url,'.');
    if(index != NULL && index != url+strlen(url)-1){
        *index = 0;
        ret = checkUrl(pheader->request.host,url);
        END_CHECK_OR_NOT(ret,suspicious_id)
    }
    int slash_total = 0;
    char *last_slash = NULL;
    index= url;
    while(index != NULL && (index = strchr(index,'/')) != NULL) {
        last_slash = index;
        slash_total++;
        index++;
    }
    if(slash_total > 1){
        *last_slash = 0;
        ret = checkUrl(pheader->request.host,url);
        END_CHECK_OR_NOT(ret,suspicious_id);
        ret = checkUrl(pheader->request.host,last_path);
        END_CHECK_OR_NOT(ret,suspicious_id)
    }
    
    #ifdef USE_HEURISTICS
        char unquoted_path[MAX_URL_LEN] = {0};
        strncpySafe(unquoted_path,pheader->request.path,strlen(pheader->request.path),sizeof(unquoted_path));
        urldecode(unquoted_path);
        char *p = replacement(pheader->request.path);
        if(p){
            strncpySafe(pheader->request.path,p,strlen(p),sizeof(pheader->request.path));
            free(p);
        }
        
        if(checkDomainListed(pheader->request.host,WHITELIST) == 0){
            suspicious_id = 8;
            if(httpRequestWhitelisted(unquoted_path) == 0 && httpRequestSuspiciousStr(unquoted_path) == 1){
                /*if regex matched*/
                int match_regex = suspicousHttpRequestRegexCheck(unquoted_path);
                if(match_regex){
                    logEvent(URL_EVENT);
                    END_CHECK_RETURN(suspicious_id)
                }
            }

            if(strchr(pheader->request.path,'.')){
                /*trip parameters*/
                char *question_mark = strchr(pheader->request.path,'?');
                if(question_mark != NULL)
                    *question_mark = 0;
                char *last_slash = strrchr(pheader->request.path,'/');
                if(question_mark != NULL)
                    *question_mark = '?';
                if(last_slash){
                    char file[256] = {0};
                    last_slash += 1;/*skip '/'*/
                    strncpySafe(file,last_slash,strlen(last_slash),sizeof(file));
                    char filename[200] = {0};
                    char extension[56] = {0};
                    char *p = strtok(file,".");
                    if(p)
                        strncpy(filename,p,sizeof(filename)-1);
                    p = strtok(NULL,".?");
                    if(p)
                        strncpy(extension,p,sizeof(extension)-1);
                    //LogMessage(LOG_DEBUG,"filename is %s,extension is %s\n",filename,extension);
                    suspicious_id = 9;
                    if(checkExtension(extension) && checkDirectDownloadKeywords(pheader->request.path) == 0 
                        && (question_mark == NULL || strchr(question_mark,'=') == NULL) && strlen(filename) < 10){
                        logEvent(URL_EVENT);
                        END_CHECK_RETURN(suspicious_id)
                    }
                    else if(isFilenameInWebshell(filename)){
                        logEvent(URL_EVENT);
                        END_CHECK_RETURN(suspicious_id)
                    }
                    else if(suspicousHttpPathRegexCheck(filename)){
                        /*reg match*/
                        logEvent(URL_EVENT);
                        END_CHECK_RETURN(suspicious_id)
                    }
                }
            }
        }
    #endif
    return 0;
}

/*0:no need to check any more*/
static int domain_filter(const char *domain)
{
    if(validateDomainFormat(domain))
        return 0;

    if(strstr(domain,".intranet.") != NULL)
        return 0;

    if(strncmp(domain+strlen(domain)-5,".arpa",5) == 0)/*5 = strlen(".arpa")*/
        return 0;
    if(strncmp(domain+strlen(domain)-6,".local",6) == 0)
        return 0;
    if(strncmp(domain+strlen(domain)-6,".guest",6) == 0)
        return 0;
    
    return 1;
    
}

static char *strchrFromEnd(char *start,char *end,char c)
{
    while(start < end){
        if(*end == c)
            return end;
        end--;
    }
    return NULL;
}

/*1:number
0: not number*/
static int isNumberString(const char *str)
{
    while(str){
        if(isdigit(*str++)){
            continue;
        }
        else{
            return 0;
        }
    }
    
    return atoi(str);
}

/*1:number
0: not number*/
static int isNumberStringWithLen(const char *str,uint16_t len)
{
    int i = 0;
    char *num = calloc(1,len+1);
    if(!num)
        return -1;
    char *p = num;
    while(str && i < len){
        i++;
        if(isdigit(*str)){
            *p++ = *str++;
            continue;
        }
        else{
            return 0;
        }
    }
    int ret = atoi(num);
    free(num);
    return ret;
}

static float getCharCountInString(const char *str,char c,uint16_t str_len)
{
    uint16_t i = 0;
    float cnt = 0;
    while(str && i < str_len){
        i++;
        if(*str++ == c)
            cnt++;
    }
    
    return cnt;
}

static int domainFrequencyHeuristicsCheck(const char *domain,uint16_t len)
{

    /*get how many times of each char appears in the part*/
    int i = 0;
    int j = 0;
    int k = 0;
    int duplicate_c = 0;
    int consonants_char_cnt = 0;
    float char_count = 0;
    float rate = 0;
    float entropy = 0;
    static char consonants[] = "bcdfghjklmnpqrstvwxyz";
    char set[512] = {0};
    while(i<len){
        k = 0;
        duplicate_c = 0;
        while(k<strlen(set)){
            if(set[k++] == *domain || k >= sizeof(set)-1){
                duplicate_c = 1;
                break;
            }
        }
        
        if(duplicate_c){
            i++;
            domain++;
            continue;
        }
        else
            set[k] = *domain;
        
        char_count = getCharCountInString(domain,*domain,len-i);
        rate = char_count/len;
        rate = (rate * log(rate)/log(2.0));
        entropy += rate;
        j = 0;
        #ifdef DEBUG
        printf("char '%c' count:%f,rate:%f,entropy:%f\n",*domain,char_count,rate,entropy);
        #endif
        while(j < strlen(consonants)){
            if(*domain == consonants[j]){
                consonants_char_cnt++;
                break;
            }
            j++;
        }
        i++;
        domain++;
    }
    entropy = -entropy;
    #ifdef DEBUG
    printf("entropy:%f,constant char cnt:%d\n",entropy,consonants_char_cnt);
    #endif
    if(entropy > 3.5 || consonants_char_cnt > 7){
        return 1;
    }
    
    return 0;
}

static int DomainChecker(msg_t *pkt)
{
    if(pkt->src_port != 53 && pkt->dst_port != 53){/*not dns packet*/
        return 0;
    }
    /*handle dns*/
    //printf("***********************************handle dns packet*******************************************\n");
    dns_header *dns_hdr = (dns_header *)pkt->url;
    dns_hdr->flags = ntohs(dns_hdr->flags);
    dns_hdr->questions = ntohs(dns_hdr->questions);
    dns_hdr->answers= ntohs(dns_hdr->answers);
    
    if(dns_hdr->questions > 0){
        /*get query*/
        static black_domain black_domains[MAX_DOMAIN_SIZE] = {{0}};
        int offset = 12;/*sizeof(dns_header)*/
        int dot_cnt = -1;
        int domain_parts_cnt = 0; /*how many parts splited by dot*/
        if(pkt->url_size> offset){
            int domain_len = 0;
            int size = 0;
            uint8_t *domain_start = (uint8_t *)pkt->url + offset;
            domain_segment sub_domain_pointer[128] = {{NULL,0}};
            //printf("query:%s\n",(char *)domain_start);
            #ifdef COPY_DOMAIN
            char domain[MAX_DOMAIN_LEN] = {0};
            while(*domain_start != '\0' && domain_len < MAX_DOMAIN_LEN-1){
                size = *domain_start;
                domain_start++;
                strncat(domain,domain_start,size);
                strcat(domain,".");
                dot_cnt++;
                if(dot_cnt < 128){
                    sub_domain_pointer[dot_cnt].start = domain + domain_len;
                    sub_domain_pointer[dot_cnt].len = size;
                }
                domain_len += size+1;
                domain_start += size;
            }
            domain_parts_cnt = dot_cnt + 1;
            
            offset += domain_len + 1;
            if(domain_len > 0 && domain[--domain_len] == '.')
                domain[domain_len] = 0;
            #else
            char *domain = domain_start;
            while(*domain_start != '\0' && domain_len < MAX_DOMAIN_LEN-1){
                size = *domain_start;
                *domain_start = '.';
                dot_cnt++;
                if(dot_cnt < 128){
                    sub_domain_pointer[dot_cnt].start = domain + domain_len + 1;
                    sub_domain_pointer[dot_cnt].len = size;
                }
                domain_len += size + 1;
                domain_start += size + 1;
            }
            domain += 1;/*skip first char*/
            domain_parts_cnt = dot_cnt + 1;
            offset += domain_len + 1;/*query class type*/
            --domain_len;/*not count on \0*/
            #endif
            
            /*check query*/
            //printf("domain len is %d,domain is %s\n",domain_len,domain);
            //str2Lower(domain);
            if(dot_cnt <= 0 || dot_cnt >= 128 || domain_len == 0)
                return 0;
            
            if(!domain_filter(domain))
                return 0;
            
            #ifdef USE_USER_WHITE_DOMAIN
            int domain_is_white = isDomainBelongToUserWhitelist(sub_domain_pointer,domain_parts_cnt);
            #else
            int domain_is_white = 0;
            #endif
            /*check flag*/
            if(dns_hdr->flags>>8 == 0x01){/*standary query*/
                /*get class and class type*/
                //printf("----------------standard query---------------\n");
                if(domain_is_white)
                    return 0;
                
                uint16_t query_type = ntohs(*(uint16_t *)((uint8_t *)dns_hdr+offset));
                uint16_t query_class = ntohs(*(uint16_t *)((uint8_t *)dns_hdr+offset+2));
                if(domain_parts_cnt > 2){
                    /*check last two or three parts of domain*/
                    char *sub_domain = NULL;
                    if(domain_parts_cnt > 3 && sub_domain_pointer[domain_parts_cnt-2].len <= 3){
                        sub_domain = sub_domain_pointer[domain_parts_cnt-3].start;
                    }
                    else{
                        sub_domain = sub_domain_pointer[domain_parts_cnt-2].start;
                    }
                    //printf("sub domain is %s\n",sub_domain);
                    if(!isDomainInWhitelist(sub_domain)){/*not in whitelist,check query frequency*/
                        static time_t sub_domain_sec = 0;
                        time_t now = time(NULL);
                        uint32_t index = getHashIndex(sub_domain,MAX_DOMAIN_SIZE);
                        if(now - sub_domain_sec > 24 * 60 * 60){/*over one day,reset/clear black_domains*/
                            memset(black_domains,0,sizeof(black_domains));
                            sub_domain_sec = now;
                        }
                        
                        if(black_domains[index].cnt < 1000){ 
                            black_domains[index].cnt++;
                        }
                        else{
                            static time_t last_dns_exhaustion = 0;
                            if(now - last_dns_exhaustion > 60){/*this domain has queried over 1000 times in one day,suspicous*/
                                last_dns_exhaustion = now;
                                logEvent(DOMAIN_EVENT);
                                logSuspiciousFlowEvent(pkt,SUSPICIOUS_DOMAIN_EVENT_NUM,"frequent dns request",sub_domain,domain,FREQUENCY_ANALYSIS_ALGORITHM);
                                END_CHECK
                            }
                            return 0;
                        }
                    }
                    else{
                        return 0;
                    }
                }
                
                if(query_type != 12 && query_type != 28 && query_class == 1){/*not PTR(transfer ip to domain) or IPV6 and this is internet query*/
                    /*check whether the dst ip or src ip in blacklist*/
                    int dst_is_black_ip = checkIpAddress(pkt->dst_ip);
                    if(dst_is_black_ip){
                        if(checkDomain(domain)){
                            logEvent(DOMAIN_EVENT);
                            logSuspiciousFlowEvent(pkt,SUSPICIOUS_DOMAIN_EVENT_NUM,"blacklist domain",domain,domain,STATIC_MATCH_ALGORITHM);
                            END_CHECK
                        }
                    }
                }
            }
            #ifdef USE_HEURISTICS
            else{
                if(dns_hdr->flags>>8 & 0x80){/*standard response*/
                    uint32_t resp_offset = offset + 4;/*skip query type and class total 4 bytes*/
                    //printf("----------------standard response---------------\n");
                    dns_response *resp = NULL;
                    if((uint8_t)dns_hdr->flags == 0x80){/*recursion available, no error*/
                        int got_ipv4 = 0;
                        while(resp_offset < pkt->url_size){
                            resp = (dns_response *)((uint8_t *)dns_hdr + resp_offset);
                            if(resp && ((ntohs(resp->name)>>8) & 0xc0) != 0  /*PTR*/
                                && ntohs(resp->query_type) == 0x0001){/*type A*/
                                    got_ipv4 = 1;
                                    break;
                            }
                            else{
                                resp_offset += 12 + ntohs(resp->dlen);
                            }
                        }
                        if(got_ipv4){
                            #ifdef __TEST__
                            char ip_addr[16] = {0};
                            inet_ntop(AF_INET,&resp->response_ip,ip_addr,sizeof(ip_addr));
                            resp->response_ip = ntohl(resp->response_ip);
                            //printf("response ip is %u(%s)\n",resp->response_ip,ip_addr);
                            #endif
                            if(domain_is_white){
                                /*add ip to user white ip list*/
                                addWhiteIpDynamicly(resp->response_ip,domain);
                                return 0;
                            }
                            
                            if(checkIpAddress(resp->response_ip)){
                                char ip_addr[16] = {0};
                                inet_ntop(AF_INET,&resp->response_ip,ip_addr,sizeof(ip_addr));
                                logEvent(IP_EVENT);
                                logSuspiciousFlowEvent(pkt,SUSPICIOUS_DOMAIN_EVENT_NUM,"the response ip belongs to blacklist",ip_addr,domain,STATIC_MATCH_ALGORITHM);
                                END_CHECK
                            }
                        }
                        
                    }
                    else if((uint8_t)dns_hdr->flags == 0x83){/*recursion available, no such name*/
                        char *p = sub_domain_pointer[domain_parts_cnt-1].start;
                        if(p){
                            if(isNumberString(p))
                                return 0;
                        }

                        int check_domain = 1;
                        if(domain_parts_cnt > 4){
                            int i = 0;
                            int num = 0;
                            while(i < 4){
                                if((num = isNumberStringWithLen(sub_domain_pointer[i].start,sub_domain_pointer[i].len)) && num < 256)
                                    i++;
                                else
                                    break;
                            }
                            if(i == 4){
                                check_domain = 0;
                            }
                        }
                        
                        //printf("last two parts:%s\n",sub_domain_pointer[domain_parts_cnt-2].start);
                        if(!check_domain){
                            return 0;
                        }
                        
                        uint32_t index = getHashIndex(sub_domain_pointer[domain_parts_cnt-2].start,MAX_DOMAIN_SIZE);
                        if(black_domains[index].cnt > 0){ 
                            return 0;
                        }
                        
                        if(checkDomainListed(domain,BLACKLIST) || checkDomainListed(domain,WHITELIST))
                            return 0;
                        
                        char *part = NULL;
                        int len = 0;
                        int i = 0;
                        if(domain_parts_cnt > 2){
                            if(sub_domain_pointer[0].len == 3 && strncmp(sub_domain_pointer[0].start,"www",3) != 0){
                                part = sub_domain_pointer[0].start;
                                len = sub_domain_pointer[0].len;
                            }
                            else{
                                part = sub_domain_pointer[1].start;
                                len = sub_domain_pointer[0].len;
                            }
                        }
                        else if(domain_parts_cnt == 2){
                            part = sub_domain_pointer[0].start;
                            len = sub_domain_pointer[0].len;
                        }
                        else{
                            part = domain;
                            len = domain_len;
                        }
                        
                        if(len <= 0)
                            return 0;
                        
                        while(i<len){
                            if(*(part + i) == '-'){
                                return 0;
                            }
                            i++;
                        }
                        
                        int ret = domainFrequencyHeuristicsCheck(part,len);
                        if(ret == 1){
                            *(part + len) = 0;
                            logEvent(DOMAIN_EVENT);
                            logSuspiciousFlowEvent(pkt,SUSPICIOUS_DOMAIN_EVENT_NUM,"DGA match",part,domain,HEURISTICS_ALGORITHM);
                            END_CHECK
                        }
                        
                    }
                }
            }
            #endif
        }
    }
        
}

static int ipWhitelistCheck(msg_t *pkt)
{
    int both_white = 0;
    
    if(!pkt->src_is_protected){
        both_white = isIpBelongToUserWhitelist(pkt->src_ip);
    }
    else{
        both_white = 1;
    }
    
    if(!pkt->dst_is_protected){
        both_white &= isIpBelongToUserWhitelist(pkt->dst_ip);
    }
    else{
        both_white &= 1;
    }
    
    return both_white;
}

/**
*@Description: SCE main entry,packet checker.if this packet is suspicous,log it,only trigger one event to log.
*@Paras: pkt
*@Return: 0:success
*@Author: Chad
*/
int suspiciousFlowChecker(msg_t *pkt)
{
    if(pkt == NULL)
        return 0;

    /*check ip*/
    uint32_t src_ip = pkt->src_ip;
    uint32_t dst_ip = pkt->dst_ip;
    static uint32_t last_suspicious_src_ip;
    static uint32_t last_suspicious_dst_ip;
    static time_t last_sec;
    is_white = 0;
    if(pkt->protocol == PROTO_TCP){
        if(pkt->tcp_syn_flag){/*ip address of tcp syn,only check the ip of tcp syn,no need to check ip of every tcp packet*/
            if(checkIpAddress(dst_ip)){
                time_t now = time(NULL);
                if(now == last_sec && dst_ip == last_suspicious_dst_ip){
                    /*in case of alert storm,ignore*/
                    return 0;
                }
                last_sec = now;
                char ip_addr[16] = {0};
                inet_ntop(AF_INET,&pkt->dst_ip,ip_addr,sizeof(ip_addr));
                logEvent(IP_EVENT);
                logSuspiciousFlowEvent(pkt,SUSPICIOUS_IP_EVENT_NUM,"destination ip is suspicious",ip_addr,"",STATIC_MATCH_ALGORITHM);
                END_CHECK
            }
            else if(checkIpAddress(src_ip) && dst_ip != 16777343){ /*and dst_ip != 127.0.0.1*/
                time_t now = time(NULL);
                if(now == last_sec && src_ip == last_suspicious_src_ip){
                    /*in case of alert storm,ignore*/
                    return 0;
                }
                last_sec = now;
                char ip_addr[16] = {0};
                inet_ntop(AF_INET,&pkt->src_ip,ip_addr,sizeof(ip_addr));
                logEvent(IP_EVENT);
                logSuspiciousFlowEvent(pkt,SUSPICIOUS_IP_EVENT_NUM,"source ip is suspicious",ip_addr,"",STATIC_MATCH_ALGORITHM);
                END_CHECK
            }
        }
    }

    /*if usr_size > 0,that means this packet is a http or dns protocol packet,so we need to dig it*/
    if(pkt->url_size > 6){
        if(pkt->url_size >= MAX_HANDLE_STR_LEN-1){
            LogMessage(LOG_NOTICE,"url or domain is too long,over %d bytes,ignore it...",MAX_HANDLE_STR_LEN);
            return -1;
        }
        #ifdef USE_USER_WHITE_DOMAIN
        if(ipWhitelistCheck(pkt)){
            #ifdef DEBUG
            char src_ip_addr[16] = {0};
            char dst_ip_addr[16] = {0};
            inet_ntop(AF_INET,&pkt->src_ip,src_ip_addr,sizeof(src_ip_addr));
            inet_ntop(AF_INET,&pkt->dst_ip,dst_ip_addr,sizeof(dst_ip_addr));
            printf("%s:whitelist ip pair:%s:%u=>%s:%u\n",__FUNCTION__,src_ip_addr,pkt->src_port,dst_ip_addr,pkt->dst_port);
            #endif
            return 0;
        }
        #endif
        
        if(pkt->protocol == PROTO_TCP){
            #ifndef DEBUG_SUSPICIOUS_FLOW
            if(!(pkt->fragment & STREAM_FIRST_REASSEMBLE_FRAGMENT))
                return 0;
            #endif
            /*or no need to copy,use pkt->url directly?*/
            static char http_data[MAX_HANDLE_STR_LEN] = {0};
            strncpySafe(http_data,pkt->url,pkt->url_size,sizeof(http_data));
            /*handle http protocol header*/
            static http_header_info http_header;
            memset(&http_header,0,sizeof(http_header));
            char *pRequest_line_end = NULL;
            if(strncmp(http_data,"HTTP/",5) == 0){/*begin with http/,http response,maybe*/
                int ret = checkHttpResponse(http_data);
                switch(ret){
                    case 0:
                        break;
                    case 1:
                        logSuspiciousFlowEvent(pkt,SUSPICIOUS_URL_EVENT_NUM,"response:suspicous content type",response_matched_suspicious_str,http_data,HTTP_ANOMALY_DETECTION);
                        break;
                    case 2:
                        logSuspiciousFlowEvent(pkt,SUSPICIOUS_URL_EVENT_NUM,"response contains sinkhole",response_matched_suspicious_str,http_data,HTTP_ANOMALY_DETECTION);
                        break;
                    case 3:
                        logSuspiciousFlowEvent(pkt,SUSPICIOUS_URL_EVENT_NUM,"response:suspicious title",response_matched_suspicious_str,http_data,HTTP_ANOMALY_DETECTION);
                        break;
                    default:
                        break;
                }
            }
            else if((pRequest_line_end = strstr(http_data,"\r\n")) != NULL){/*http request?*/
                char request_line[MAX_URL_LEN + 32] = {0};
                char http_method[16] = {0};
                char http_path[MAX_URL_LEN] = {0};
                if(pRequest_line_end - http_data > sizeof(request_line) - 1){
                    LogMessage(LOG_NOTICE,"http request line is too long,over %d bytes,ignore it...",MAX_URL_LEN);
                    return -1;
                }
                else{
                    /*try to get request line ,format is just like:method path HTTP/2.0*/
                    strncpySafe(request_line,http_data,pRequest_line_end - http_data,sizeof(request_line));
                    char *p;
                    int space_cnt = 0;
                    p = strtok(request_line," ");
                    if(p && strlen(p) < sizeof(http_method)){
                        strncpy(http_method,p,sizeof(http_method)-1);
                        space_cnt++;
                    }
                    else
                        return 0;
                    
                    p = strtok(NULL," ");
                    if(p && strlen(p) < sizeof(http_path)){
                        strncpy(http_path,p,sizeof(http_path)-1);
                        space_cnt++;
                    }
                    else
                        return 0;
                    
                    p = strtok(NULL," ");
                    if(p && strncmp(p,"HTTP/",5) == 0 && space_cnt == 2){/*make sure this is http request,got method and path already*/
                        //LogMessage(LOG_DEBUG,"check http packet...\n");
                        strncpySafe(http_header.request.method,http_method,strlen(http_method),sizeof(http_header.request.method));
                        strncpySafe(http_header.request.path,http_path,strlen(http_path),sizeof(http_header.request.path));
                        http_header.request.header = pRequest_line_end;
                        http_header.dst_ip = dst_ip;
                        http_header.dst_port = pkt->dst_port;
                        inet_ntop(AF_INET,&pkt->dst_ip,http_header.request.host,sizeof(http_header.request.host));
                        int ret = checkHttpRequest(&http_header);
                        if(ret != 0 && strlen(http_header.request.url) == 0){
                            if(http_header.request.path[0] != '/')
                                snprintf(http_header.request.url,sizeof(http_header.request.url),"%s",http_header.request.path);
                            else
                                snprintf(http_header.request.url,sizeof(http_header.request.url),"%s%s",http_header.request.host,http_header.request.path);
                        }
                        switch(ret){
                            case 0:
                                break;
                            case 1:
                                logSuspiciousFlowEvent(pkt,SUSPICIOUS_URL_EVENT_NUM,"request:suspicious host",http_header.request.host,http_data,HTTP_ANOMALY_DETECTION);
                                break;
                            case 2:
                                logSuspiciousFlowEvent(pkt,SUSPICIOUS_URL_EVENT_NUM,"request:no host found",http_header.request.path,http_data,HEURISTICS_ALGORITHM);
                                break;
                            case 3:
                                logSuspiciousFlowEvent(pkt,SUSPICIOUS_URL_EVENT_NUM,"request:path with http://xxx/,and xxx is not belong to whitelist",http_header.request.path,http_data,HTTP_ANOMALY_DETECTION);
                                break;
                            case 4:
                                logSuspiciousFlowEvent(pkt,SUSPICIOUS_URL_EVENT_NUM,"request:suspicious user agent",http_header.request.url,http_data,HTTP_ANOMALY_DETECTION);
                                break;
                            case 5:
                                logSuspiciousFlowEvent(pkt,SUSPICIOUS_URL_EVENT_NUM,"request:path with ://xxx/,and xxx is suspicious",http_header.request.path,http_data,HTTP_ANOMALY_DETECTION);
                                break;
                            case 6:
                                logSuspiciousFlowEvent(pkt,SUSPICIOUS_URL_EVENT_NUM,"request:connect method with suspicious path",http_header.request.url,http_data,HTTP_ANOMALY_DETECTION);
                                break;
                            case 7:
                                logSuspiciousFlowEvent(pkt,SUSPICIOUS_URL_EVENT_NUM,"request:suspicious url",http_header.request.url,http_data,HTTP_ANOMALY_DETECTION);
                                break;
                            case 8:
                                logSuspiciousFlowEvent(pkt,SUSPICIOUS_URL_EVENT_NUM,"request:suspicious regex matched the path",http_header.request.url,http_data,HTTP_ANOMALY_DETECTION);
                                break;
                            case 9:
                                logSuspiciousFlowEvent(pkt,SUSPICIOUS_URL_EVENT_NUM,"request:suspicious filename",http_header.request.url,http_data,HTTP_ANOMALY_DETECTION);
                                break;
                            default:
                                break;

                        }
                    }
                }
            }
        }
        else if(pkt->protocol == PROTO_UDP){
            DomainChecker(pkt);
        }
    }
    return 0;
}


/**
*@Description: initialize list(blacklist ,suspicious webshell or user agent),and read resource file,add the line to the list.
*@Paras: NULL
*@Return: 0:success
*@Author: Chad
*/
int holdTheSuspiciousDoor()
{
    if(initializeSuspiciousList() != 0)
        return -1;
    if(initializeWebshellList() != 0)
        return -1;
    if(initializeUaList() != 0)
        return -1;
    
    int err = 0;
    #ifdef USE_PLAIN_FILE
    err += lookupResourceFileAndAddResource2List(STATIC_RESOURCE_FILE_PATH,BLACKLIST);
    err += lookupResourceFileAndAddResource2List(STATIC_WEBSHELL_FILE_PATH,WEBSHELL);
    err += lookupResourceFileAndAddResource2List(STATIC_UA_FILE_PATH,USER_AGENT);
    #else
    char *start = (char *)&_binary_maltrails_csv_start;
    char *end = (char *)&_binary_maltrails_csv_end;
    err += loadResourceFile(start,end,BLACKLIST);
    
    start = (char *)&_binary_web_shells_txt_start;
    end = (char *)&_binary_web_shells_txt_end;
    err += loadResourceFile(start,end,WEBSHELL);
    
    start = (char *)&_binary_ua_txt_start;
    end = (char *)&_binary_ua_txt_end;
    err += loadResourceFile(start,end,USER_AGENT);
    #endif
    buildSuspicousUserAgentRegexStr();
    return err;
}


/**
*@Description: initialize list(whitelist),and read resource file,add the line to the list.
*@Paras: NULL
*@Return: 0:success
*@Author: Chad
*/
int holdTheFrontDoor()
{
    if(initializeWhiteList() != 0)
        return -1;
    
    int err = 0;
    #ifdef USE_PLAIN_FILE
    err += lookupResourceFileAndAddResource2List(STATIC_WHITELIST_FILE_PATH,WHITELIST);
    err += lookupResourceFileAndAddResource2List(STATIC_USER_WHITE_DOMAIN_FILE_PATH,USER_WHITE_DOMAIN);
    #else
    char *start = (char *)&_binary_whitelist_txt_start;
    char *end = (char *)&_binary_whitelist_txt_end;
    err += loadResourceFile(start,end,WHITELIST);
    
    start = (char *)&_binary_user_white_domain_txt_start;
    end = (char *)&_binary_user_white_domain_txt_end;
    err += loadResourceFile(start,end,USER_WHITE_DOMAIN);
    #endif
    
    return err;
}


#ifdef DEBUG
static void printArrayListInfo()
{
    int i = 0;
    int array_size = 0;
    int max_list_size = 0;
    int list_size = 0;
    match_ip_list *ip_node;
    while(i<MAX_IP_SIZE){
        list_size = 0;
        if(c_list_empty(&(black_ip_array[i].h_list))){
            i++;
            continue;
        }
        list_for_each_entry(ip_node, &(black_ip_array[i].h_list), h_list) {
            total_line_in_list++;
            list_size++;
        }
        if(list_size > max_list_size)
            max_list_size = list_size;
        array_size++;
        i++;
    }
    LogMessage(LOG_DEBUG,"ip array size is %d,used %d,max list size is %d\n",MAX_IP_SIZE,array_size,max_list_size);

    i= 0;
    array_size = 0;
    max_list_size = 0;
    list_size = 0;
    match_str_list *domain_node;
    while(i<MAX_DOMAIN_SIZE){
        list_size = 0;
        if(c_list_empty(&(black_domain_array[i].h_list))){
            i++;
            continue;
        }
        list_for_each_entry(domain_node, &(black_domain_array[i].h_list), h_list) {
            total_line_in_list++;
            list_size++;
        }
        if(list_size > max_list_size)
            max_list_size = list_size;
        array_size++;
        i++;
    }
    LogMessage(LOG_DEBUG,"domain array size is %d,used %d,max list size is %d\n",MAX_DOMAIN_SIZE,array_size,max_list_size);

    
    i= 0;
    array_size = 0;
    max_list_size = 0;
    list_size = 0;
    match_str_list *url_node;
    while(i<MAX_URL_SIZE){
        list_size = 0;
        if(c_list_empty(&(black_url_array[i].h_list))){
            i++;
            continue;
        }
        list_for_each_entry(url_node, &(black_url_array[i].h_list), h_list) {
            total_line_in_list++;
            list_size++;
        }
        if(list_size > max_list_size)
            max_list_size = list_size;
        array_size++;
        i++;
    }
    LogMessage(LOG_DEBUG,"url array size is %d,used %d,max list size is %d\n",MAX_URL_SIZE,array_size,max_list_size);

}

static void printGloableInfo()
{
    LogMessage(LOG_DEBUG,"total black ip: %u\n",black_ip_cnt);
    LogMessage(LOG_DEBUG,"total black domain: %u\n",black_domain_cnt);
    LogMessage(LOG_DEBUG,"total black url: %u\n",black_url_cnt);
    LogMessage(LOG_DEBUG,"total white ip: %u,white url: %u,white domain: %u\n",white_ip_cnt,white_url_cnt,white_domain_cnt);
    LogMessage(LOG_DEBUG,"total line in file: %u,total in list: %u\n",total_line_in_file,total_line_in_list);
    LogMessage(LOG_DEBUG,"max url len: %u,min url len: %u\n",max_black_url_len,min_black_url_len);
    LogMessage(LOG_DEBUG,"max domain len: %u,min domain len: %u\n",max_black_domain_len,min_black_domain_len);
    LogMessage(LOG_DEBUG,"web shell cnt: %u,user agent regex cnt:%u,user agent regex str len:%u\n",webshell_cnt,ua_cnt,user_agents_len);
    LogMessage(LOG_DEBUG,"user white domain cnt: %u,max domain len:%u\n",user_white_domain_cnt,max_user_white_domain_len);
}
#endif

#ifdef __DEBUG_AS_MAIN_THREAD__

#define TEST_RET(ret) do{\
    if(ret) printf("nonzero:match\n");else printf("zero:not match\n");\
}while(0);

void testEngine()
{
    msg_t msg;
    char ssip[] = "192.168.2.111";
    char ddip[] = "139.2.65.54";
    struct in_addr s;
    struct in_addr d;
    inet_pton(AF_INET, ssip, (void *)&s);
    inet_pton(AF_INET, ddip, (void *)&d);
    msg.src_ip = s.s_addr; /*network byte order 192.168.2.111*/
    msg.dst_ip = d.s_addr; /*139.2.65.54*/
    msg.protocol = PROTO_TCP;
    msg.dst_port = 80;
    msg.src_port = 80;
    msg.pkt_len = 12;
    strcpy(msg.url,"get php?id=/windows/systeeem.ini HTTP/1.1\r\n\
Host: best-protectforryou.net\r\n\
Connection: keep-alive\r\n\
Cache-Control: max-age=0,200\r\n\
Upgrade-Insecure-Requests: HTTP_HOST\r\n\
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) 404Searrch/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36\r\n\
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n\
Referer: https://www.baidu.com/link?url=1ZL2Ci5LXroWUwApVV0TEqeWUjuK5fk16TQHBr8ji-HLXC0krGK7d4Ks82WyryLEVgi6LMDdJ7ctbh5ibZ4Jpa&wd=&eqid=b7ae41a30001ea2700000005593e32af\r\n\
Accept-Encoding: gzip, deflate, sdch\r\n\
Accept-Language: zh-CN,zh;q=0.8\r\n\
Cookie: Hm_lvt_8e2a116daf0104a78d601f40a45c75b4=1497248477; Hm_lpvt_8e2a116daf0104a78d601f40a45c75b4=1497248477\r\n\r\n");

    //strcpy(msg.url,"get php?id=/windows/systeeem.ini HTTP/1.1\r\n""Host: best-protectforyou.net\r\n\r\n");

    msg.url_size = strlen(msg.url);
    suspiciousFlowChecker(&msg);
    
}
int main(int argc,char *argv[])
{
    int ret = 0;
    ret = holdTheSuspiciousDoor();
    if(ret < 0)
        return -1;
    ret = holdTheFrontDoor();
    if(ret < 0)
        return -1;
    
    #ifdef DEBUG
    LogMessage(LOG_INFO,"*************info below*************\n");
    printArrayListInfo();
    printGloableInfo();
    #endif

    #ifdef __TEST__
    LogMessage(LOG_INFO,"\n...init done,test search...\n");
    
    uint32_t ipaddr;
    //inet_pton(AF_INET,"219.255.13.77",&ipaddr);
    inet_pton(AF_INET,"204.11.56.48",&ipaddr);
    printf("ip in blacklist?\n");
    ret = isIpInBlacklist(ipaddr);
    TEST_RET(ret);
    
    printf("domain in blacklist?\n");
    ret = isDomainInBlacklist("best-protectforyou.net");
    TEST_RET(ret);
    
    printf("url in blacklist?\n");
    ret = isUrlInBlacklist("kwlbroadcast.com/9y878hia");
    TEST_RET(ret);
    
    printf("domain heuristic check\n");
    ret = domainHeuristic("nnnee3333333333333-333333333333333333333ee.nne.aa");
    TEST_RET(ret);
    
    printf("check domain\n");
    ret = checkDomain("www.baidu.com");
    TEST_RET(ret);
    printf("domain frequency check\n");
    ret = domainFrequencyHeuristicsCheck("www.baidu.com",13);
    TEST_RET(ret);
    
    printf("http content type check\n");
    ret = checkContentType("\r\nContent-Type: text/x-sh \r\n");
    TEST_RET(ret);
    
    uint32_t dip = 0;
    inet_pton(AF_INET,"219.255.13.78",&dip);
    printf("request host check\n");
    ret = checkRequestHost("abc.abcd.best-protectforyou.net",dip);
    TEST_RET(ret);
    
    printf("request in whitelist?\n");
    ret = httpRequestWhitelisted("/path/../images/abc.png");
    TEST_RET(ret);
    
    ret = suspicousHttpPathRegexCheck("test-fador-soame-inexisadtent-filade1.1acu1");
    TEST_RET(ret);
    
    ret = suspicousHttpRequestRegexCheck(".htadaccessadfa");
    TEST_RET(ret);

    char test_ua[] = "fda-adfaab404Searrchabc";
    ret = suspicousUserAgentRegexCheck(test_ua);
    TEST_RET(ret);
    
    char test_domain[] = "3www4test5tieba5baidu3com";
    char *domain_start = test_domain;
    char *domain = domain_start;
    int domain_len = 0;
    int size = 0;
    int dot_cnt = -1;
    domain_segment sub_domain_pointer[20] = {{NULL,0}};
    while(*domain_start != '\0' && domain_len < MAX_DOMAIN_LEN-1){
        size = *domain_start - '0';
        *domain_start = '.';
        dot_cnt++;
        if(dot_cnt < 128){
            sub_domain_pointer[dot_cnt].start = domain + domain_len + 1;
            sub_domain_pointer[dot_cnt].len = size;
        }
        domain_len += size + 1;
        domain_start += size + 1;
    }
    printf("domain in user whitelist?\n");
    ret = isDomainBelongToUserWhitelist(sub_domain_pointer,dot_cnt+1);
    TEST_RET(ret);
    
    printf("*************checker begin...\n");
    testEngine();
    #endif
    
    sceClean();

    return 0;
}
#endif


