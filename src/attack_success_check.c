/*
 *
 *  Created on: 2017-6-7
 *      Author: lzh
 */
     
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "dbapi.h"
#include <mysql/mysql.h>
#include <ctype.h>
#include <string.h>
#include "uthash.h"
#include "attack_success_check.h"


static node_t *http = NULL;
static node_t *ftp = NULL;
static node_t *dns = NULL;
static node_t *smtp = NULL;
static node_t *snmp = NULL;
static node_t *pop3 = NULL;
static node_t *imap = NULL;

/**
 *
 * [http]
 * [200]
 * key1,key2,key3,key4
 * [normal]
 * key1,key2,key3,key4
 *
 * [ftp]
 * [normal]
 * key1,key2,key3,key4,key5
 *
 * [dns]
 * [normal]
 * key1,key2,key3,key4,key5
 *
 */

static char * rmTransferChar(char *str)
{
    if(!str)
        return NULL;
    
    static char new_str[1024];
    memset(new_str,0,sizeof(new_str));
    size_t len = strlen(str);
    if(len > sizeof(new_str)){
        LogMessage(LOG_NOTICE,"this line is too long,we will not tranfer it...it might be cause some troubles\n");
        return str;
    }
    int i = 0;
    int idx = 0;
    while(i<len){
        if(str[i] == '\\')
            new_str[idx] = str[++i];
        else
            new_str[idx] = str[i];
        idx++;
        i++;
    }
    return new_str;
}

void PrintKeywordConfig()
{
	node_t *iter = NULL;
	printf("[INFO]Configured keywords for checking attack status\n");
	if (NULL != http)
	{
		printf("http list\n");
		iter = http;
		while (iter != NULL)
		{
			printf("%s->%s\n", iter->label, iter->keyword);
			iter = iter->next;
		}
		printf("\n");
	}
	if (NULL != ftp)
	{
		printf("ftp list\n");
		iter = ftp;
		while (iter != NULL)
		{
			printf("%s->%s\n", iter->label, iter->keyword);
			iter = iter->next;
		}
		printf("\n");
	}
	if (NULL != dns)
	{
		printf("dns list\n");
		iter = dns;
		while (iter != NULL)
		{
			printf("%s->%s\n", iter->label, iter->keyword);
			iter = iter->next;
		}
		printf("\n");
	}
	if (NULL != smtp)
	{
		printf("smtp list\n");
		iter = smtp;
		while (iter != NULL)
		{
			printf("%s->%s\n", iter->label, iter->keyword);
			iter = iter->next;
		}
		printf("\n");
	}
	if (NULL != snmp)
	{
		printf("snmp list\n");
		iter = snmp;
		while (iter != NULL)
		{
			printf("%s->%s\n", iter->label, iter->keyword);
			iter = iter->next;
		}
		printf("\n");
	}
	if (NULL != pop3)
	{
		printf("pop3 list\n");
		iter = pop3;
		while (iter != NULL)
		{
			printf("%s->%s\n", iter->label, iter->keyword);
			iter = iter->next;
		}
		printf("\n");
	}
	if (NULL != imap)
	{
		printf("imap list\n");
		iter = imap;
		while (iter != NULL)
		{
			printf("%s->%s\n", iter->label, iter->keyword);
			iter = iter->next;
		}
		printf("\n");
	}
}

int ParseKeywordConfig(const char* path)
{
#ifndef BUFLEN
#define BUFLEN 1024
#endif

	FILE *fp = fopen(path, "r");
	if (NULL == fp)
	{
		return -1;
	}

	int group = TYPE_NONE;
	char subgroup[BUFLEN] = {0};

	char line[BUFLEN] = {0};
	char *iter = NULL;
	char *end = NULL;
	while(NULL != fgets(line, BUFLEN, fp))
	{
		//skip leading spaces & tabs & newlines
		iter = line;
		while(isspace(*iter) && (*iter != '\0')) iter++;
		if (*iter == '\0') continue;
		if (*iter == '[')
		{
			end = iter;
			//skip leading [
			iter++;
			while((*end != ']') && ( *end != '\0')) end++;
			if (*end == '\0') continue;
			*end = '\0';
			if (strcasecmp(iter, HTTP_TAG) == 0)
				group = HTTP;
			else if(strcasecmp(iter, FTP_TAG) == 0)
				group = FTP;
			else if(strcasecmp(iter, DNS_TAG) == 0)
				group = DNS;
			else if(strcasecmp(iter, SMTP_TAG) == 0)
				group = SMTP;
			else if(strcasecmp(iter, SNMP_TAG) == 0)
				group = SNMP;
			else if(strcasecmp(iter, POP3_TAG) == 0)
				group = POP3;
			else if(strcasecmp(iter, IMAP_TAG) == 0)
				group = IMAP;
			else {
				//sub group including self-defined group and 'normal' group
				strcpy(subgroup, iter);
			}
		}
		else
		{
			//keys
			//split keys by comma
			//for each key, create a node
			//set the node keyword to keys separated here
			//set the node label to subgroup here
			//add node the the list according to group type
			char *key = NULL;
			char *delimiter = ",";
			char *ptr = iter;
			while (NULL != (key = strsep(&ptr, delimiter)))
			{
				//skip leading spaces
				while (isspace(*key) && (*key != '\0')) key++;
                
				if (*key == '\0') continue;
                
                //if(*key == '\\'){
                    key = rmTransferChar(key);
                //}
				//skip possibly padding \r\n
				end = key + strlen(key) - 1;
				while (isspace(*end) && (end != key)) end--;
                
				if (end == key) continue;

				node_t *node = (node_t*)malloc(sizeof(node_t));
				if (NULL != node) {
					node->keyword = (char*)malloc(end - key + 2);
					node->keyword[end - key + 1] = 0;
					strncpy(node->keyword, key, end - key + 1);
					strcpy(node->label, subgroup);
					switch (group) {
						case HTTP:{
							node->next = http;
							http = node;
							break;
						}
						case FTP:{
							node->next = ftp;
							ftp = node;
							break;
						}
						case DNS:{
							node->next = dns;
							dns = node;
							break;
						}
						case SMTP:{
							node->next = smtp;
							smtp = node;
							break;
						}
						case SNMP:{
							node->next = snmp;
							snmp = node;
							break;
						}
						case POP3:{
							node->next = pop3;
							pop3 = node;
							break;
						}
						case IMAP:{
							node->next = imap;
							imap = node;
							break;
						}
						default: {
							free(node->keyword);
							free(node);
						}
					}//end-of-switch
				}
			}//end-of-while
		}//end-of-else
	}
	fclose(fp);
    
    #ifdef DEBUG
	PrintKeywordConfig();
    #endif
	return 0;
}

static int IsHttp(int sp, int dp)
{
	int ports[132] = {
			36,80,81,82,83,84,85,86,87,88,
			89,90,311,383,555,591,593,631,801,808,
			818,901,972,1158,1220,1414,1533,1741,1830,1942,
			2231,2301,2381,2578,2809,2980,3029,3037,3057,3128,
			3443,3702,4000,4343,4848,5000,5117,5250,5600,5814,
			6080,6173,6988,7000,7001,7005,7071,7144,7145,7510,
			7770,7777,7778,7779,8000,8001,8008,8014,8015,8020,
			8028,8040,8080,8081,8082,8085,8088,8090,8118,8123,
			8180,8181,8182,8222,8243,8280,8300,8333,8344,8400,
			8443,8500,8509,8787,8800,8888,8899,8983,9000,9002,
			9060,9080,9090,9091,9111,9290,9443,9447,9710,9788,
			9999,10000,11371,12601,13014,15489,19980,29991,33300,34412,
			34443,34444,40007,41080,44449,50000,50002,51423,53331,55252,
			55555,56712
	};
	int idx = 0;
	for (; idx < 132; idx++)
	{
		if (ports[idx] == sp || ports[idx] == dp)
		{
			return 1;
		}
	}
	return 0;
}
static int IsFtp(int sp, int dp)
{
	int ports[2] = {20, 21};
	int idx = 0;
	for (; idx < 2; idx++)
	{
		if (ports[idx] == sp || ports[idx] == dp)
		{
			return 1;
		}
	}
	return 0;
}
static int IsDns(int sp, int dp)
{
	if (53 == sp || 53 == dp)
		return 1;
	return 0;
}
static int IsSmtp(int sp, int dp)
{
	int ports[4] = {25, 2525, 587, 3535};
	int idx = 0;
	for (; idx < 4; idx++)
	{
		if (ports[idx] == sp || ports[idx] == dp)
			return 1;
	}
	return 0;
}
static int IsSnmp(int sp, int dp)
{
	int ports[3] = {161, 162, 199};
	int idx = 0;
	for (; idx < 3; idx++)
	{
		if (ports[idx] == sp || ports[idx] == dp)
			return 1;
	}
	return 0;
}
static int IsPop3(int sp, int dp)
{
	if (110 == sp || 110 == dp)
		return 1;
	return 0;
}
static int IsImap(int sp, int dp)
{
	int ports[2] = {220, 143};
	int idx = 0;
	for (; idx < 2; idx++)
	{
		if (ports[idx] == sp || ports[idx] == dp)
			return 1;
	}
	return 0;
}

static inline const char *GetProtoType(int ip_proto)
{
	switch (ip_proto)
	{
	case 4:
		return "ICMP";
	case 7:
		return "TCP";
	case 6:
		return "UDP";
	default:
		return "NONE";
	}
}

static char *success_attack_proto_type[] = {
	HTTP_TAG,
	FTP_TAG,
	DNS_TAG,
	SMTP_TAG,
	SNMP_TAG,
	POP3_TAG,
	IMAP_TAG,
	"N/A"
};

struct _matched_packet_flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    u_short src_port;
    u_short dst_port;
};

typedef struct _success_match_info {
    struct _matched_packet_flow_key key;
    uint8_t match_label;
    uint8_t match_keyword;
    uint8_t is_matched;
    time_t timestamp;
    #ifdef _DEBUG_
    char matched_label[32*5];
    char matched_keyword[128*16];
    #else
    char matched_label[32];
    char matched_keyword[128];
    #endif
	UT_hash_handle hh;
}success_match_info;

static success_match_info *attack_success_match_info;

/*this is the debug function for httpAttackSuccessCheck, it will not break out even if matched label or keyword,required by HuangPengJiang*/
static int httpAttackSuccessCheckForDebug(msg_t* msg,char *matched_label,char *matched_keyword)
{
    /*consider below match situations:
        a:first response packet comes first,
            1,it only contains label that will be matched;
            2,it contains both label and keyword which will be matched;
            3,next response packets come then and it contains keyword or not.
        b:next response packets come first and then received the first response packet.
        */
    if(http == NULL)
        return 0;
    
    if(msg->url_size < 6)
        return 0;
    
	static int hash_list_len = 0;
	int match_label = 0;
	int match_keyword = 0;
    success_match_info *node = NULL;
    struct _matched_packet_flow_key key;
    key.src_ip = msg->src_ip;
    key.src_port = msg->src_port;
    key.dst_ip = msg->src_port;
    key.dst_port = msg->dst_port;
    /*if we have reassembled the packet,we could wipe this list off*/
	HASH_FIND(hh, attack_success_match_info, &key, sizeof(key), node);
	if (NULL != node)
	{
	    if(node->is_matched){
            /*update the timestamp if nessesary*/
            return 0;
        }
	    match_label = node->match_label;
	    match_keyword = node->match_keyword;
	}
    else{
        if(hash_list_len > 10000){
            success_match_info *free_node = NULL,*tmp_node =NULL;
            time_t now = time(NULL);
        	HASH_ITER(hh, attack_success_match_info, free_node, tmp_node) {
                if(free_node->is_matched || now - free_node->timestamp > 3600){
            		HASH_DEL(attack_success_match_info, free_node);
            		free(free_node);
                    hash_list_len--;
                }
            }
            if(hash_list_len > 5000){
                int free_node_cnt = hash_list_len/2;
            	HASH_ITER(hh, attack_success_match_info, free_node, tmp_node) {
                    if(free_node_cnt <= 0)
                        break;
            		HASH_DEL(attack_success_match_info, free_node);
            		free(free_node);
                    hash_list_len--;
                    free_node_cnt--;
                }
            }
        }
		node = (success_match_info*)calloc(1,sizeof(success_match_info));
        if(node == NULL)
            return 0;
        node->key = key;
        node->timestamp = time(NULL);
        HASH_ADD(hh, attack_success_match_info, key, sizeof(key), node);
        hash_list_len++;
    }

    /*notice:all of the packets in this stream might be disordered*/
    if(msg->fragment & STREAM_FIRST_NORMAL_FRAGMENT){
        if(!match_label){
            char *split = strstr(msg->url,"\r\n\r\n");
            char *end = msg->url + msg->url_size;
	        node_t *iter = http;
            char *got_lable_match = NULL;
            char *got_keyword_match = NULL;
            while(iter != NULL){
                /*we assume that the label is mutex each other,that is say only one label&keyword pair will be matched,
                                so ,if matched,we will break out to simplify the process,otherwise,we need to modify the node struct*/
                if(split){
                    /*this packet contains both header and body*/
		            if (strcmp(iter->label, "normal") != 0){
                        //if(!match_keyword && split < end - 4){
                        if(split < end - 4){
                            got_keyword_match = strcasestr(split+4,iter->keyword);
                            if(got_keyword_match){
                                #ifdef DEBUG
                                printf("=========first packet matched keyword:%s===========\n",iter->keyword);
                                #endif
                                node->match_keyword = 1;
                                size_t keyword_len = strlen(node->matched_keyword);
                                snprintf(node->matched_keyword+keyword_len,sizeof(node->matched_keyword)-keyword_len,"%s,",iter->keyword);
                                match_keyword = 1;
                            }
                        }
                        //if(!got_lable_match){
                            got_lable_match = strstr(msg->url, iter->label);
                            if(got_lable_match && got_lable_match < split){
                                node->match_label = 1;
                                size_t label_len = strlen(node->matched_label);
                                if(strstr(node->matched_label,iter->label) == NULL){
                                    #ifdef DEBUG
                                    printf("=========first packet matched label:%s=============\n",iter->label);
                                    #endif
                                    snprintf(node->matched_label+label_len,sizeof(node->matched_label)-label_len,"%s,",iter->label);
                                }
                                match_label = 1;
                            }
                        //}
                        if(match_label && match_keyword){
                            //break;
                        }
                    }
                    else{
                        got_keyword_match = strcasestr(msg->url,iter->keyword);
                        if(got_keyword_match){
                            #ifdef DEBUG
                            printf("=========first packet matched keyword:%s===========\n",iter->keyword);
                            #endif
                            node->match_keyword = 1;
                            size_t keyword_len = strlen(node->matched_keyword);
                            snprintf(node->matched_keyword+keyword_len,sizeof(node->matched_keyword)-keyword_len,"%s,",iter->keyword);
                            match_keyword = 1;
                            node->match_label = 1;
                            size_t label_len = strlen(node->matched_label);
                            if(strstr(node->matched_label,iter->label) == NULL)
                                snprintf(node->matched_label+label_len,sizeof(node->matched_label)-label_len,"%s,",iter->label);
                            match_label = 1;
                            //break;
                        }
                    }
                }
                else{
                    /*header too long? no body,only check label*/
		            if (strcmp(iter->label, "normal") != 0){
                        got_lable_match = strstr(msg->url, iter->label);
                        if(got_lable_match){
                            node->match_label = 1;
                            size_t label_len = strlen(node->matched_label);
                            if(strstr(node->matched_label,iter->label) == NULL){
                                #ifdef DEBUG
                                printf("=========first packet matched label:%s=============\n",iter->label);
                                #endif
                                snprintf(node->matched_label+label_len,sizeof(node->matched_label)-label_len,"%s,",iter->label);
                            }
                            match_label = 1;
                            //break;
                        }
                    }
                }
			    iter = iter->next;
            }
        }
    }
    else if(msg->fragment & STREAM_NEXT_NORMAL_FRAGMENT){
        if(!match_keyword){
	        node_t *iter = http;
            char *got_keyword_match = NULL;
            while(iter != NULL){
                got_keyword_match = strcasestr(msg->url,iter->keyword);
                if(got_keyword_match){
                    #ifdef DEBUG
                    printf("==========next packet matched keyword:%s============\n",iter->keyword);
                    #endif
                    node->match_keyword = 1;
                    size_t keyword_len = strlen(node->matched_keyword);
                    snprintf(node->matched_keyword+keyword_len,sizeof(node->matched_keyword)-keyword_len,"%s,",iter->keyword);
                    match_keyword = 1;
                    //if(!match_label && strcmp(iter->label, "normal") == 0){
                    if(strcmp(iter->label, "normal") == 0){
                        node->match_label = 1;
                        size_t label_len = strlen(node->matched_label);
                        if(strstr(node->matched_label,iter->label) == NULL)
                            snprintf(node->matched_label+label_len,sizeof(node->matched_label)-label_len,"%s,",iter->label);
                        match_label = 1;
                        //break;
                    }
                }
			    iter = iter->next;
            }
        }
    }

    if(match_label && match_keyword){
        #ifdef DEBUG
        printf("================matched==================\n");
        #endif
        node->is_matched = 1;
        strncpy(matched_label,node->matched_label,32*5-1);
        strncpy(matched_keyword,node->matched_keyword,128*16-1);
        return 1;
    }
    
    return 0;
}

static int httpAttackSuccessCheck(msg_t* msg,char *matched_label,char *matched_keyword)
{
    /*consider below match situations:
        a:first response packet comes first,
            1,it only contains label that will be matched;
            2,it contains both label and keyword which will be matched;
            3,next response packets come then and it contains keyword or not.
        b:next response packets come first and then received the first response packet.
        */
    #ifdef _DEBUG_
    return httpAttackSuccessCheckForDebug(msg,matched_label,matched_keyword);
    #endif
    if(http == NULL)
        return 0;
    
    if(msg->url_size < 6)
        return 0;
    
	static int hash_list_len = 0;
	int match_label = 0;
	int match_keyword = 0;
    success_match_info *node = NULL;
    struct _matched_packet_flow_key key;
    key.src_ip = msg->src_ip;
    key.src_port = msg->src_port;
    key.dst_ip = msg->src_port;
    key.dst_port = msg->dst_port;
    /*if we have reassembled the packet,we could wipe this list off*/
	HASH_FIND(hh, attack_success_match_info, &key, sizeof(key), node);
	if (NULL != node)
	{
	    if(node->is_matched){
            /*update the timestamp if nessesary*/
            return 0;
        }
	    match_label = node->match_label;
	    match_keyword = node->match_keyword;
	}
    else{
        if(hash_list_len > 10000){
            success_match_info *free_node = NULL,*tmp_node =NULL;
            time_t now = time(NULL);
        	HASH_ITER(hh, attack_success_match_info, free_node, tmp_node) {
                if(free_node->is_matched || now - free_node->timestamp > 3600){
            		HASH_DEL(attack_success_match_info, free_node);
            		free(free_node);
                    hash_list_len--;
                }
            }
            if(hash_list_len > 5000){
                int free_node_cnt = hash_list_len/2;
            	HASH_ITER(hh, attack_success_match_info, free_node, tmp_node) {
                    if(free_node_cnt <= 0)
                        break;
            		HASH_DEL(attack_success_match_info, free_node);
            		free(free_node);
                    hash_list_len--;
                    free_node_cnt--;
                }
            }
        }
		node = (success_match_info*)calloc(1,sizeof(success_match_info));
        if(node == NULL)
            return 0;
        node->key = key;
        node->timestamp = time(NULL);
        HASH_ADD(hh, attack_success_match_info, key, sizeof(key), node);
        hash_list_len++;
    }

    /*notice:all of the packets in this stream might be disordered*/
    if(msg->fragment & STREAM_FIRST_NORMAL_FRAGMENT){
        if(!match_label){
            char *split = strstr(msg->url,"\r\n\r\n");
            char *end = msg->url + msg->url_size;
	        node_t *iter = http;
            char *got_lable_match = NULL;
            char *got_keyword_match = NULL;
            while(iter != NULL){
                /*we assume that the label is mutex each other,that is say only one label&keyword pair will be matched,
                                so ,if matched,we will break out to simplify the process,otherwise,we need to modify the node struct*/
                if(split){
                    /*this packet contains both header and body*/
		            if (strcmp(iter->label, "normal") != 0){
                        if(!match_keyword && split < end - 4){
                            got_keyword_match = strcasestr(split+4,iter->keyword);
                            if(got_keyword_match){
                                #ifdef DEBUG
                                printf("=========first packet matched keyword:%s===========\n",iter->keyword);
                                #endif
                                node->match_keyword = 1;
                                strcpy(node->matched_keyword,iter->keyword);
                                match_keyword = 1;
                            }
                        }
                        if(!got_lable_match){
                            got_lable_match = strstr(msg->url, iter->label);
                            if(got_lable_match && got_lable_match < split){
                                #ifdef DEBUG
                                printf("=========first packet matched label:%s=============\n",iter->label);
                                #endif
                                node->match_label = 1;
                                strcpy(node->matched_label,iter->label);
                                match_label = 1;
                            }
                        }
                        if(match_label && match_keyword){
                            break;
                        }
                    }
                    else{
                        got_keyword_match = strcasestr(msg->url,iter->keyword);
                        if(got_keyword_match){
                            #ifdef DEBUG
                            printf("=========first packet matched keyword:%s===========\n",iter->keyword);
                            #endif
                            node->match_keyword = 1;
                            strcpy(node->matched_keyword,iter->keyword);
                            match_keyword = 1;
                            node->match_label = 1;
                            strcpy(node->matched_label,iter->label);
                            match_label = 1;
                            break;
                        }
                    }
                }
                else{
                    /*header too long? no body,only check label*/
		            if (strcmp(iter->label, "normal") != 0){
                        got_lable_match = strstr(msg->url, iter->label);
                        if(got_lable_match){
                            #ifdef DEBUG
                            printf("=========first packet matched label:%s=============\n",iter->label);
                            #endif
                            node->match_label = 1;
                            strcpy(node->matched_label,iter->label);
                            match_label = 1;
                            break;
                        }
                    }
                }
			    iter = iter->next;
            }
        }
    }
    else if(msg->fragment & STREAM_NEXT_NORMAL_FRAGMENT){
        if(!match_keyword){
	        node_t *iter = http;
            char *got_keyword_match = NULL;
            while(iter != NULL){
                got_keyword_match = strcasestr(msg->url,iter->keyword);
                if(got_keyword_match){
                    #ifdef DEBUG
                    printf("==========next packet matched keyword:%s============\n",iter->keyword);
                    #endif
                    node->match_keyword = 1;
                    strcpy(node->matched_keyword,iter->keyword);
                    match_keyword = 1;
                    if(!match_label && strcmp(iter->label, "normal") == 0){
                        node->match_label = 1;
                        strcpy(node->matched_label,iter->label);
                        match_label = 1;
                        break;
                    }
                }
			    iter = iter->next;
            }
        }
    }

    if(match_label && match_keyword){
        #ifdef DEBUG
        printf("================matched==================\n");
        #endif
        node->is_matched = 1;
        strncpy(matched_label,node->matched_label,31);
        strncpy(matched_keyword,node->matched_keyword,127);
        return 1;
    }
    
    return 0;
}

static int otherProtoAttackSuccessCheck(char *data,node_t *match_list,char *matched_label,char *matched_keyword)
{
    int matched = 0;
    node_t *iter = match_list;
	while (NULL != iter)
	{
		if (strcmp(iter->label, "normal") != 0)
		{
			if (strstr(data,iter->label) && strcasestr(data, iter->keyword))
			{
				matched = 1;
                strncpy(matched_label,iter->label,31);
                strncpy(matched_keyword,iter->keyword,127);
				break;
			}
		}
		else
		{
			if (strcasestr(data, iter->keyword))
			{
				matched = 1;
                strncpy(matched_label,iter->label,31);
                strncpy(matched_keyword,iter->keyword,127);
				break;
			}
		}
		iter = iter->next;
	}
    
    return matched;
}

static uint64_t selectAsUint64(MYSQL *pConn,char *sql)
{
    MYSQL_RES *mysql_res;
    MYSQL_ROW tuple;
    uint64_t ret = 0;

    if(ExecuteSql(pConn,sql) != 0)
        return ret;

    mysql_res = mysql_store_result(pConn);
    if(mysql_res){
        uint32_t num = mysql_num_rows(mysql_res);
        if(num == 0)
            return 0;

        if(tuple = mysql_fetch_row(mysql_res)){
            if(tuple[0] != NULL)
                sscanf(tuple[0],"%lu",&ret);
        }
        FreeResult(pConn,mysql_res);
    }

    return ret;
}

void AttackSuccessCheck(msg_t* msg)
{
#ifndef SQLLEN
#define SQLLEN 1024
#endif

	if (msg->url_size == 0)
		return;
    if(msg->match_rule == 0)
        return;
    
    int proto = TYPE_NONE;
	int matched = 0;
    #ifdef _DEBUG_
    char matched_label[32*5] = {0};
    char matched_keyword[128*16] = {0};
    #else
    char matched_label[32] = {0};
    char matched_keyword[128] = {0};
    #endif
    
	if (IsHttp(msg->src_port, msg->dst_port))
	{
        proto = HTTP;
        matched = httpAttackSuccessCheck(msg,matched_label,matched_keyword);
	}
	if (!matched && (NULL != ftp) && IsFtp(msg->src_port, msg->dst_port))
	{
        proto = FTP;
        matched = otherProtoAttackSuccessCheck(msg->url,ftp,matched_label,matched_keyword);
	}
	if (!matched && (NULL != dns) && IsDns(msg->src_port, msg->dst_port))
	{
        proto = DNS;
        matched = otherProtoAttackSuccessCheck(msg->url,dns,matched_label,matched_keyword);
	}
	if (!matched && (NULL != snmp) && IsSnmp(msg->src_port, msg->dst_port))
	{
        proto = SNMP;
        matched = otherProtoAttackSuccessCheck(msg->url,snmp,matched_label,matched_keyword);
	}
	if (!matched && (NULL != smtp) && IsSmtp(msg->src_port, msg->dst_port))
	{
        proto = SMTP;
        matched = otherProtoAttackSuccessCheck(msg->url,smtp,matched_label,matched_keyword);
	}
	//if it's POP3 and pop3 is not null, go ahead
	if (!matched && (NULL != pop3) && IsPop3(msg->src_port, msg->dst_port))
	{
        proto = POP3;
        matched = otherProtoAttackSuccessCheck(msg->url,pop3,matched_label,matched_keyword);
	}
	//if it's IMAP and imap is not null, go ahead
	if (!matched && (NULL != imap) && IsImap(msg->src_port, msg->dst_port))
	{
        proto = IMAP;
        matched = otherProtoAttackSuccessCheck(msg->url,imap,matched_label,matched_keyword);
	}

	if (matched)
	{
		//if matched, check wether its counterpart is there in table portrait, if yes, set the table row status to SUCCESS(1)
		//if not in table portrait, check whether is event/iphdr table, if there, generate a entry in matched_table
		//TODO: update portrait to set portrait row status to SUCCESS(1) if a counterpart is found in matched_table when inserting
		//a entry in table portrait
    	static MYSQL *conn = NULL;
    	char sql[SQLLEN] = {0};
		if (NULL == conn)
		{
			conn = CreateDBConn();
		}
		else if (!IsDBConnActive(conn))
		{
			CloseDBConn(conn);
			conn = CreateDBConn();
		}
		if (NULL != conn)
		{
		    snprintf(sql,sizeof(sql),"select id from keyword_matched where src_ip = %u and src_port = %u and dst_ip = %u and dst_port = %u and protocol = '%s'",
                ntohl(msg->src_ip), msg->src_port, ntohl(msg->dst_ip), msg->dst_port, GetProtoType(msg->protocol));
            uint64_t id = selectAsUint64(conn,sql);
			if (id > 0){
    			snprintf(sql,sizeof(sql),"update keyword_matched set timestamp = now() where id = %lu",id);
    			if (ExecuteSql(conn, sql) != 0)
    			{
    				LogMessage(LOG_ERR, "MySQL error(%s): %s", sql, mysql_error(conn));
    			}
            }
            else{
    			sprintf(sql, "INSERT INTO `keyword_matched`(src_ip, src_port, dst_ip, dst_port, protocol,app_proto,label,keyword,timestamp) "
    					"VALUES(%u, %u, %u, %u, '%s', '%s','%s','%s',from_unixtime(%u))",
    					ntohl(msg->src_ip), msg->src_port, ntohl(msg->dst_ip), msg->dst_port, GetProtoType(msg->protocol),
    					success_attack_proto_type[proto],matched_label,matched_keyword,(unsigned int)time(NULL));
    			if (ExecuteSql(conn, sql) != 0)
    			{
    				LogMessage(LOG_ERR, "MySQL error(%s): %s", sql, mysql_error(conn));
    			}

            }
		}
	}//end-of-match
}


#ifdef __DEBUG_ATTACK_CHECK_AS_MAIN__

int main(int argc,char *argv[])
{
    return 0;
}

#endif
