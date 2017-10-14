
#ifndef __SUSPICIOUS_IP_DOMAIN_URL_ALERT__
#define __SUSPICIOUS_IP_DOMAIN_URL_ALERT__

#include "c_list.h"
#include "common.h"

#define TRUE 1
#define FALSE 0


#define STATIC_RESOURCE_FILE_PATH "/opt/psi_nids/maltrails.csv"
#define STATIC_WHITELIST_FILE_PATH "/opt/psi_nids/whitelist.txt"
#define STATIC_WEBSHELL_FILE_PATH "/opt/psi_nids/web_shells.txt"
#define STATIC_USER_WHITE_DOMAIN_FILE_PATH "/opt/psi_nids/user_white_domain.txt"
#define STATIC_UA_FILE_PATH "/opt/psi_nids/ua.txt" /*user agent file*/
#define MAX_IP_SIZE 65536 /*ip array size,255*255*/
#define MAX_DOMAIN_SIZE 43853 /*domain array size,prime number*/
#define MAX_URL_SIZE 21911 /*url array size,prime number*/
#define MAX_WHITE_IP_SIZE 1024 /*white ip array size*/
#define MAX_WHITE_DOMAIN_SIZE 10949 /*domain array size,prime number*/
#define MAX_WHITE_URL_SIZE 5471 /*url array size,prime number*/
#define MAX_WEBSHELL_SIZE 1024
#define IP_STR 0
#define DOMAIN_STR 1
#define URL_STR 2
#define NULL_STR 3
#define WHITELIST 0
#define BLACKLIST 1
#define WEBSHELL 2
#define USER_AGENT 3
#define USER_WHITE_DOMAIN 4
#define IP_EVENT 0
#define DOMAIN_EVENT 1
#define URL_EVENT 2
#define NULL_EVENT 3
#define IP_EVENT_STR "suspicious ip"
#define DOMAIN_EVENT_STR "suspicious domain"
#define URL_EVENT_STR "suspicious link"
#define UNKNOWN_EVENT_STR "unknown event"
#define HTTP_REQUEST_EVENT_STR "suspicious http request"
#define HTTP_RESPONSE_EVENT_STR "suspicious http response"
#define SUSPICIOUS_DOMAIN_LENGTH_THRESHOLD 24
#define MAX_SUSPICIOUS_DOMAIN_LENGTH 1024

#define MAX_HOST_LEN 128
#define MAX_DOMAIN_LEN 512
#define MAX_URL_LEN 896
#define MAX_HANDLE_STR_LEN 4096

enum {
    SUSPICIOUS_IP_EVENT_NUM = 1,
    SUSPICIOUS_DOMAIN_EVENT_NUM = 2,
    SUSPICIOUS_URL_EVENT_NUM = 4,
    SUSPICIOUS_MAX_EVENT_NUM
};


typedef struct __black_domain {
		int cnt; /*domain query count*/
}black_domain;

#pragma pack(1)

typedef struct _dns_header
{
    uint16_t id;
    uint16_t flags;
    uint16_t questions;
    uint16_t answers;
    uint16_t authorities;
    uint16_t additionals;
} dns_header;

typedef struct _dns_response
{
    uint16_t name;
    uint16_t query_type;
    uint16_t query_class;
    uint32_t ttl;
    uint16_t dlen;
    uint32_t response_ip;
} dns_response;

#pragma pack()

typedef struct _sub_domain {
    char *start;
    uint16_t len;
}domain_segment;

typedef struct _match_ip_address {
		uint32_t ip; /*white ip address,integer*/
		struct list_head h_list;
}match_ip_list;


typedef struct _match_str_list {
		char *match_str; /*pointer to the match string*/
		struct list_head h_list;
}match_str_list;


typedef struct _http_response {
    char user_agent[128];
    char content_type[128];
}http_response;

typedef struct _http_request {
    char method[16];
    char path[MAX_URL_LEN];
    char host[MAX_DOMAIN_LEN];
    char url[MAX_URL_LEN];
    char *header;
}http_request;

typedef struct _http_header_info {
    http_request request;
    http_response response;
    u_short dst_port;
    u_short src_port;
    uint32_t src_ip;
    uint32_t dst_ip;
} http_header_info;

typedef struct _five_meta_array {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t protocol;
} five_meta_array;

int suspiciousFlowChecker(msg_t *pkt);
int holdTheSuspiciousDoor();
int holdTheFrontDoor();


#endif
