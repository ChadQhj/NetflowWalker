
#ifndef _PORT_FLOW_STATISTICS_
#define _PORT_FLOW_STATISTICS_

#include "common.h"
#include "uthash.h"

#define MAX_PORT_NUM 65536
#define PORT_QUEUE_BACKLOG 512
#define WAIT_QUEUE_BACKLOG 64 /*if use one thread update database,this is max len of the buffer queue*/
#define UPDATE_INTERVAL_TIME 2 /*if use one thread update database perioly,this is the interval time*/
//#define MAX_FLOW_SIZE 1024*1024 /*1MByte,update to db if the total size over it*/
#define MAX_FLOW_SIZE 1024 /*1KByte for test*/
#define MAX_OUTER_IP_NUM 5
#define DAY_COUNT_INTERVAL 7
#define HOUR_COUNT_INTERVAL 24
#define TRUE 1
#define FALSE 0

typedef struct _time_format {
    u_short year;
    u_short month;
    u_short day;
    u_short hour;
    u_short wday;
}time_format;

struct statistics_meta_info {
    u_short port;  /*port number*/
    //uint32_t protocol; /*protocol,tcp,udp,or ip*/
    uint32_t property_ip; /*property ip or internal ip*/
};

typedef struct _port_flow_info {
    struct statistics_meta_info metadata;
    time_format hour_time; /*time,count by hour*/
    uint64_t upstream; /*the bytes of upstream of this metadata*/
    uint64_t downstream; /*the bytes of downstream of this metadata*/
    uint32_t outer_ips[MAX_OUTER_IP_NUM]; /*external ips*/
    u_short outer_ips_index; /*the index to outer_ips*/
	UT_hash_handle hh;
}port_flow;


typedef struct _sync_port_flow_info {
    port_flow *backlog_port;
    pthread_mutex_t backlog_lock;
    uint32_t tcp_backlog_index;
    uint32_t udp_backlog_index;
    uint32_t ip_backlog_index;
    uint32_t *backlog_index;
}port_flow_sync;

struct _day_stream {
    uint32_t week_day; /*day of a week,0-6*/
    uint64_t upstream; 
    uint64_t downstream;
};

struct _hour_stream {
    uint32_t hour;/*hour of a day,0-23*/
    uint64_t upstream;
    uint64_t downstream;
};

struct _hour_avg_stream {
    uint64_t total_work_time_upstream;
    uint64_t total_free_time_upstream;
    uint64_t total_work_time_downstream;
    uint64_t total_free_time_downstream;
    uint32_t total_work_time_cnt;
    uint32_t total_free_time_cnt;
};

struct _day_avg_stream {
    uint64_t total_weekday_upstream;
    uint64_t total_weekend_upstream;
    uint64_t total_weekday_downstream;
    uint64_t total_weekend_downstream;
    uint32_t total_weekday_cnt;
    uint32_t total_weekend_cnt;
};

typedef struct _port_benchmark_value {
    struct _day_stream day_stream[DAY_COUNT_INTERVAL+1]; /*the last index DAY_COUNT_INTERVAL+1 will save the avg data*/
    struct _hour_stream hour_stream[HOUR_COUNT_INTERVAL+1];
    u_short generated_hour_avg;/*flag to check whether we have generated the hour avg data of yesterday,so,we only count once in one hour*/
    u_short generated_day_avg;
    u_short port; /*packet port*/
}port_flow_benchmark;


typedef struct _port_benchmark {
    struct _day_stream day_stream[DAY_COUNT_INTERVAL]; /*one week:monday,tuesday,etc*/
    struct _hour_stream weekend_hour_stream[HOUR_COUNT_INTERVAL]; /*one day,24 hours*/
    struct _hour_stream weekday_hour_stream[HOUR_COUNT_INTERVAL]; /*one day,24 hours*/
    u_short port;
}benchmark;

typedef struct _region_info_key{
        char country[8];
        char chn_city[8];
}region_info_key;

struct _port_flow_Bps_metadata {
    uint32_t property_ip;
    u_short port;
    region_info_key country_city;
};

typedef struct _port_flow_Bps {
    struct _port_flow_Bps_metadata bps_metadata;
    uint64_t upstream;
    uint64_t downstream;
	UT_hash_handle hh;
}port_flow_bps;


void portFlowStatistics(msg_t *pkt);
void *updatePortStatistics(void *);
void *updatePortBps(void *);
void* generateBenchmark(void *arg);
void initTimeZone();
int loadPortConfiguration();


#endif

