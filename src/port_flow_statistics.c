/**
*@Description: port flow statistics to check the malware flow,
    if the network flow is huge,set the WAIT_QUEUE_BACKLOG bigger and call loadPortFlowStatisticsModule
    before call portFlowStatistics function to handle the database action might be a better way,in the meantime,
    adjust the UPDATE_INTERVAL_TIME if you like,or, call portFlowStatistics directly if you think that the system
    is okay to create thread and excute sql frequently.
*@Author: Chad
*@Date: 9 May 2017
*@Changelog:
*1)separate the port into tcp and udp on 15 May 2017
*2)24 May 2017,add portFlowBps and it's related,remove mul thread,use single thread instead.
*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <netinet/in.h>
#include <mysql/errmsg.h>
#include <mysql/mysql.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include "port_flow_statistics.h"
#include "dbapi.h"
#include "uthash.h"
#include "utlist.h"
#include "c_list.h"

static int port_config[PORT_QUEUE_BACKLOG] = {0}; /*user's configuation*/
volatile sig_atomic_t reload_config = TRUE; /*reload flag, true:reload the port configuration*/
char use_single_thread = FALSE; /*true:single thread,false:mul thread*/
static pthread_mutex_t statistic_lock = PTHREAD_MUTEX_INITIALIZER; /*thread mutex lock for portFlowStatistics*/
static uint64_t pkt_count = 0;
static uint64_t valid_pkt_count = 0;
static port_flow *port_flow_list = NULL;
static port_flow_bps *port_flow_bps_list = NULL;
static int total_port;

#define TCP_PORT_FLOW_TABLE "tcp_port_flow_statistics" /*tcp port table name*/
#define UDP_PORT_FLOW_TABLE "udp_port_flow_statistics" /*udp port table name*/
#define PORT_FLOW_HOUR_STATISTICS "port_flow_hour_statistics" /*tcp&udp port table name*/
#define PORT_FLOW_DAY_STATISTICS "port_flow_day_statistics" /*tcp&udp port table name*/
#define PORT_FLOW_WEEKDAY_HOUR_BENCHMARK "port_flow_weekday_hour_benchmark" /*tcp&udp port table name*/
#define PORT_FLOW_WEEKEND_HOUR_BENCHMARK "port_flow_weekend_hour_benchmark" /*tcp&udp port table name*/
#define PORT_FLOW_DAY_BENCHMARK "port_flow_day_benchmark" /*tcp&udp port table name*/
#define PORT_FLOW_WORK_HOUR_BENCHMARK "port_flow_work_hour_benchmark" /*work time free time*/
#define PORT_FLOW_FREE_HOUR_BENCHMARK "port_flow_free_hour_benchmark" /*work time free time*/
#define FLOW_CONFIGURATION_TABLE "flow_config" /*port configuration table name*/

#define MAX_DB_CONNECTION_TRY_TIMES 3
#define MAX_ARRAY_SIZE 2048
#define HOUR_STATISTICS 0
#define WEEK_STATISTICS 1
#define WEEKDAY_STATISTICS 0
#define WEEKEND_STATISTICS 1
#define MAX_SQL_LENGTH 2048

#define PORT_FLOW_BPS_PATH "/var/run/.port_flow_bps_path"

struct port_flow_bps_info {
    uint32_t property_ip;
    uint32_t external_ip;
    uint32_t pkt_len;
    u_short port;
    char is_upstream;
};
static volatile int fetch_bps = 0;

static port_flow_bps pflow_bps[MAX_ARRAY_SIZE];
int tz_minuteswest = 60;/*BeiJin*/

/*load configuration*/
static int loadPortFlowConfiguration()
{
    TRACE();
    char sql[MAX_SQL_LENGTH];
    int ret = 0;
    MYSQL *pConn = NULL;
    pConn = CreateDBConn();
    if(pConn == NULL)
        return -1;
    
    snprintf(sql,sizeof(sql),"select port from "FLOW_CONFIGURATION_TABLE" where isapply = 1 order by port asc");

	if (ExecuteSql(pConn,sql) != 0)
	{
	    CloseDBConn(pConn);
        return -1;
	}
    else{
        MYSQL_RES *mysql_res;
        MYSQL_ROW tuple;
        int i = 0;
        int port = 0;
        
        mysql_res = mysql_store_result(pConn);
        
        while((tuple = mysql_fetch_row(mysql_res)))
        {
            if(tuple[0] == NULL)
                continue;
            
            port = atoi(tuple[0]);
            if(port <= 0 || port >= MAX_PORT_NUM)
                continue;
            if(i>= PORT_QUEUE_BACKLOG)
                break;
            port_config[i++] = port;
            LogMessage(LOG_INFO,"apply port %d\n",port);
        }
        total_port = i;
        
        FreeResult(pConn,mysql_res);
    }
    
	CloseDBConn(pConn);
    return ret;
}

void initTimeZone()
{
    struct timeval tv;
    struct timezone tz;
    int ret = gettimeofday(&tv,&tz);
    if(gettimeofday(&tv,&tz) == 0){
        tz_minuteswest = tz.tz_minuteswest;
    }
}

/*load configuration from db table*/
inline int loadPortConfiguration()
{
    if(reload_config){
        if(loadPortFlowConfiguration() != 0)
            return -1;
        else
            reload_config = FALSE;
    }
    
    return 0;
}

/**
*@Description: check whether the port is in configuration.
*@Paras: sport
*@Return: 1 yes,and 0 is no
*@Author: Chad
*/
static int portInConfiguration(u_short port)
{
    static u_short last_port = 0;
    int i = 0;
    if(port == 0 || total_port == 0)
        return 0;
    if(port == last_port)
        return 1;
    if(port < port_config[0] || port > port_config[total_port - 1])
        return 0;
    if(total_port <= 10){
        while(i<total_port){
            if(port_config[i++] == port){
                last_port = port;
                return 1;
            }
        }
    }
    else{
        int max = total_port;
        int mid = max>>1;
        while(mid > 0 && mid < max){
            if(port == port_config[mid]){
                last_port = port;
                return 1;
            }
            else if(port > port_config[mid]){
                mid = (mid+max)>>1;
            }
            else if(port < port_config[mid]){
                max = mid;
                mid = mid>>1;
            }
            if(mid == max-1){
                if(port == port_config[mid]){
                    last_port = port;
                    return 1;
                }
                break;
            }
        }
    }
    
    return 0;
}

/*get date like 51813 (5/18 13:00)*/
static int getHourTime(time_format *t)
{
    char time[10] = "";
    char format[10] = "%d";
    
    if(t->day < 10)
        strcat(format,"0%d");
    else
        strcat(format,"%d");

    if(t->hour < 10)
        strcat(format,"0%d");
    else
        strcat(format,"%d");
    
    snprintf(time,sizeof(time),format,t->month,t->day,t->hour);
    
    return atoi(time);
}

/*get date like 20170915*/
static int getDayTime(time_format *t)
{
    char time[10] = "";
    char format[10] = "%d";
    
    if(t->month < 10)
        strcat(format,"0%d");
    else
        strcat(format,"%d");

    if(t->day< 10)
        strcat(format,"0%d");
    else
        strcat(format,"%d");
    
    snprintf(time,sizeof(time),format,t->year,t->month,t->day);
    
    return atoi(time);
}


/*get current time,include year,month,day,hour,wday*/
static inline time_format *getCurrentTime()
{
    static time_format hour_time;
    static time_t last_time = 0;
    time_t now;
    time(&now);
    if(last_time != 0 && now - last_time <= 5){
        return &hour_time;
    }
    last_time = now;
    //return &hour_time;
    /*notice:I use gmtime instead of localtime to improve performence,
        so i get tz_minuteswest once when i reload config and adjust the timestamp based on it,
       */
    struct tm *tm_now ;
    now -= tz_minuteswest*60;
    tm_now = gmtime(&now);
    
    hour_time.year = tm_now->tm_year+1900;
    hour_time.month = tm_now->tm_mon+1;
    hour_time.day = tm_now->tm_mday;
    hour_time.hour = tm_now->tm_hour;
    hour_time.wday = tm_now->tm_wday;
    
    return &hour_time;
}

/*return value:
-1 on error
0 not found record
1 found record
*/
static uint64_t getLastStreamDataFromDbByPortAndDate(MYSQL *pConn,char *sql,char *outer_ips,int outer_ips_len)
{
    uint64_t id = 0;
	if (ExecuteSql(pConn,sql) != 0)
	{
        return -1;
	}
    else{
        MYSQL_RES *mysql_res;
        MYSQL_ROW tuple;
        /*get last upstream and downstream*/
        mysql_res = mysql_store_result(pConn);
        if((tuple = mysql_fetch_row(mysql_res)))
        {
            if(tuple[0] != NULL)
                id = atoll(tuple[0]);
            
            if(tuple[1] != NULL)
                strncpy(outer_ips,tuple[1],outer_ips_len - 1);
        }
        FreeResult(pConn,mysql_res);
    }
    
    return id;
}

static void updateStatisticsDayData2Database(MYSQL *pConn,port_flow *pflow)
{
    if(pflow->upstream <= 0 && pflow->downstream <= 0)
        return;
    
    char sql[MAX_SQL_LENGTH] = {0};
    char outer_ips[255] = {0};
    int date = getDayTime(&(pflow->hour_time));
    
    snprintf(sql,sizeof(sql),"select id,outer_ips from %s \
        where property_ip = %u and port = %u and date = %d",
        PORT_FLOW_DAY_STATISTICS,ntohl(pflow->metadata.property_ip),pflow->metadata.port,date);

    uint64_t id = getLastStreamDataFromDbByPortAndDate(pConn,sql,outer_ips,sizeof(outer_ips));

    int i = pflow->outer_ips_index-1;
    char ip[INET_ADDRSTRLEN] = "";
    if(strlen(outer_ips) > 0 && strlen(outer_ips) < sizeof(outer_ips)-1){
        strcat(outer_ips,",");
    }
    while(i>=0){
        inet_ntop(AF_INET,&(pflow->outer_ips[i]),ip,sizeof(ip));
        i--;
        if(strstr(outer_ips,ip) != NULL)
            continue;
        if(sizeof(outer_ips)-strlen(outer_ips) <= sizeof(ip))
            break;
        snprintf(outer_ips+strlen(outer_ips),sizeof(outer_ips)-strlen(outer_ips),"%s,",ip);
    }
    
    if(outer_ips[strlen(outer_ips)-1] == ','){
        outer_ips[strlen(outer_ips)-1] = '\0';
    }
    
    if(id >= 1){
        /*update*/
        snprintf(sql,sizeof(sql),"update %s set upstream=upstream+%lu,downstream=downstream+%lu,outer_ips = '%s' \
        where id = %lu",
        PORT_FLOW_DAY_STATISTICS,
        pflow->upstream,
        pflow->downstream,
        outer_ips,
        id);
    }
    else{
        /*insert*/
        snprintf(sql,sizeof(sql),"insert into %s(port,upstream,downstream,date,property_ip,outer_ips,\
        year,month,day,wday)\
        values(%u,%lu,%lu,%d,%u,'%s',%u,%u,%u,%u)",
        PORT_FLOW_DAY_STATISTICS,
        pflow->metadata.port,
        pflow->upstream,
        pflow->downstream,
        date,
        ntohl(pflow->metadata.property_ip),
        outer_ips,
        pflow->hour_time.year,
        pflow->hour_time.month,
        pflow->hour_time.day,
        pflow->hour_time.wday
        );
    }
    /*excute sql sentence*/
	ExecuteSql(pConn,sql);
}


/**
*@Description: update the statistics data to database port_flow_hour_statistics
*@Paras: pflow
               pointer to port flow
*@Return: void
*@Author: Chad
*/
static void updateStatisticsHourData2Database(MYSQL *pConn,port_flow *pflow)
{
    if(pflow->upstream <= 0 && pflow->downstream <= 0)
        return;
    char sql[MAX_SQL_LENGTH] = {0};
    char outer_ips[255] = {0};
    int date = getHourTime(&(pflow->hour_time));
    
    
    snprintf(sql,sizeof(sql),"select id,outer_ips from %s \
        where port = %u and date = %d and property_ip = %u",
        PORT_FLOW_HOUR_STATISTICS,pflow->metadata.port,date,ntohl(pflow->metadata.property_ip));

    uint64_t id = getLastStreamDataFromDbByPortAndDate(pConn,sql,outer_ips,sizeof(outer_ips));

    int i = pflow->outer_ips_index-1;
    char ip[INET_ADDRSTRLEN] = "";
    if(strlen(outer_ips) > 0 && strlen(outer_ips) < sizeof(outer_ips)-1){
        strcat(outer_ips,",");
    }
    while(i>=0){
        inet_ntop(AF_INET,&(pflow->outer_ips[i]),ip,sizeof(ip));
        i--;
        if(strstr(outer_ips,ip) != NULL)
            continue;
        if(sizeof(outer_ips)-strlen(outer_ips) <= sizeof(ip))
            break;
        snprintf(outer_ips+strlen(outer_ips),sizeof(outer_ips)-strlen(outer_ips),"%s,",ip);
    }
    
    if(outer_ips[strlen(outer_ips)-1] == ','){
        outer_ips[strlen(outer_ips)-1] = '\0';
    }
    
    if(id >= 1){
        /*update*/
        snprintf(sql,sizeof(sql),"update %s set upstream=upstream+%lu,downstream=downstream+%lu,outer_ips = '%s' \
        where id = %lu",
        PORT_FLOW_HOUR_STATISTICS,
        pflow->upstream,
        pflow->downstream,
        outer_ips,
        id);
    }
    else{
        /*insert*/
        snprintf(sql,sizeof(sql),"insert into %s(port,upstream,downstream,date,property_ip,outer_ips,\
        year,month,day,hour,wday)\
        values(%u,%lu,%lu,%d,%u,'%s',%u,%u,%u,%u,%u)",
        PORT_FLOW_HOUR_STATISTICS,
        pflow->metadata.port,
        pflow->upstream,
        pflow->downstream,
        date,
        ntohl(pflow->metadata.property_ip),
        outer_ips,
        pflow->hour_time.year,
        pflow->hour_time.month,
        pflow->hour_time.day,
        pflow->hour_time.hour,
        pflow->hour_time.wday
        );
    }
	ExecuteSql(pConn,sql);
    /*excute sql sentence*/

}

/**
*@Description: select one int column and return the value.
*@Paras: sql
                sql sentence
*@Return: the column value on positive,error on negative.
*@Author: Chad
*/
static int selectAsInt(MYSQL *pConn,char *sql)
{
    MYSQL_RES *mysql_res;
    MYSQL_ROW tuple;
    int ret = -1;

    if(ExecuteSql(pConn,sql) != 0)
        return ret;

    mysql_res = mysql_store_result(pConn);
    if(mysql_res){
        uint32_t num = mysql_num_rows(mysql_res);
        if(num == 0)
            return -2;

        if(tuple = mysql_fetch_row(mysql_res)){
            if(tuple[0] != NULL)
                ret = atoi(tuple[0]);
        }
        FreeResult(pConn,mysql_res);
    }

    return ret;
}
  

static int updateAllHashListStatisticsBps2Db(port_flow_bps *bps_data,int len)
{
    uint32_t bps_array_index= 0;
    char sql[MAX_SQL_LENGTH] = "";
    char upsert_sql[MAX_SQL_LENGTH] = "";
    int id = 0;
    int sql_ret = 0;
    static MYSQL *pConn = NULL;
    if(pConn == NULL){
        LogMessage(LOG_INFO,"%s:create db connection...\n",__FUNCTION__);
        pConn = CreateDBConn();
        if(pConn == NULL){
            LogMessage(LOG_INFO,"%s:failed to create db connection,return\n",__FUNCTION__);
            return 0;
        }
    }
	else if (!IsDBConnActive(pConn))
	{
		CloseDBConn(pConn);
		pConn = CreateDBConn();
	}
    snprintf(sql,sizeof(sql),"update property_ip_port_region_bps set upstream_bps = 0,downstream_bps = 0");
    sql_ret = ExecuteSql(pConn,sql);
    if(sql_ret != 0)
        return 0;
    
    int i = 0;
    while(i<len){
        if(bps_data[i].bps_metadata.port <= 0)
            break;
        snprintf(sql,sizeof(sql),"select id from property_ip_port_region_bps where \
            property_ip = %u and port = %u and region = '%s' and city = '%s'",
            ntohl(bps_data[i].bps_metadata.property_ip),
            bps_data[i].bps_metadata.port,
            bps_data[i].bps_metadata.country_city.country,
            bps_data[i].bps_metadata.country_city.chn_city);
        id = selectAsInt(pConn,sql);
        if(id == -1){ /*error*/
            break;
        }
        else if(id == -2){/*not found record,insert*/
            snprintf(upsert_sql,sizeof(upsert_sql),"insert into property_ip_port_region_bps\
                (property_ip,port,region,city,upstream_bps,downstream_bps,timestamp) values\
                (%u,%u,'%s','%s',%lu,%lu,now())",
                ntohl(bps_data[i].bps_metadata.property_ip),
                bps_data[i].bps_metadata.port,
                bps_data[i].bps_metadata.country_city.country,
                bps_data[i].bps_metadata.country_city.chn_city,
                bps_data[i].upstream,
                bps_data[i].downstream);
               // time(NULL));
        }
        else{/*got record,update it*/
            snprintf(upsert_sql,sizeof(upsert_sql),"update property_ip_port_region_bps \
                set upstream_bps = %lu,downstream_bps = %lu where \
                property_ip = %u and port = %u and region = '%s' and city = '%s'",
                bps_data[i].upstream,
                bps_data[i].downstream,
                ntohl(bps_data[i].bps_metadata.property_ip),
                bps_data[i].bps_metadata.port,
                bps_data[i].bps_metadata.country_city.country,
                bps_data[i].bps_metadata.country_city.chn_city);
        }
        //printf("%s\n",upsert_sql);
        sql_ret = ExecuteSql(pConn,upsert_sql);
        if(sql_ret != 0)
            break;
        i++;
    }
    return i;
}



/*update statistics data to db,called by thread to make sure if no packet come,update anyway*/
static void updateStatisticsData2Database(MYSQL *pConn,port_flow *pflow)
{
    updateStatisticsHourData2Database(pConn,pflow);
    updateStatisticsDayData2Database(pConn,pflow);
    pflow->upstream = 0;
    pflow->downstream = 0;
}

/*update statistics data to db,called by engine(got packet) if hour time is changed*/
static void updateSinglePortStatisticsData2Database(port_flow *pflow)
{
    MYSQL *pConn = NULL;
    pConn = CreateDBConn();
    if(pConn == NULL){
        LogMessage(LOG_INFO,"%s:failed to create db connection,return\n",__FUNCTION__);
    }
    else{
        updateStatisticsHourData2Database(pConn,pflow);
        updateStatisticsDayData2Database(pConn,pflow);
        pflow->upstream = 0;
        pflow->downstream = 0;
        CloseDBConn(pConn);
    }
}

static int updateAllHashListStatisticsData()
{
    int i = 0;
    MYSQL *pConn = NULL;
    if(pConn == NULL){
        LogMessage(LOG_INFO,"%s:no packet trigger,thread create db connection to update all statistics data...\n",__FUNCTION__);
        pConn = CreateDBConn();
        if(pConn == NULL){
            LogMessage(LOG_INFO,"%s:failed to create db connection,return\n",__FUNCTION__);
            return;
        }
    }
    
    LogMessage(LOG_INFO,"digger thread is going to update statistics data...\n");
    
	port_flow *node = NULL, *temp = NULL;
    if (pthread_mutex_lock(&statistic_lock) == 0){
    	HASH_ITER(hh, port_flow_list, node, temp) {
            if(node->metadata.port <= 0)
                break;
            updateStatisticsData2Database(pConn,node);
    		HASH_DEL(port_flow_list, node);
    		free(node);
    		i++;
    	}
        pthread_mutex_unlock(&statistic_lock);
    }
    
    CloseDBConn(pConn);
    LogMessage(LOG_INFO,"udpate done,update %d records,total pkt count is %lu,valid pkt count is %lu\n",i,pkt_count,valid_pkt_count);

    return i;
}

/**
*@Description: get country code and city code by ip,and set to metadata.
*@Paras: remote_ip
                remote ip address
              bps_metadata
                the pointer to metadata struct
*@Return: success on 0
*@Author: Chad
*/
static int setRemoteRegionByRemoteIp(uint32_t remote_ip,region_info_key *region)
{
    size_t size = 0;
    char ipaddr[INET_ADDRSTRLEN];
    char *country = NULL;
    char *city = NULL;

    /*get the country of remote ip*/
    const char *p = inet_ntop(AF_INET,&remote_ip,ipaddr,sizeof(ipaddr));
    if(p == NULL)
        return -1;
    
    //country = GetCountryByIp(ipaddr,&size);
    if(country != NULL){
        strncpy(region->country,country,sizeof(region->country)-1);
    	if (strcmp(region->country, "CN") == 0) {/*china*/
    	    size = 0;
    		//city = GetCityByIp(ipaddr,&size);
            if(city != NULL){
                strncpy(region->chn_city,city,sizeof(region->chn_city)-1);
                free(city);
            }
        }
        free(country);
        return 0;
    }
    
    //return -2;
    /*consider internal network flow,so return 0*/
    return 0;
}

typedef struct _region_info{
	    region_info_key key;
	    UT_hash_handle hh;
}region_info;

struct _ip_region {
    unsigned char ip; /*last part of ip*/
    region_info *location;
};

struct _ip_part_three {
        struct _ip_region ip_pair[256];
};

typedef struct _match_ip_address {
        struct _ip_part_three *ipPart3;
}ip_country_list;

region_info *country_city_list;/*country + china city*/

static ip_country_list ip_country_array[56865-256-16-1] = {NULL};

static region_info *getRegionLocation(uint32_t dst_ip,region_info_key *region)
{
    if(setRemoteRegionByRemoteIp(dst_ip,region) < 0)
        return NULL;
    
    region_info_key key;
    strcpy(key.country,region->country);
    strcpy(key.chn_city,region->chn_city);
    region_info *node = NULL;
    
	HASH_FIND(hh, country_city_list, &key, sizeof(key), node);
	if (NULL == node)
	{
	    static int list_size = 0;
        if(list_size > 1000){
            LogMessage(LOG_ERR,"something wrong,no such more country and city...over 1000?\n");
            return NULL;
        }
		node = (region_info*)calloc(1,sizeof(region_info));
        if(node == NULL)
            return NULL;
		node->key = key;
        
		HASH_ADD(hh, country_city_list, key, sizeof(key), node);
        list_size++;
	}
    
    return node;
    
}

static int putIpRegionInfo(uint32_t ip,region_info_key *region)
{
    int duplicated = 0;
    uint32_t host_byte_order_ip = ntohl(ip);
    int array_index = host_byte_order_ip>>16 & 0xffff;
    if(array_index >= 65536){
        return -1;
    }
    
    ip_country_list *pList = &ip_country_array[array_index];
    if(pList->ipPart3 == NULL){
        pList->ipPart3 = calloc(256,sizeof(struct _ip_part_three));
    }
    
    if(pList->ipPart3 == NULL){
        return -1;
    }
    
    region_info *region_loc = getRegionLocation(ip,region);
    if(region_loc == NULL)
        return 1;
    
    int part3 = host_byte_order_ip>>8 & 0xff;
    int part4 = host_byte_order_ip & 0xff;
    struct _ip_part_three *pPart3 = pList->ipPart3+part3;
    pPart3->ip_pair[part4].ip = part4;
    pPart3->ip_pair[part4].location = region_loc;
    
    return 0;

}
static int getIpRegionInfo(uint32_t ip,region_info_key *region)
{
    uint32_t host_byte_order_ip = ntohl(ip);
    int array_index = host_byte_order_ip>>16 & 0xffff;
    if(array_index >= 65536)
        return -1;
    
    ip_country_list *pList = &ip_country_array[array_index];
    if(pList->ipPart3 == NULL)
        return 1;
    int part3 = host_byte_order_ip>>8 & 0xff;
    int part4 = host_byte_order_ip & 0xff;
    struct _ip_part_three *pPart3 = pList->ipPart3+part3;
    if(pPart3->ip_pair[part4].ip > 0 && pPart3->ip_pair[part4].location != NULL){
        strcpy(region->country,pPart3->ip_pair[part4].location->key.country);
        strcpy(region->chn_city,pPart3->ip_pair[part4].location->key.chn_city);
        //printf("get succece region info,%s,%s==\n",meta->region,meta->chn_city);
        return 0;
    }
    return 2;
}

static void portFlowBps(struct port_flow_bps_info *info)
{
    static struct _port_flow_Bps_metadata cur_pkt_metadata;
    memset(&cur_pkt_metadata,0,sizeof(struct _port_flow_Bps_metadata));

    cur_pkt_metadata.port= info->port;
    cur_pkt_metadata.property_ip = info->property_ip;
        
    if(getIpRegionInfo(info->external_ip,&(cur_pkt_metadata.country_city))!= 0){
        putIpRegionInfo(info->external_ip,&(cur_pkt_metadata.country_city));
    }
    
    port_flow_bps *node = NULL;
	HASH_FIND(hh, port_flow_bps_list, &(cur_pkt_metadata), sizeof(struct _port_flow_Bps_metadata), node);
	if (NULL == node)
	{
	    static int list_size = 0;
        if(list_size > 100000){
            LogMessage(LOG_ERR,"something wrong?bps(property+port) over 100000?,it's bad...");
            return;
        }
		node = (port_flow_bps*)calloc(1,sizeof(port_flow_bps));
        if(node == NULL){
            LogMessage(LOG_ERR,"out of memory?error info:%s",strerror(errno));
            return;
        }
        list_size++;
        node->bps_metadata = cur_pkt_metadata;
		HASH_ADD(hh, port_flow_bps_list, bps_metadata, sizeof(struct _port_flow_Bps_metadata), node);
	}
    
    if(info->is_upstream)
        node->upstream += info->pkt_len;
    else
        node->downstream += info->pkt_len;
    
    return;
}

void portFlowStatistics(msg_t *pkt)
{     
    pkt->src_is_protected = isProtectedIp(pkt->src_ip);
    pkt->dst_is_protected = isProtectedIp(pkt->dst_ip);
    
    if(pkt->fragment & STREAM_FIRST_REASSEMBLE_FRAGMENT)
        return;
    
    pkt_count++;
    
    if(loadPortConfiguration() != 0){
        return;
    }
    
    uint32_t outer_ip;
    char is_upstream = TRUE;
    int check_both = 0;
    struct statistics_meta_info sta_info = {0};
    
    int src_is_private = pkt->src_is_protected;
    int dst_is_private = pkt->dst_is_protected;
    
    /*if this is a upstream packet,we only count on source port, otherwise, count on destination port*/
    /*we assume that private ip is internal ip, i.e. property ip*/
    if((src_is_private&dst_is_private) || !(src_is_private|dst_is_private)){/*ignore internal or external network flow*/
        check_both = 1;
        //return;
    }
    
    CHECK_STA:
    if(src_is_private){/*source ip is private,that means the packet is the upstream of this ip*/
        src_is_private = 0;
        is_upstream = TRUE;
        sta_info.property_ip= pkt->src_ip;
        sta_info.port = pkt->src_port;
        //sta_info.protocol = pkt->protocol;
        outer_ip = pkt->dst_ip;
    }
    else if(dst_is_private){/*destination ip is private,that means the packet is the downtream of this ip*/
        dst_is_private = 0;
        is_upstream = FALSE;
        sta_info.property_ip= pkt->dst_ip;
        sta_info.port = pkt->src_ip; 
        //sta_info.protocol = pkt->protocol;
        outer_ip = pkt->src_ip;
    }
    else{
        return;
    }
    
    if(!portInConfiguration(sta_info.port)){
        return;
    }
    
    valid_pkt_count++;
    
    #if 0
    /*for test*/
    char ipaddr[16];
    char ipaddr11[16];
    
    inet_ntop(AF_INET,&pkt->iph->ip_src,ipaddr,sizeof(ipaddr));
    inet_ntop(AF_INET,&pkt->iph->ip_dst,ipaddr11,sizeof(ipaddr11));
    LogMessage(LOG_INFO,"%s handle %s:%u=>%s:%u,sprivate:%d,dprivate:%d\n",__FUNCTION__,ipaddr,
        pkt->sp,ipaddr11,pkt->dp,src_is_private,dst_is_private);
    /*test end*/
    #endif
    
    
    port_flow *node = NULL;
    if (pthread_mutex_lock(&statistic_lock) == 0){
        if(fetch_bps){
            /*for bps*/
            struct port_flow_bps_info bps_info = {0};
            bps_info.property_ip = sta_info.property_ip;
            bps_info.external_ip = outer_ip;
            bps_info.port = sta_info.port;
            bps_info.is_upstream = is_upstream;
            bps_info.pkt_len = pkt->pkt_len;
            /*bps end*/
            portFlowBps(&bps_info);
        }
        
    	HASH_FIND(hh, port_flow_list, &(sta_info), sizeof(struct statistics_meta_info), node);
    	if (NULL == node)
    	{
    	    static int list_size = 0;
            if(list_size > 100000){
                LogMessage(LOG_ERR,"something wrong?property+port over 100000?,it's bad...");
                pthread_mutex_unlock(&statistic_lock);
                return;
            }
    		node = (port_flow*)calloc(1,sizeof(port_flow));
            if(node == NULL){
                LogMessage(LOG_ERR,"out of memory?error info:%s",strerror(errno));
                pthread_mutex_unlock(&statistic_lock);
                return;
            }
            list_size++;
            memcpy(&(node->metadata),&sta_info,sizeof(struct statistics_meta_info));
    		HASH_ADD(hh, port_flow_list, metadata, sizeof(struct statistics_meta_info), node);
    	}
        pthread_mutex_unlock(&statistic_lock);
    }
    
    if (is_upstream)
        node->upstream += pkt->pkt_len;
    else
        node->downstream += pkt->pkt_len;
    
    /*get old hour time before set node->hour_time*/
    u_short last_hour = node->hour_time.hour;
    node->hour_time = *(getCurrentTime());
    
    if(last_hour != node->hour_time.hour){
        updateSinglePortStatisticsData2Database(node);
    }
    
    /*get external ips*/
    if(outer_ip != 0 && node->outer_ips_index < MAX_OUTER_IP_NUM){
        int i = 0;
        char same_ip = FALSE;
        while(i<node->outer_ips_index){
            if(node->outer_ips[i++] == outer_ip){
                same_ip = TRUE;
                break;
            }
        }
        if(! same_ip)
            node->outer_ips[node->outer_ips_index++] = outer_ip;
    }
    
    if(check_both){
        check_both = 0;
        goto CHECK_STA;
    }
    return;
    
}


static void updateStandardDeviation(MYSQL *pConn,char *sql,char *table)
{
    if(!pConn || !sql || !table)
        return;
    //printf("%s:%s\n",__FUNCTION__,sql);
    char update_sql[512] = {0};
    int ret = ExecuteSql(pConn,sql);
    if(ret != 0){
        return;
    }
    else{
        MYSQL_RES *mysql_res;
        MYSQL_ROW tuple;
        mysql_res = mysql_store_result(pConn);
        int port = 0;
        int64_t std_deviation = 0;
        int hour = 0;
        while((tuple = mysql_fetch_row(mysql_res)))
        {
            port = atoi(tuple[0]);
            hour = atoi(tuple[1]);
            sscanf(tuple[2],"%ld",&std_deviation);
            if(strcmp(table,PORT_FLOW_WORK_HOUR_BENCHMARK) == 0 || strcmp(table,PORT_FLOW_FREE_HOUR_BENCHMARK) == 0){
                snprintf(update_sql,sizeof(update_sql),"update %s set std_deviation = %ld \
                    where port = %d",table,std_deviation,port);
            }
            else{
                snprintf(update_sql,sizeof(update_sql),"update %s set std_deviation = %ld \
                    where port = %d and hour = %d",table,std_deviation,port,hour);
            }
            //printf("std:%d,update-sql:%s\n",atoi(tuple[2]),update_sql);
            ExecuteSql(pConn,update_sql);
        }
        FreeResult(pConn,mysql_res);
    }

}

static int excuteMysqlTransaction(MYSQL *pConn,char *sql,char *truncate_table)
{
    int ret = 0;
    if(!pConn || !sql)
        return;
    
    ExecuteSql(pConn,"start transaction");
    
    if(truncate_table){
        char truncate[256] = {0};
        snprintf(truncate,sizeof(truncate),"truncate table %s",truncate_table);
        ret = ExecuteSql(pConn,truncate);
    }
    
    ret += ExecuteSql(pConn,sql);
    if(ret != 0){
        LogMessage(LOG_INFO,"%s:rollback sql:%s\n",__FUNCTION__,sql);
        ExecuteSql(pConn,"rollback");
    }
    else{
        LogMessage(LOG_INFO,"%s:commit sql:%s\n",__FUNCTION__,sql);
        ExecuteSql(pConn,"commit");
    }
    return ret;
}

void runBenchmarkGenerator()
{
    TRACE();
    int ret = 0;
    int last_port = 0;
    MYSQL *pConn;
    char sql[MAX_SQL_LENGTH] = {0};
    
    LogMessage(LOG_INFO,"%s:create db connection to generate benchmark...\n",__FUNCTION__);
    pConn = CreateDBConn();
    if(pConn == NULL){
        LogMessage(LOG_INFO,"%s:failed to create db connection,just return\n",__FUNCTION__);
        return;
    }
    
    /*regenerate port flow weekday hour benchmark,weekday 0-23 hour*/
    snprintf(sql,sizeof(sql),"insert into %s(port,hour,total_up,total_down,cnt) \
        (select port,hour,sum(upstream) as total_up,sum(downstream) as total_down,count(id) as cnt from \
        %s where wday >= 1 and wday <=5 group by port,hour)",
        PORT_FLOW_WEEKDAY_HOUR_BENCHMARK,PORT_FLOW_HOUR_STATISTICS);
    ret = excuteMysqlTransaction(pConn,sql,PORT_FLOW_WEEKDAY_HOUR_BENCHMARK);
    if(ret == 0){
        snprintf(sql,sizeof(sql),"select s.port,s.hour,floor(sqrt(sum(power((s.upstream-(c.total_up/c.cnt))/1024,2))/count(s.id))) as std \
            from %s as s,%s as c where s.wday >= 1 and s.wday <=5 and s.port = c.port and s.hour = c.hour group by s.port,s.hour",PORT_FLOW_HOUR_STATISTICS,PORT_FLOW_WEEKDAY_HOUR_BENCHMARK);
        updateStandardDeviation(pConn,sql,PORT_FLOW_WEEKDAY_HOUR_BENCHMARK);
    }

    
    /*regenerate port flow weekend hour benchmark,weekend 0-23 hour*/
    snprintf(sql,sizeof(sql),"insert into %s(port,hour,total_up,total_down,cnt) \
        (select port,hour,sum(upstream) as total_up,sum(downstream) as total_down,count(id) as cnt from \
        %s where wday = 6 or wday = 0 group by port,hour)",
        PORT_FLOW_WEEKEND_HOUR_BENCHMARK,PORT_FLOW_HOUR_STATISTICS);
    ret = excuteMysqlTransaction(pConn,sql,PORT_FLOW_WEEKEND_HOUR_BENCHMARK);
    if(ret == 0){
        snprintf(sql,sizeof(sql),"select s.port,s.hour,floor(sqrt(sum(power((s.upstream-(c.total_up/c.cnt))/1024,2))/count(s.id))) as std \
            from %s as s,%s as c where (s.wday = 6 or s.wday = 0) and s.port = c.port and s.hour = c.hour group by s.port,s.hour",PORT_FLOW_HOUR_STATISTICS,PORT_FLOW_WEEKEND_HOUR_BENCHMARK);
        updateStandardDeviation(pConn,sql,PORT_FLOW_WEEKEND_HOUR_BENCHMARK);
    }
    /*regenerate port flow day benchmark,monday to sunday*/
    snprintf(sql,sizeof(sql),"insert into %s(port,wday,total_up,total_down,cnt) \
        (select port,wday,sum(upstream) as total_up,sum(downstream) as total_down,count(id) as cnt from \
        %s group by port,wday)",
        PORT_FLOW_DAY_BENCHMARK,PORT_FLOW_DAY_STATISTICS);
    ret = excuteMysqlTransaction(pConn,sql,PORT_FLOW_DAY_BENCHMARK);
    if(ret == 0){
        snprintf(sql,sizeof(sql),"select s.port,s.hour,floor(sqrt(sum(power((s.upstream-(c.total_up/c.cnt))/1024,2))/count(s.id))) as std \
            from %s as s,%s as c where s.port = c.port and s.wday = c.wday group by s.port,s.wday",PORT_FLOW_DAY_STATISTICS,PORT_FLOW_DAY_BENCHMARK);
        updateStandardDeviation(pConn,sql,PORT_FLOW_DAY_BENCHMARK);
    }

    /*regenerate port flow work hour benchmark,monday to sunday 9-18*/

    snprintf(sql,sizeof(sql),"insert into %s(port,total_up,total_down,cnt) \
        (select port,sum(upstream) as total_up,sum(downstream) as total_down,count(id) as cnt from \
        %s where wday>=1 and wday<=5 and hour>8 and hour<18 group by port)",
        PORT_FLOW_WORK_HOUR_BENCHMARK,PORT_FLOW_HOUR_STATISTICS);
    ret = excuteMysqlTransaction(pConn,sql,PORT_FLOW_WORK_HOUR_BENCHMARK);
    if(ret == 0){
        snprintf(sql,sizeof(sql),"select s.port,s.hour,floor(sqrt(sum(power((s.upstream-(c.total_up/c.cnt))/1024,2))/count(s.id))) as std \
            from %s as s,%s as c where s.wday>=1 and s.wday<=5 and s.hour>8 and s.hour<18 and s.port = c.port group by s.port",PORT_FLOW_HOUR_STATISTICS,PORT_FLOW_WORK_HOUR_BENCHMARK);
        updateStandardDeviation(pConn,sql,PORT_FLOW_WORK_HOUR_BENCHMARK);
    }
    /*regenerate port flow free hour benchmark,monday to sunday !(9-18) and saturday and sunday*/
    snprintf(sql,sizeof(sql),"insert into %s(port,total_up,total_down,cnt) \
        (select port,sum(upstream) as total_up,sum(downstream) as total_down,count(id) as cnt from \
        %s where !(wday>=1 and wday<=5 and hour>8 and hour<18) group by port)",
        PORT_FLOW_FREE_HOUR_BENCHMARK,PORT_FLOW_HOUR_STATISTICS);
    ret = excuteMysqlTransaction(pConn,sql,PORT_FLOW_FREE_HOUR_BENCHMARK);
    if(ret == 0){
        snprintf(sql,sizeof(sql),"select s.port,s.hour,floor(sqrt(sum(power((s.upstream-(c.total_up/c.cnt))/1024,2))/count(s.id))) as std \
            from %s as s,%s as c where !(s.wday>=1 and s.wday<=5 and s.hour>8 and s.hour<18) and s.port = c.port group by s.port",PORT_FLOW_HOUR_STATISTICS,PORT_FLOW_WORK_HOUR_BENCHMARK);
        updateStandardDeviation(pConn,sql,PORT_FLOW_FREE_HOUR_BENCHMARK);
    }
    
    CloseDBConn(pConn);
}

static int InitWebSocketFd(int EpollFd)
{
    
    struct sockaddr_un cServerSock;

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if ( fd < 0 )
    {
        LogMessage(LOG_ERR,"%s: socket error\n",__func__);
        return -1;
    }

    unlink(PORT_FLOW_BPS_PATH);
    cServerSock.sun_family = AF_UNIX;
    strcpy(cServerSock.sun_path, PORT_FLOW_BPS_PATH);

    if ( bind(fd, (struct sockaddr*)&cServerSock, sizeof(cServerSock)) < 0)
    {
        LogMessage(LOG_ERR,"%s: bind error:%s\n",__func__,strerror(errno));
        close(fd);
        return -2;
    }
    
    if (listen(fd, 128) < 0 ){
        LogMessage(LOG_ERR,"%s: listen error:%s\n",__func__,strerror(errno));
        close(fd);
        return -3;
    }

    struct epoll_event cEvent;
    cEvent.data.fd = fd;
    cEvent.events = EPOLLIN;
    
    if (epoll_ctl(EpollFd, EPOLL_CTL_ADD, fd, &cEvent) < 0)
    {
        LogMessage(LOG_ERR,"%s: epoll_ctl error\n",__func__);
        close(fd);
        return -3;
    }
    
    int flags = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP |
            S_IWGRP | S_IXGRP | S_IROTH |S_IWOTH |S_IXOTH | S_ISUID;
    if (chmod(PORT_FLOW_BPS_PATH, flags) < 0)
    {
        LogMessage(LOG_ERR, "chmod error: %s\n", strerror(errno));
        close(fd);
        return -4;
    }
    
    return fd;
}

static int resetBpsTimer(int fd,int timeout)
{
    struct itimerspec cSpec;
    cSpec.it_value.tv_sec = timeout;
    cSpec.it_value.tv_nsec = 0;
    cSpec.it_interval.tv_sec = timeout;
    cSpec.it_interval.tv_nsec = 0;
    
    if (timerfd_settime(fd, 0, &cSpec, NULL) < 0)
    {
        LogMessage(LOG_ERR,"%s: timerfd_settime error:%s\n",__func__,strerror(errno));
        return -1;
    }
    return 0;
}

static int InitBpsTimer(int EpollFd,int timeout)
{
    struct epoll_event cEvent;
    struct itimerspec cSpec;

    int fd = timerfd_create(CLOCK_MONOTONIC, 0);
    if ( fd < 0 )
    {
        LogMessage(LOG_ERR,"%s: socket error\n",__func__);
        return -1;
    }

    cSpec.it_value.tv_sec = timeout;
    cSpec.it_value.tv_nsec = 0;
    cSpec.it_interval.tv_sec = timeout;
    cSpec.it_interval.tv_nsec = 0;
    
    if ( timerfd_settime(fd, 0, &cSpec, NULL) < 0)
    {
        LogMessage(LOG_ERR,"%s: timerfd_settime error:%s\n",__func__,strerror(errno));
        close(fd);
        return -2;
    }

    cEvent.data.fd = fd;
    cEvent.events = EPOLLIN;
    
    if (epoll_ctl(EpollFd, EPOLL_CTL_ADD, fd, &cEvent) < 0)
    {
        LogMessage(LOG_ERR,"%s: epoll_ctl error\n",__func__);
        close(fd);
        return -3;
    }
    
    return fd;
}

int acceptConn(int fd)
{
    int cli = -1;
    struct sockaddr_un sock;
    bzero(&sock, sizeof(sock));
    socklen_t len = sizeof(sock);

    cli = accept(fd, (struct sockaddr*)&sock, &len);
    if (cli < 0)
    {
        LogMessage(LOG_ERR,"acceptConn error: %s\n",strerror(errno));
    }

    return cli;
}
int handleBpsTimer()
{
    if(fetch_bps)
        fetch_bps = 0;
}

int handleFetchPortFlowBps()
{
	port_flow_bps *node = NULL, *temp = NULL;
    port_flow_bps bps_info[512];
    int i = 0;
    if (pthread_mutex_lock(&statistic_lock) == 0){
        if(port_flow_bps_list != NULL){
        	HASH_ITER(hh, port_flow_bps_list, node, temp) {
                if(node->bps_metadata.port <= 0 || i >= 512)
                    break;
                memcpy(&bps_info[i++],node,sizeof(port_flow_bps));
        		HASH_DEL(port_flow_bps_list, node);
        		free(node);
            }
        }
        if(!fetch_bps)
            fetch_bps = 1;
        pthread_mutex_unlock(&statistic_lock);
    }
    
    return updateAllHashListStatisticsBps2Db(bps_info,i);
}

struct _port_flow_msg {
    int msg_type;
};

/**
*@Description: update the upstream_bps and downstream_bps to zero if there is no packet for a long time,
because if no packet trigger the portFlowBps function,the value in table will be the last value all the time,but actully,it should be zero.
*@Paras: arg
*@Return: void
*@Author: Chad
*/
void* updatePortBps(void *arg)
{
    int EpollFd = epoll_create(32);
    if (EpollFd < 0)
        return NULL;

    fcntl(EpollFd, F_SETFD, fcntl(EpollFd, F_GETFD) | FD_CLOEXEC);
    struct _port_flow_msg msg;
    int32_t recv_len = 0;
    int32_t num = 0;
    int get_bps_fd = InitWebSocketFd(EpollFd);
    int timer_fd = InitBpsTimer(EpollFd,60);
    struct epoll_event cEvs[32];
    int i = 0;
    while(1){
        num = epoll_wait(EpollFd, cEvs, 32, -1);
        if ( num < 0 )
        {
            if ( EINTR == errno )
                continue;
            else
                return;
        }

        for (i = 0; i < num; i++) {
            if (cEvs[i].data.fd == get_bps_fd )
            {
                if (cEvs[i].events & EPOLLIN)
                {
                    memset(&msg,0,sizeof(msg));
                    int connfd = acceptConn(get_bps_fd);
                    if(connfd < 0)
                        continue;
                    recv_len = 0;
                    while((recv_len = read(connfd,&msg,sizeof(msg))) > 0){
                        if(recv_len == sizeof(msg)){
                            switch(msg.msg_type){
                                case 1:
                                    resetBpsTimer(timer_fd,5);
                                    handleFetchPortFlowBps();
                                    break;
                                default:
                                    break;
                            }
                        }
                    }
                    close(connfd);
                }
            }
            else if(cEvs[i].data.fd == timer_fd)
            {
                uint64_t n,len;
                len = read(timer_fd,&n,sizeof(uint64_t));
                if(len == sizeof(uint64_t)){
                    handleBpsTimer();
                    resetBpsTimer(timer_fd,60);
                }
            }
        }
    }
}

void* updatePortStatistics(void *arg)
{
    while(1){
        sleep(60);
        updateAllHashListStatisticsData();
    }
}

void* generateBenchmark(void *arg)
{
    static int last_day = 0;
    
    while(1){
        
        time_t now;
        struct tm *tm_now;
        
        time(&now) ;
        now -= tz_minuteswest*60;
        tm_now = gmtime(&now);
        
        int cur_day = tm_now->tm_mday;
        if(cur_day != last_day){
            runBenchmarkGenerator();
            last_day = cur_day;
        }
    
        sleep(60);
    }
}


