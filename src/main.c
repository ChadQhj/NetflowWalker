/*
 * main.cpp
 *
 *  Created on: 2017-6-7
 *      Author: lzh
 */

#include "common.h"
#include "dbapi.h"
#include "suspicious_ip_domain_url_alert.h"
#include "port_flow_statistics.h"
#include "attack_success_check.h"
#include "uthash.h"
#include <rte_config.h>
#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_errno.h>
#include <signal.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//------------DPDK globals----------------
#ifndef META_MEMPOOL
#define META_MEMPOOL "meta-mempool"
#endif
#ifndef META_PAYLOAD_MEMPOOL
#define META_PAYLOAD_MEMPOOL "meta-payload-mempool"
#endif
#ifndef META_RING
#define META_RING "meta-ring"
#endif
#ifndef META_PAYLOAD_RING
#define META_PAYLOAD_RING "meta-payload-ring"
#endif
#ifndef DIGGER_MEMPOOL
#define DIGGER_MEMPOOL "digger-mempool"
#endif
#ifndef DIGGER_RING
#define DIGGER_RING "digger-ring"
#endif

struct rte_mempool *meta_mempool = NULL;
struct rte_mempool *meta_payload_mempool = NULL;

struct rte_ring *meta_ring = NULL;
struct rte_ring *meta_payload_ring = NULL;

struct rte_mempool *digger_mempool = NULL;
struct rte_ring *digger_ring = NULL;
extern int tz_minuteswest;

//for SQL optimization
#ifndef BATCH_SIZE
#define BATCH_SIZE 5000
#endif
#ifndef FLUSH_INTERVAL
#define FLUSH_INTERVAL 10*60
#endif
struct pkt_key
{
	struct in_addr src_ip;
	struct in_addr dst_ip;
};
struct pkt_info
{
	struct pkt_key key;
	size_t size;
	UT_hash_handle hh;
};
struct pkt_info *list = NULL;
pthread_mutex_t pkt_lock = PTHREAD_MUTEX_INITIALIZER;
extern short reload_config;
#define DIGGER_PID_FILE "/opt/psi_nids/digger.pid"

static inline uint8_t user_rte_get_huge_maps()
{
    uint8_t numa_maps_c;
    FILE *fp;
    char line[256];

    numa_maps_c = 0;
    fp = popen("for i in $(pgrep minerva); "
            "do cat /proc/$i/numa_maps |grep -e '/mnt/huge/rtemap_0'"
            " | awk '{print $4}'; done", "r");
    if (NULL != fp)
    {
    	while (fgets(line, sizeof(line), fp) != NULL) {
    		if ( !strncmp(line, "huge", 4) )
    			numa_maps_c++;
    	}
    	pclose(fp);
    }
    return numa_maps_c;
}

static void handleSigusr1(int signo)
{
    /*well,it's unsafe,but it's ok*/
    reload_config = 1;
}

static void initSignal()
{
    FILE *fp = fopen(DIGGER_PID_FILE,"w");
    if(fp){
        fprintf(fp,"%u\n",getpid());
        fclose(fp);
    }
    signal(SIGUSR1,handleSigusr1);
}

/**
 *	Purpose: 	receive message from message queue
 *	Input: 		UNIX domain socket
 *	Output: 	message list
 *	Return: 	void*
 *	Author:		hittlle
 *	Date:		2017/06/07
 */
void *Receiver(void * arg)
{
#ifndef MAX_DEQUEUE_NUM
#define MAX_DEQUEUE_NUM 8192
#endif
	uint32_t short_count = 0;
	uint32_t long_count = 0;
	uint32_t idx = 0;

	void *meta[MAX_DEQUEUE_NUM];
	void *meta_payload[MAX_DEQUEUE_NUM];
	msg_t *msg = NULL;
	void *mem = NULL;
	uint64_t drops = 0;
	uint64_t handled = 0;
	uint64_t loop_cnt = 0;
	uint8_t /*sur_c, */numa_maps_c = 0;

	while (1)
	{
		short_count = rte_ring_dequeue_burst(meta_ring, (void**)&meta, MAX_DEQUEUE_NUM);
		long_count = rte_ring_dequeue_burst(meta_payload_ring, (void**)&meta_payload, MAX_DEQUEUE_NUM);
		if (likely(short_count) > 0)
		{
			handled += short_count;
			//printf("received %u meta info\n", short_count);
			for (idx = 0; idx < short_count; idx++)
			{
				msg_t *tmp = (msg_t*)meta[idx];
				if (rte_mempool_get(digger_mempool, &mem) == 0)
				{
					if (NULL != mem) {
						msg = (msg_t*)mem;
						//NOTE: Don't use memcpy here for performance's sake
						msg->msg_size = tmp->msg_size;
				        msg->pkt_len = tmp->pkt_len;
        				msg->src_ip = tmp->src_ip;
        				msg->dst_ip = tmp->dst_ip;
       					msg->src_port = tmp->src_port;
        				msg->dst_port = tmp->dst_port;
        				msg->protocol = tmp->protocol;
        				msg->tcp_syn_flag = tmp->tcp_syn_flag;
        				msg->tcp_psh_flag = tmp->tcp_psh_flag;
        				msg->tcp_fin_flag = tmp->tcp_fin_flag;
                        msg->fragment= tmp->fragment;
                        msg->match_rule= tmp->match_rule;
        				msg->url_size = tmp->url_size;
						if (rte_ring_enqueue(digger_ring, (void*)msg) != 0)
						{
							rte_mempool_put(digger_mempool, mem);
							drops++;
						}
					}
					else {
						rte_mempool_put(digger_mempool, mem);
						drops++;
					}
				}	
				else
				{
					drops++;
				}
				//anyway, free mempool unit
				rte_mempool_put(meta_mempool, meta[idx]);
			}			
		
		}
		if (likely(long_count) > 0)
		{
			handled += long_count;
			//printf("received %u metas\n", long_count);
			for (idx = 0; idx < long_count; idx++)
			{
				msg_t *tmp = (msg_t*)meta_payload[idx];
				if (rte_mempool_get(digger_mempool, &mem) == 0)
                {
					if (NULL != mem)
					{
                        //NOTE: Don't use memcpy here for performance's sakea
						msg = (msg_t*)mem;
                        msg->msg_size = tmp->msg_size;
                        msg->pkt_len = tmp->pkt_len;
                        msg->src_ip = tmp->src_ip;
                        msg->dst_ip = tmp->dst_ip;
                        msg->src_port = tmp->src_port;
                        msg->dst_port = tmp->dst_port;
                        msg->protocol = tmp->protocol;
                        msg->tcp_syn_flag = tmp->tcp_syn_flag;
                        msg->tcp_psh_flag = tmp->tcp_psh_flag;
                        msg->tcp_fin_flag = tmp->tcp_fin_flag;
                        msg->fragment= tmp->fragment;
                        msg->match_rule= tmp->match_rule;
                        msg->url_size = tmp->url_size;
						memcpy(msg->url, (char*)tmp + MSG_HDR_SIZE, msg->url_size);
                        if (rte_ring_enqueue(digger_ring, (void*)msg) != 0)
                        {
                        	rte_mempool_put(digger_mempool, mem);
                            drops++;
                        }
					}
					else{
						rte_mempool_put(digger_mempool, mem);
						drops++;
					}
                 }
                 else
                 {
                    drops++;
                 }
                 //anyway, free mempool unit
                 rte_mempool_put(meta_payload_mempool, meta_payload[idx]);

			}//end-of-for
		}//end-of-if
		if (likely(handled > 10000))
		{
			LogMessage(LOG_INFO, "digger handled %lu pkt info so far", handled);
			handled = 0;
		}
		if (unlikely(drops > 100000)) {
			LogMessage(LOG_INFO, "%s: drops %u\n", __func__, drops);
			drops = 0;
		}

		if ( 0xffffff == (loop_cnt++&0xffffff) ) {
		    numa_maps_c = user_rte_get_huge_maps();
		    if ( 0 == numa_maps_c ) {
		        syslog(LOG_INFO, "%s(digger): RTE_EAL missing, check for "
		                "problem and restart me.\n", __func__);
		        exit(0);
		    }
		    else {
		        syslog(LOG_INFO, "%s(digger): RTE_EAL active.\n", __func__);
		    }
		}
	}
	return NULL;
}

/**
 *	Purpose:	process messages from message queues
 *	Input:		message vector
 *	Output:		alerting  IP/URL/DNS in blacklist
 *					alerting  traffic that has ratios in accordance with trojans/worms/backdoors
 *					calculating TCP session data
 *					calculate geo-based traffic and generate alerts
 *					calculate port-based traffic and generate alerts
 *	Return:		void*
 *	Author:		hittlle
 *	Date:		2017/06/07
 */
void *Handler(void *arg)
{
#ifndef MAX_HANDLER_NUM
#define MAX_HANDLER_NUM 8192
#endif
	msg_t *table[MAX_HANDLER_NUM];
	uint32_t count = 0;
	uint32_t idx = 0;
	msg_t *msg = NULL;
	struct in_addr src;
	struct in_addr dst;
	uint32_t processed = 0;

	while (1)
	{
	    count = rte_ring_dequeue_burst(digger_ring,(void**)&table, MAX_HANDLER_NUM);
		if (likely(count > 0))
		{
			for (idx = 0; idx < count; idx++)
			{
				msg = (msg_t*)table[idx];
        		portFlowStatistics(msg);
        		if (msg->url_size > 0)
        		{
        			suspiciousFlowChecker(msg);
        			AttackSuccessCheck(msg);
        		}
				rte_mempool_put(digger_mempool, (void*)msg);
			}//end-of-for
			processed += count;
		}//end-of-if
		if (processed >= 100000)
		{
			processed = 0;
			LogMessage(LOG_INFO, "%s: Processed another %u\n", __func__, processed);
		}
		
	}//end-of-while
	return NULL;
}

/**
 *      Purpose:        receive message from message queue
 *      Input:          UNIX domain socket
 *      Output:         message list
 *      Return:         void*
 *      Author:         hittlle
 *      Date:           2017/06/07
 */
void InitMemoryList(int argc, char **argv)
{
#ifndef MAX_TRY_TIMES
#define MAX_TRY_TIMES 120
#endif
	int count = 0;
	uint8_t /*sur_c, */numa_maps_c = 0;

	//Loop for ete_eal Primary ready
	while (1) {
	    numa_maps_c = user_rte_get_huge_maps();
	    if ( 0 == numa_maps_c ) {
	        syslog(LOG_INFO, "%s(digger): waiting primary RTE, numa_maps %d\n",
	                __func__, numa_maps_c);
	        sleep(1);
	    }
	    else {
            syslog(LOG_INFO, "%s(digger): primary RTE is ready, numa_maps %d\n",
                    __func__, numa_maps_c);
	        break;
	    }
	}

	if (rte_eal_init(argc, argv) < 0)
	{
		LogMessage(LOG_ERR, "rte_eal_init failed: %s", rte_strerror(rte_errno));
		exit(-1);
	}
	LogMessage(LOG_INFO, "EAL initialized successfully");
	//puts("EAL initialized successfully");
	while ((count < MAX_TRY_TIMES) && (NULL == meta_mempool || NULL == meta_payload_mempool || NULL == meta_ring || NULL == meta_payload_ring || NULL == digger_mempool||NULL == digger_ring))
	{
		meta_ring = rte_ring_lookup(META_RING);
		meta_payload_ring = rte_ring_lookup(META_PAYLOAD_RING);
		meta_mempool = rte_mempool_lookup(META_MEMPOOL);
		meta_payload_mempool = rte_mempool_lookup(META_PAYLOAD_MEMPOOL);
		digger_ring = rte_ring_lookup(DIGGER_RING);
		digger_mempool = rte_mempool_lookup(DIGGER_MEMPOOL);
		count++;
		//puts("Trying to lookup mempool and ring buffers created by surveyor");
		LogMessage(LOG_INFO, "Trying to lookup mempools and ring buffers created by surveyor");
		sleep(count);
	}
	if (NULL == meta_mempool || NULL == meta_payload_mempool || NULL == meta_ring || NULL == meta_payload_ring || NULL == digger_mempool||NULL == digger_ring)
	{
		LogMessage(LOG_ERR, "Failed to lookup mempools and ring buffers created by surveyor.Quitting...");
		exit(-1);
	}
	//puts("Successfully found mempools and ring buffers created by surveyor");
	LogMessage(LOG_INFO, "Successfully found mempools and ring buffers created by surveyor %lx.", (unsigned long)digger_mempool);
	return;
}

int main(int argc, char **argv)
{
	pthread_t receiver;
	pthread_t handler;
	pthread_t cleanup;
	pthread_t port_bps_update;
	pthread_t port_statistics_update;
	pthread_t port_benchmark_update;
	pthread_t geo;

    InitMySQLLibrary();
    InitLog();
    //parse possible attack-success configuration
    //if (argc == 2)
    {
    	if (ParseKeywordConfig("/opt/psi_nids/success_signature.txt") < 0)
    	{
    		LogMessage(LOG_ERR, "ParseKeywordConfig error.Quitting...");
    		exit(-1);
    	}
    }

    InitMemoryList(argc, argv);

    initSignal();
    initTimeZone();
    loadPortConfiguration();
    /*chad added,initialize maltrail*/
    holdTheSuspiciousDoor();
    holdTheFrontDoor();
    
    if (pthread_create(&receiver, NULL, Receiver, NULL) < 0)
    {
    	LogMessage(LOG_ERR, "Failed to create Receiver thread: %s", strerror(errno));
    	exit(-1);
    }
    if (pthread_create(&handler, NULL, Handler, NULL) < 0)
    {
    	LogMessage(LOG_ERR, "Failed to create Handler thread: %s", strerror(errno));
    	exit(-1);
    }
    
    if (pthread_create(&port_bps_update, NULL, updatePortBps, NULL) < 0)
    {
    	LogMessage(LOG_ERR, "Failed to create port bps update thread: %s", strerror(errno));
    	exit(-1);
    }
    if (pthread_create(&port_statistics_update, NULL, updatePortStatistics, NULL) < 0)
    {
    	LogMessage(LOG_ERR, "Failed to create port statistics update thread: %s", strerror(errno));
    	exit(-1);
    }
    if (pthread_create(&port_benchmark_update, NULL, generateBenchmark, NULL) < 0)
    {
    	LogMessage(LOG_ERR, "Failed to create port benchmark update thread: %s", strerror(errno));
    	exit(-1);
    }

    if (pthread_join(receiver, NULL) < 0)
    {
    	LogMessage(LOG_ERR, "Failed to join Receiver thread: %s", strerror(errno));
    	exit(-1);
    }
    if (pthread_join(handler, NULL) < 0)
    {
       	LogMessage(LOG_ERR, "Failed to join Handler thread: %s", strerror(errno));
       	exit(-1);
    }
    if (pthread_join(port_bps_update, NULL) < 0)
    {
       	LogMessage(LOG_ERR, "Failed to join port bps thread: %s", strerror(errno));
       	exit(-1);
    }
    if (pthread_join(port_statistics_update, NULL) < 0)
    {
       	LogMessage(LOG_ERR, "Failed to join port statistics thread: %s", strerror(errno));
       	exit(-1);
    }
    if (pthread_join(port_benchmark_update, NULL) < 0)
    {
       	LogMessage(LOG_ERR, "Failed to join port benchmark thread: %s", strerror(errno));
       	exit(-1);
    }
    DestroyMySQLLibrary();
	return 0;
}

