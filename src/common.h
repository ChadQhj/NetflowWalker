/*
 * common.h
 *
 *  Created on: 2017-6-7
 *      Author: lzh
 */

#ifndef COMMON_H_
#define COMMON_H_

//--------------------LINUX POSIX headers------------------
#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <syslog.h>
#include <pthread.h>
#include <arpa/inet.h>

//--------------------Project headers-------------------------
//------------------Macros-----------------------------------
#ifdef DEBUG
#define TRACE() do{\
			fprintf(stdout, "Enter %s\n", __func__);\
		}while(0)
#else
#define TRACE() do{\
			LogMessage(LOG_ERR, "Enter %s ", __func__);\
	}while(0)
#endif

//------------------Constants---------------------------------
#ifndef RECEIVE_PATH
#define RECEIVE_PATH "/tmp/digger-queue-001"
#endif

#ifndef PROTO_TCP
#define PROTO_TCP 6
#endif

#ifndef PROTO_UDP
#define PROTO_UDP 17
#endif

#ifndef PROTO_ICMP
#define PROTO_ICMP 1
#endif

#ifndef PROTO_SCTP
#define PROTO_SCTP 132
#endif
#ifndef HANDLER_INTERVAL
#define HANDLER_INTERVAL 1
#endif

#ifndef CLEANUP_INTERVAL
#define CLEANUP_INTERVAL 30 * 24 * 60 * 60
#endif

#ifndef BUFLEN
#define BUFLEN 2048
#endif

#ifndef MAX_PAYLOAD_SIZE
#define MAX_PAYLOAD_SIZE 4064
#endif
//------------------Prototypes--------------------------------
typedef struct _message
{
	/**
	 * total message size
	 */
	uint32_t msg_size;
	/**
	 * packet length
	 */
	uint32_t pkt_len;
	/**
	 * source ip
	 */
	uint32_t src_ip;
	/**
	 * destination ip
	 */
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	/**
	 * Valid option: PROTO_TCP, PROTO_UDP, PROTO_ICMP, PROTO_SCTP
	 */
	uint8_t protocol;
	/**
	 * if protocol == PROTO_TCP, then the following three fields make sense;
	 */
	uint8_t tcp_syn_flag;
	uint8_t tcp_psh_flag;
	uint8_t tcp_fin_flag;
	/**
	 * if url_size == 0, just ignore the following url; otherwise, this field indicates the size of url
	 */
    uint8_t fragment;
    uint8_t src_is_protected;
    uint8_t dst_is_protected;
    uint8_t match_rule;
	uint32_t url_size;
	char url[MAX_PAYLOAD_SIZE];
} msg_t;

#ifndef MSG_HDR_SIZE
#define MSG_HDR_SIZE 32 /*remember to modify it if you changed the struct msg_t,and change it in digger_msg.h too*/
#endif

#define STREAM_FIRST_NORMAL_FRAGMENT 0x01
#define STREAM_NEXT_NORMAL_FRAGMENT 0x02
#define STREAM_FIRST_REASSEMBLE_FRAGMENT 0x04


/**
 *  ---------------Globals defined here-----------------------------
 **/
int ParseKeywordConfig(const char* path);
void PrintKeywordConfig();
void AttackSuccessCheck(msg_t*);

/**
 * Purpose: initialize log routine
 * Input: 	N/A
 * Output: N/A
 * Return: void
 * Author: hittlle
 * Date: 2017/06/07
 */
void InitLog();
/**
 * Purpose: write log message to log system
 * Input:
 * 			level: log level, possible values are LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING,LOG_NOTICE,
 * 						  LOG_INFO, LOG_DEBUG
 * 			format: formatting string, the same as that of printf and sprintf
 * 			other arguments that may be given by the caller
 * Output: new log entry to the log system
 * Return: void
 * Author: hittlle
 * Date: 2017/06/07
 */
void LogMessage(int level, const char* format,...);
/**
 * Purpose: create a UNIX domain socket
 * Input: 	UNIX domain socket file path
 * Output: socket descriptor
 * Return: socket descriptor on success, -1 on failure
 * Author: hittlle
 * Date: 2017/06/07
 */
int CreateMessageSocket(const char* path);
/**
 *	Purpose:	check whether a IP is local/protected IP or not
 *	Input:		struct in_addr
 *	Output:		void
 *	Return:		int
 *	Author:		hittlle
 *	Date:		2017/06/07
 */
int isProtectedIp(uint32_t tip);

void YieldCpu(int iInterval);
#endif /* COMMON_H_ */
