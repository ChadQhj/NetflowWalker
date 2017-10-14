/*
 * common.c
 *
 *  Created on: 2017-6-7
 *      Author: lzh
 */

#include "common.h"
#include <ctype.h>
#include <string.h>
#include "dbapi.h"

void YieldCpu(int iInterval)
{
	TRACE();
	//pthread_yield();
	sleep(iInterval);
}

/**
 * Purpose: initialize log routine
 * Input: 	N/A
 * Output: N/A
 * Return: void
 * Author: hittlle
 * Date: 2017/06/07
 */
void InitLog()
{
	TRACE();
	openlog("digger", LOG_CONS | LOG_PID, 0);
}
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
void LogMessage(int level, const char* format,...)
{
	//TRACE();
	char buf[BUFLEN];
	va_list va;
	memset(buf, 0, BUFLEN);
	va_start(va, format);
	vsnprintf(buf, BUFLEN, format, va);
	va_end(va);
#ifdef DEBUG
	fprintf(stdout, "%s\n", buf);
#endif
	syslog(level, "%s", buf);
}

/**
 * Purpose: create a UNIX domain socket
 * Input: 	UNIX domain socket file path
 * Output: socket descriptor
 * Return: socket descriptor on success, -1 on failure
 * Author: hittlle
 * Date: 2017/06/07
 */
int CreateMessageSocket(const char* path)
{
	int fd = -1;
	struct sockaddr_un addr;
	bzero(&addr, sizeof(struct sockaddr_un));

	if (NULL == path || strlen(path) == 0)
	{
		return -1;
	}

	//unlink path
	unlink(path);

	if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
	{
		LogMessage(LOG_ERR, "CreateMessageSocket socket error: %s", strerror(errno));
		return -1;
	}
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);
	if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		LogMessage(LOG_ERR, "CreateMessageSocket bind error: %s", strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

/**
 *	Purpose:	check whether a IP is local/protected IP or not
 *	Input:		struct in_addr
 *	Output:		void
 *	Return:		int
 *	Author:		hittlle
 *	Date:		2017/06/07
 */

#ifndef MAX_PROTECTED_CONFIG
#define MAX_PROTECTED_CONFIG 4096
#endif
struct net_pair {
	uint32_t netid;
	uint32_t mask;
};
static struct net_pair protected_subnets[MAX_PROTECTED_CONFIG];
int isProtectedIp(uint32_t tip)
{
	MYSQL_RES *pRes = NULL;
	MYSQL_ROW pRow = NULL;
	char sql[1024] = {0};
	static time_t lastTime = 0;
	char part[20] = {0};
	static uint16_t count = 0;
	uint16_t idx = 0;
	char *prev = NULL, *iter = NULL, *tmp = NULL;
	time_t current = time(NULL);
	static MYSQL *pConn = NULL;
	//query database every 10 seconds
	if (current - lastTime > 120) {
		if (NULL == pConn) {
			pConn = CreateDBConn();
		} else if (!IsDBConnActive(pConn)) {
			CloseDBConn(pConn);
			pConn = CreateDBConn();
		}
		if (NULL == pConn) {
			LogMessage(LOG_ERR, "Cannot create db connection in isProtectedIp");
			return 0;
		}
		sprintf(sql, "SELECT home_net FROM `intranet_config`");
		if (ExecuteSql(pConn, sql) != 0) {
			LogMessage(LOG_ERR, "IsConfigProtected error 1: %s--%s", mysql_error(pConn), sql);
			return 0;
		}
		pRes = mysql_store_result(pConn);
		if (NULL == pRes) {
			LogMessage(LOG_ERR, "IsConfigProtected error 2: %s", mysql_error(pConn));
			return 0;
		}
		pRow = mysql_fetch_row(pRes);
		if (NULL == pRow) {
			FreeResult(pConn, pRes);
			return 0;
		}
		if (NULL != pRow[0]) {
			prev = pRow[0];
			while(isspace(*prev) || (*prev=='[')) prev++;
			iter = prev;
			while((*iter != '\0') && (idx < MAX_PROTECTED_CONFIG)) {
				if (*iter==',' || *iter==']') {
					bzero(part, 20);
					strncpy(part, prev, iter - prev);
					LogMessage(LOG_INFO, "protected ip subnet: %s", part);

					tmp = strstr(part, "/");
					if (NULL != tmp) {
						*tmp = '\0';
						tmp++;
						if(*tmp != '\0')
							protected_subnets[idx].mask = atoi(tmp);
						else
							protected_subnets[idx].mask = 0;
					} else {
						protected_subnets[idx].mask = 0;
					}
					protected_subnets[idx].netid = inet_addr(part);
					LogMessage(LOG_INFO, "netid: %s, mask: %u", part, protected_subnets[idx].mask);
					idx++;
					prev = iter + 1;
				}
				iter++;
			}//end-of-while
			count = idx;
		}
		FreeResult(pConn, pRes);
		lastTime = current;
	}//end-of-if
	//LogMessage(LOG_INFO, "Total %d subnet masks", count);
	uint32_t numIp = tip;
	uint32_t mask = 0;
	for (idx = 0; idx < count; idx++) {
		if (protected_subnets[idx].mask == 0) {
			if (protected_subnets[idx].netid == numIp)
				return 1;
		} else {
			mask = (1<<protected_subnets[idx].mask)-1;
			//LogMessage(LOG_INFO, "mask: 0x%X, netid: 0x%X, ip: 0x%X", mask, protected_subnets[idx].netid, numIp);
			if ((protected_subnets[idx].netid & mask) == (numIp & mask))
				return 1;
		}
	}
	return 0;
}




