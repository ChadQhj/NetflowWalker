/*
 * common.c
 *
 *  Created on: 2017-6-7
 *      Author: Chad
 */

#include "common.h"
#include <ctype.h>
#include <string.h>
#include "dbapi.h"

void InitLog()
{
	TRACE();
	openlog("digger", LOG_CONS | LOG_PID, 0);
}

void LogMessage(int level, const char* format,...)
{
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
 *	Purpose:	check whether a IP is local/protected IP or not
 *	Input:		struct in_addr
 *	Output:		void
 *	Return:		int
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




