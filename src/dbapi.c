/*
 * dbapi.c
 *
 *  Created on: 2017-6-16
 *      Author: lzh
 */
#include "dbapi.h"
#include "common.h"

void CloseDBConn(MYSQL *pConn)
{
	mysql_close(pConn);
	mysql_thread_end();
}

int IsDBConnActive(MYSQL *pConn)
{
	return (mysql_ping(pConn) == 0);
}

MYSQL *CreateDBConn()
{
	MYSQL *pConn = NULL;

	pConn = mysql_init(NULL);
	if (NULL == pConn)
	{
		LogMessage(LOG_ERR, "Digger: MySQL initialization error");
		return NULL;
	}

	if (mysql_real_connect(
			pConn,
			HOST,
			USER,
			PWD,
			DB,
			0, NULL, 0) == NULL)
	{
		LogMessage(LOG_ERR, "digger: %s(code:%d)", mysql_error(pConn), mysql_errno(pConn));
		mysql_close(pConn);
		return NULL;
	}

    mysql_set_character_set(pConn, "utf8");
	return pConn;
}

/**
 * Purpose: initialize MySQL library routines
 * Input: 	N/A
 * Output: N/A
 * Return: 	void
 * Author: hittlle
 * Date: 2017/06/07
 */
void InitMySQLLibrary()
{
	TRACE();
	//the mysql client api is multithreaded?
	if (!mysql_thread_safe())
	{
		LogMessage(LOG_ERR, "digger: MySQL Client API is not thread safe");
		exit(EXIT_FAILURE);
	}

	//initialize mysql library for multithreading environment
	if (mysql_library_init(0, NULL, NULL) != 0)
	{
		LogMessage(LOG_ERR, "digger: cannot initialize MySQL library for multithreading");
		exit(EXIT_FAILURE);
	}
}
/**
 * Purpose: release MySQL library resources
 * Input: 	N/A
 * Output: N/A
 * Return: 	void
 * Author: hittlle
 * Date: 2017/06/07
 */
void DestroyMySQLLibrary()
{
	TRACE();
	mysql_library_end();
}

void FreeResult(MYSQL *conn, MYSQL_RES *res)
{
	if (NULL == res || NULL == conn)
		return;
	mysql_free_result(res);
	while (!mysql_next_result(conn))
	{
		res = mysql_store_result(conn);
		mysql_free_result(res);
	}
}

int ExecuteSql(MYSQL *conn, char* sql)
{
	if (NULL == conn || NULL == sql)
	{
		return -1;
	}
	if (mysql_real_query(conn, sql, strlen(sql)) != 0)
	{
		return -1;
	}
	return 0;
}

int StartTransaction(MYSQL *pConn)
{
	TRACE();
	char sql[BUFLEN + 1] = {0};
	sprintf(sql, "START TRANSACTION");
	if (mysql_real_query(pConn, sql, strlen(sql)) != 0)
	{
		LogMessage(LOG_ERR, "%s",mysql_error(pConn));
		return 0;
	}
	if (mysql_errno(pConn) == 0)
		return 1;
	else
		return 0;
}

int CommitTransaction(MYSQL *pConn)
{
	TRACE();
    char sql[BUFLEN + 1] = {0};
    sprintf(sql, "COMMIT");
    if (mysql_real_query(pConn, sql, strlen(sql)) != 0)
    {
    	LogMessage(LOG_ERR, "%s", mysql_error(pConn));
    	return 0;
    }
    if (mysql_errno(pConn) == 0)
    	return 1;
    else
    	return 0;
}
int RollBack(MYSQL *pConn)
{
	TRACE();
	char sql[BUFLEN] = {0};
	sprintf(sql, "ROLLBACK");
	if (mysql_real_query(pConn, sql, strlen(sql)) != 0)
	{
		LogMessage(LOG_ERR, "%s", mysql_error(pConn));
		return 0;
	}
	if (mysql_errno(pConn) == 0)
		return 1;
	else
		return 0;
}
