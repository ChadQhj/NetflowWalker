/*
 * dbapi.h
 *
 *  Created on: 2017-6-16
 *      Author: lzh
 */

#ifndef DBAPI_H_
#define DBAPI_H_

#include <mysql/mysql.h>
#include <string.h>

#ifndef _CONFIG_MYSQL_KEYS
#define _CONFIG_MYSQL_KEYS
#define HOST "127.0.0.1"
#define USER "root"
#define PWD "13246"
#define DB "surveyor"
#endif

/**
 * Purpose: initialize MySQL library routines
 * Input: 	N/A
 * Output: N/A
 * Return: 	void
 * Author: hittlle
 * Date: 2017/06/07
 */
void InitMySQLLibrary();
/**
 *	Purpose:	create MySQL connection
 *	Input:		MySQL host ip, user name, password and database name
 *	Output:		connection to MySQL server
 *	Return:		MYSQL*
 *	Author:		hittlle
 *	Date:		2017/06/07
 */
MYSQL *CreateDBConn();
/**
 *	Purpose:	close MySQL connection
 *	Input:		MYSQL pointer
 *	Output:		void
 *	Return:		void
 *	Author:		hittlle
 *	Date:		2017/06/07
 */
void CloseDBConn(MYSQL *pConn);
/**
 *	Purpose:	check whether a MySQL connection is active or not
 *	Input:		MYSQL pointer
 *	Output:		void
 *	Return:		int
 *	Author:		hittlle
 *	Date:		2017/06/07
 */
int IsDBConnActive(MYSQL *pConn);
/**
 * Purpose: release MySQL library resources
 * Input: 	N/A
 * Output: N/A
 * Return: 	void
 * Author: hittlle
 * Date: 2017/06/07
 */
void DestroyMySQLLibrary();
void FreeResult(MYSQL *, MYSQL_RES *);
int ExecuteSql(MYSQL *, char*);

int StartTransaction(MYSQL *pConn);
int CommitTransaction(MYSQL *pConn);
int RollBack(MYSQL *pConn);

#endif /* DBAPI_H_ */
