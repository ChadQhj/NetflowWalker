
#ifndef _ATTACK_SUCESS_CHECK_H_
#define _ATTACK_SUCESS_CHECK_H_

#include "common.h"

#ifndef MAX_KEYWORD_SIZE
#define MAX_KEYWORD_SIZE 64
#endif

#ifndef HTTP_TAG
#define HTTP_TAG "http"
#endif

#ifndef FTP_TAG
#define FTP_TAG "ftp"
#endif

#ifndef DNS_TAG
#define DNS_TAG "dns"
#endif

#ifndef SMTP_TAG
#define SMTP_TAG "smtp"
#endif

#ifndef SNMP_TAG
#define SNMP_TAG "snmp"
#endif

#ifndef POP3_TAG
#define POP3_TAG "pop3"
#endif

#ifndef IMAP_TAG
#define IMAP_TAG "imap"
#endif

typedef struct _node
{
	char *keyword;
	char label[MAX_KEYWORD_SIZE];
	struct _node *next;
}node_t;

enum {
	HTTP,
	FTP,
	DNS,
	SMTP,
	SNMP,
	POP3,
	IMAP,
	TYPE_NONE
};


void AttackSuccessCheck(msg_t* msg);
int ParseKeywordConfig(const char* path);

#endif
