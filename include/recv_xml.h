#ifndef __XML_RECV__
#define __XML_RECV__
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <gnutls/gnutls.h>

#define MAX_JID_LEN 50
#define MAX_SHOW_LEN 10
#define MAX_STATUS_LEN 1024
#define MAX_MESSAGE_LEN 8192
#define MAX_XML_STREAM_LEN 8192

typedef enum {ST_STREAM, ST_BIND, ST_AVAILABLE, ST_UNAVAILABLE, ST_MESSAGE} Stanza_Type;

typedef struct {
	char *jid;
} Bind_Data;

typedef struct {
	char *jid;
	char *show;
	char *status;
} Available_Data;

typedef struct {
	char *jid;
} Unavailable_Data;

typedef struct {
	char *from;
	char *message;
} Message_Data;

typedef union {
	Bind_Data bind_data;
	Available_Data available_data;
	Unavailable_Data unavailable_data;
	Message_Data message_data;
} Stanza_Data;

typedef struct {
	Stanza_Type type;
	Stanza_Data data;
	char *stream;
} Xml_Stanza;

Xml_Stanza *recv_xml_stream(int sockfd);
Xml_Stanza *recv_tls_xml_stream(gnutls_session_t session);
#endif
