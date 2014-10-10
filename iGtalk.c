/*
** client.c -- a stream socket client demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include "./include/recv_xml.h"
#include "./include/gsasl.h"

#include <termios.h>

#define MAX_BUF     1024
#define BUF_SIZE    100
#define CAFILE      "/etc/ssl/certs/ca-certificates.crt"
#define MSG         "GET / HTTP/1.0\r\n\r\n"

typedef struct {
    char userBuf[BUF_SIZE];
    char passBuf[BUF_SIZE];
} UsernamePassword;

typedef struct {
	char *jid;
	char *show;
	char *status;
} PeerUser;

/* part 2 sent msg */
char *startContact = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='gmail.com' version='1.0'>";

/* part 4 sent msg */
char *startTls = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";

/* part 5 sent msgs */
char *startAuth = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='gmail.com' version='1.0'>";
char *authOpenTag = "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN' xmlns:ga='http://www.google.com/talk/protocol/auth' ga:client-uses-full-bind-result='true'>";
char *authCloseTag = "</auth>";
char *encodedOutput = NULL;

/* part 6 sent msgs */
char *initiateStream = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='gmail.com' version='1.0'>";
char *startBind = "<iq type='set' id='bind_1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>gmail.</resource></bind></iq>";
char *establishSession = "<iq to='gmail.com' type='set' id='sess_1'><session xmlns='urn:ietf:params:xml:ns:xmpp-session'/></iq>";
char *notifyFriends = "<presence/>";

int sockfd;
Xml_Stanza *servResp = NULL;
UsernamePassword usernamePassword;

gnutls_session_t gnutls_sess;
gnutls_certificate_credentials_t xcred;

char *p = NULL;
char *myJid = NULL;
char *recipientUsername = NULL;
PeerUser **rosterList;

/* part 2 methods */
void *get_in_addr(struct sockaddr *sa);
ssize_t writeN(int sockfd, const void *ptr, size_t n);
void establishConnection(int argc, char *argv[]);

/* part 4 methods */
void performTlsHandshake();

/* part 5 methods */
void retrieveUsernamePassword();
void retrieveUserInfo(char *userInfoField);
void generateEncodedOutput();
static void initializeClient(Gsasl *ctx);
static void authenticateClient(Gsasl_session * session);
void sendEncodedOutput();

/* part 7/8/9 methods */
void performMainChatSession();
void handleServerMsg();
void addPeerUser();
void removePeerUser();
int handleKeyboardInput(char *stdinBuf);
int executeCommand(char *stdinBuf);
void printRosterList();
char *getUsernameFromJid(char *jid) ;
char *getJidFromUsername(char *username);
void sendGtalkMessage(char *stdinBuf);
void sendTerminateElements();
void cleanUp(char *stdinBuf);

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/* 
 * Write N bytes to a socket file descriptor.
 * Keep writing until N bytes are written, or if an error occurs.
 * Returns -1 if no bytes are written and an error occurs during write.
 * Returns number of bytes written so far if error occurs during write,
 *  or if no error and no bytes are written (server closes file descriptor).
 */
ssize_t writeN(int sockfd, const void *ptr, size_t n)
{
    size_t nLeft;
    ssize_t nWritten;
    nLeft = n;
    while (nLeft > 0) {
        if ((nWritten = write(sockfd, ptr, nLeft)) < 0) {
            if (nLeft == n) {
                return -1;  // error, return -1
            }
            else {
                break;  // error, return amount written so far
            }
        }
        else {
            if (nWritten == 0) {
                break;
            }
        }
        nLeft -= nWritten;
        ptr += nWritten;
    }
    return n - nLeft; // return >= 0
}

/* 
 * Establishes a socket connection.
 */
void establishConnection(int argc, char *argv[])
{
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];

	if (argc != 3) {
	    fprintf(stderr,"usage: client hostname hostport\n");
	    exit(1);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(argv[1], argv[2], &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		exit(1);
	}

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("client: connect");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		exit(2);
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
			s, sizeof s);
	// printf("client: connecting to %s\n", s);

	freeaddrinfo(servinfo);
}

/*
 * Performs a TLS handshake to create a secure session with libgnutls.
 */
void performTlsHandshake()
{
    int ret, sd, ii;
    char buffer[MAX_BUF + 1];
    const char *err;

    gnutls_global_init();

    // X509 stuff
    gnutls_certificate_allocate_credentials (&xcred);

    // sets the trusted cas file
    gnutls_certificate_set_x509_trust_file (xcred, CAFILE, GNUTLS_X509_FMT_PEM);

    // initialize TLS session 
    gnutls_init (&gnutls_sess, GNUTLS_CLIENT); 
    gnutls_session_set_ptr(gnutls_sess, (void *) "my_host_name");
    gnutls_server_name_set(gnutls_sess, GNUTLS_NAME_DNS, "my_host_name", strlen("my_host_name"));

    // use default priorities 
    ret = gnutls_priority_set_direct (gnutls_sess, "NORMAL", &err);
    if (ret < 0) {
        if (ret == GNUTLS_E_INVALID_REQUEST) {
            fprintf(stderr, "Syntax error at: %s\n", err);
        }
        exit(1);
    }

    // put the x509 credentials to the current session
    gnutls_credentials_set(gnutls_sess, GNUTLS_CRD_CERTIFICATE, xcred);

    // connect to the peer
    gnutls_transport_set_ptr(gnutls_sess, (gnutls_transport_ptr_t) sockfd);

    // perform the TLS handshake
    do {
        ret = gnutls_handshake(gnutls_sess);
    }
    while((ret < 0 && gnutls_error_is_fatal(ret) == 0) || ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

    if (ret < 0) {
        fprintf(stderr, "*** Handshake failed\n");
        gnutls_perror(ret);
    	
    	gnutls_deinit(gnutls_sess);
    	gnutls_certificate_free_credentials(xcred);
    	gnutls_global_deinit();
    	gnutls_bye(gnutls_sess, GNUTLS_SHUT_RDWR);
    }
    else {
        // printf("- Handshake was completed\n");
    }
}

/*
 * Retrieves a username and password from stdin. During retrieval,
 * echoing will be turned off to enable encryption.
 */
void retrieveUsernamePassword()
{
    struct termios tp, save;

    // retrieve current terminal settings, turn echoing off
    if (tcgetattr(STDIN_FILENO, &tp) == -1) {
        fprintf(stderr, "tcgetattr");
        exit(1);
    }
    save = tp;                          // so we can restore settings later
    tp.c_lflag &= ~ECHO;                // ECHO off, other bits unchanged
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &tp) == -1) {
        fprintf(stderr, "tcsetattr");
        exit(1);
    }
    
    retrieveUserInfo("Username");
    retrieveUserInfo("Password");
     
    // restore original terminal settings
    if (tcsetattr(STDIN_FILENO, TCSANOW, &save) == -1) {
        fprintf(stderr, "tcsetattr");
        exit(1);
    }
}

/* Helper function for retrieveUsernamePassword.
 * Prompts user for username and password and stores input
 * into a global struct.
 */
void retrieveUserInfo(char *userInfoField)
{   
    char *retVal = NULL;
    char *whichBuf = NULL;

	printf("%s: ", userInfoField);
    fflush(stdout);
      
    if (strcmp(userInfoField, "Username") == 0) {   
        retVal = fgets(usernamePassword.userBuf, BUF_SIZE, stdin);
        whichBuf = usernamePassword.userBuf;
    }
    else if (strcmp(userInfoField, "Password") == 0) {
        retVal = fgets(usernamePassword.passBuf, BUF_SIZE, stdin);
        whichBuf = usernamePassword.passBuf;
    }
    else {
        fprintf(stderr, "readUserInfo: userInfoField");
        exit(1);
    }

	// end of file encountered while trying to read a char
    if (retVal == NULL) {
        printf("Got end-of-file/error on fgets()\n");
    }
    
    // remove newline
    else {
        char *newline = strchr(whichBuf, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }
    }
    printf("\n");
}

/* Generated encoded username and password to send to Google servers
 * to be matched with existing account.
 */
void generateEncodedOutput() 
{
    Gsasl *ctx = NULL;
    int rc;
 
    // initialize library
    if ((rc = gsasl_init(&ctx)) != GSASL_OK)
    {
       printf("Cannot initialize libgsasl(%d): %s", rc, gsasl_strerror(rc));
       exit(1);
    }
 
    // do it
    initializeClient(ctx);

    // cleanup
    gsasl_done(ctx);
}

/* Helper functions for generateEncodedOutput()
 */
static void initializeClient(Gsasl *ctx)
{
    Gsasl_session *session;
    const char *mech = "PLAIN";
    int rc;

    // create new authentication session
    if ((rc = gsasl_client_start(ctx, mech, &session)) != GSASL_OK) {
       printf("Cannot initialize client(%d): %s\n", rc, gsasl_strerror(rc));
       exit(1);
    }

    // set username and password in session handle
    // this info will be lost when this session is deallocated below
    gsasl_property_set(session, GSASL_AUTHID, usernamePassword.userBuf);
    gsasl_property_set(session, GSASL_PASSWORD, usernamePassword.passBuf);

    // do it
    authenticateClient(session);

    // cleanup
    gsasl_finish(session);
}

static void authenticateClient(Gsasl_session * session)
{
	char buf[BUFSIZ] = "";
    int rc;
    do {
        // generate client output
        // output is in p
        rc = gsasl_step64(session, buf, &p);
        if (rc == GSASL_NEEDS_MORE || rc == GSASL_OK) {
            // if successful, print it
            // printf("Output: %s\n", p);
        }
        if (rc == GSASL_NEEDS_MORE) {
            // if the client need more data from server, get it here
            printf("Input base64 encoded data from server:\n");
            p = fgets(buf, sizeof(buf) - 1, stdin);
      
            if (p == NULL) {
                perror("fgets");
                return;
            }
            if (buf[strlen(buf) - 1] == '\n') {
                buf[strlen(buf) - 1] = '\0';
            }
        }
    } while (rc == GSASL_NEEDS_MORE);
    printf ("\n");

    if (rc != GSASL_OK) {
        printf("Authentication error(%d): %s\n", rc, gsasl_strerror(rc));
        exit(1);
    }
}

/* Sends encoded username and password to Google servers to be matched for
 * existing account.
 */
void sendEncodedOutput()
{
    gnutls_record_send(gnutls_sess, (const void *) startAuth, strlen(startAuth)); 
    while ((servResp = recv_tls_xml_stream(gnutls_sess)) == NULL);
    while ((servResp = recv_tls_xml_stream(gnutls_sess)) == NULL);

    encodedOutput = (char *) malloc(strlen(authOpenTag) + strlen(authCloseTag) + strlen(p) + 1);
    strcpy(encodedOutput, authOpenTag);
    strcat(encodedOutput, p);
    strcat(encodedOutput, authCloseTag);
    
    gnutls_record_send(gnutls_sess, (const void *) encodedOutput, strlen(encodedOutput));
    while ((servResp = recv_tls_xml_stream(gnutls_sess)) == NULL);
}

/* Main chat session loop 
 */
void performMainChatSession() 
{
	fd_set readfds;
	int stdinfd = fileno(stdin);
	int nfds = sockfd+1;
	char *stdinBuf = NULL;
	rosterList = (PeerUser **) malloc(sizeof(PeerUser *)*100);
	int i;
	for (i=0; i<100; ++i) {
		rosterList[i] = NULL;
	}
	
	while (1) {
	
		// reinitialize
		fflush(stdin);
		fflush(stdout);
		FD_ZERO(&readfds);
		FD_SET(stdinfd, &readfds);
		FD_SET(sockfd, &readfds);
		stdinBuf = malloc(MAX_BUF);
		
		// select
		if (select(nfds, &readfds, NULL, NULL, NULL) == -1) {
			fprintf(stderr, "select");
			exit(1);
		}
		
		// server
		if (FD_ISSET(sockfd, &readfds)) {
			handleServerMsg(stdinBuf);
		}
	
		// keyboard
		if (FD_ISSET(stdinfd, &readfds)) {
			if (handleKeyboardInput(stdinBuf)) {
				break;
			}
		}

		free(stdinBuf);
		stdinBuf = NULL;
	}
}

/* Hands actions upon reception of all server messages.
 */
void handleServerMsg()
{
	// for command lags after recv msg
	// select still thinks there's msgs to be read, so it was hanging on the while loop
	if ((servResp = recv_tls_xml_stream(gnutls_sess)) != NULL) {
		if (servResp->type == ST_AVAILABLE) {
			addPeerUser();
		}
		else if (servResp->type == ST_UNAVAILABLE) {
			removePeerUser();
		}
		else if (servResp->type == ST_MESSAGE) {
			char *username = getUsernameFromJid((servResp->data).message_data.from);
			printf("%s: %s\n", username, (servResp->data).message_data.message);
			free(username);
		}
	}
}

/* Adds a friend to the roster list, or if it's already there, updates it */
void addPeerUser() 
{
	int i;
	// first loop tries to update
	for (i=0; i<100; ++i) {
		if (rosterList[i] != NULL && strcmp(rosterList[i]->jid, (servResp->data).available_data.jid) == 0) {
			free(rosterList[i]->show);
			free(rosterList[i]->status);
			rosterList[i]->show = malloc(strlen((servResp->data).available_data.show)+1);
			rosterList[i]->status = malloc(strlen((servResp->data).available_data.status)+1);
			strcpy(rosterList[i]->show, (servResp->data).available_data.show);
			strcpy(rosterList[i]->status, (servResp->data).available_data.status);
			return;
		}
	}
	// second loop adds
	for (i=0; i<100; ++i) {
		if (rosterList[i] == NULL) {
			rosterList[i] = malloc(sizeof(PeerUser));
			rosterList[i]->jid = malloc(strlen((servResp->data).available_data.jid)+1);
			rosterList[i]->show = malloc(strlen((servResp->data).available_data.show)+1);
			rosterList[i]->status = malloc(strlen((servResp->data).available_data.status)+1);
			strcpy(rosterList[i]->jid, (servResp->data).available_data.jid);
			strcpy(rosterList[i]->show, (servResp->data).available_data.show);
			strcpy(rosterList[i]->status, (servResp->data).available_data.status);
			return;
		}
	}
}

/* Removes a friend from the roster list */
void removePeerUser() {
	int i;
	for (i=0; i<100; ++i) {
		if (rosterList[i] != NULL && strcmp(rosterList[i]->jid, (servResp->data).available_data.jid) == 0) {
			free(rosterList[i]->jid);
			free(rosterList[i]->show);
			free(rosterList[i]->status);
			free(rosterList[i]);
			rosterList[i] = NULL;
			return;
		}
	}
}

/* Handles all keyboard input from user.
 */
int handleKeyboardInput(char *stdinBuf)
{
	// end of file encountered while trying to read a char
	if (fgets(stdinBuf, BUF_SIZE, stdin) == NULL) {
		printf("Got end-of-file/error on fgets()\n");
	}
    // remove newline
    else {
        char *newline = strchr(stdinBuf, '\n');
        if (newline != NULL) {
    		*newline = '\0';
        }
    }
    
    // command
    if (stdinBuf[0] == ':') {
		if (executeCommand(stdinBuf)) {
			return 1;
		}
    }
    		
    // message
    else {
    	char *jidRetVal = NULL;
    	if (recipientUsername != NULL && (jidRetVal = getJidFromUsername(recipientUsername)) != NULL) {
    		free(jidRetVal);
    		sendGtalkMessage(stdinBuf);
    	}
    	/* else {
    		printf("message not sent - recipient not set or not available\n\n");
    	}*/
    }
    return 0;
}

/* Handles all user commands from keyboard.
*/
int executeCommand(char *stdinBuf)
{
	// roster
    if (strcmp(stdinBuf+1, "roster") == 0) {
    	printRosterList();
    	return 0;
    }
    // set recipient
    else if (strncmp(stdinBuf+1, "to ", 3) == 0) {
    	char *jidRetVal = NULL;
    	if ((jidRetVal = getJidFromUsername(stdinBuf+4)) != NULL) {
    		free(jidRetVal);
    		free(recipientUsername);
    		recipientUsername = NULL;
    		recipientUsername = malloc(strlen(stdinBuf+4)+1);
    		strcpy(recipientUsername, stdinBuf+4);
    		// printf("recipient set: %s\n\n", recipientUsername);
    	}
    	/* else {
    		printf("recipient not in roster list\n");
    		printf("recipient is: %s\n\n", recipientUsername);
    	} */
    	return 0;
    }
    // quit
    else if (strcmp(stdinBuf+1, "q") == 0) {
    	sendTerminateElements();
    	cleanUp(stdinBuf);
    	return 1;
    }
}

/* Prints entire roster list.
 */
void printRosterList() 
{
	int i;
	char *presInfoBuf = NULL;
	char *username = NULL;
	char *show = NULL;
	char *status = NULL;
	
	for (i=0; i<100; ++i) {
		if (rosterList[i] != NULL) {
		
			// get buffer info
			username = getUsernameFromJid(rosterList[i]->jid);
			show = rosterList[i]->show;
			status = rosterList[i]->status;
			
			printf("%s\t%s\n\t%s\n", show, username, status); 
			
			// cleanup
			free(username);
			username = NULL;
		}
	}
}

/* Gets a username from a jid.
 */
char *getUsernameFromJid(char *jid) 
{
	char *secondHalf = strchr(jid, '/');
	size_t usernameLength = strlen(jid) - strlen(secondHalf);
	char *username = malloc(usernameLength+1);
	strncpy(username, jid, usernameLength);
	username[usernameLength] = '\0';
	return username;
}

/* Gets a jid from a username.
 */
char *getJidFromUsername(char *username)
{
	char *jid = NULL;
	char *usernameFromJid = NULL;
	int i;
	for (i=0; i<100; ++i) {
		if (rosterList[i] != NULL) {
			usernameFromJid = getUsernameFromJid(rosterList[i]->jid);
			if (strcmp(username, usernameFromJid) == 0) {
				free(usernameFromJid);
				jid = malloc(strlen(rosterList[i]->jid)+1);
				strcpy(jid, rosterList[i]->jid);
				return jid;
			}
			free(usernameFromJid);
			usernameFromJid = NULL;
		}
	}
	return NULL; // not found in roster list
}

/* Sends a Gtalk message to a recipient. 
 */
void sendGtalkMessage(char *stdinBuf) 
{
	char *first = "<message to='";
	char *recipientJid = getJidFromUsername(recipientUsername);
	char *second = "' from='";
	char *senderJid = myJid;
	char *third = "' type='chat' xml:lang='en'><body>";
	char *message = stdinBuf;
	char *fourth = "</body></message>";
	
	char *sendBuf = malloc(strlen(first) +
					  	   strlen(recipientJid) + 
					  	   strlen(second) + 
					  	   strlen(senderJid) + 
					  	   strlen(third) + 
					  	   strlen(message) + 
					  	   strlen(fourth) + 1);
	strcpy(sendBuf, first);
	strcat(sendBuf, recipientJid);
	strcat(sendBuf, second);
	strcat(sendBuf, senderJid);
	strcat(sendBuf, third);
	strcat(sendBuf, message);
	strcat(sendBuf, fourth);
	
	gnutls_record_send(gnutls_sess, (const void *) sendBuf, strlen(sendBuf));
	free(sendBuf);
	free(recipientJid);
}

/* Sends terminate xml elements to notify Gtalk to exit session.
 */
void sendTerminateElements()
{
    char *firstMsgHeader = "<presence from='";
    char *senderJid = myJid;
    char *firstMsgFooter = "' type='unavailable'/>";
    				
    char *sendBuf = malloc(strlen(firstMsgHeader) + 
    					   strlen(senderJid) + 
    					   strlen(firstMsgFooter) + 
    					   1);
    strcpy(sendBuf, firstMsgHeader);
    strcat(sendBuf, senderJid);
   	strcat(sendBuf, firstMsgFooter);
   	gnutls_record_send(gnutls_sess, (const void *) sendBuf, strlen(sendBuf));
    free(sendBuf);
    sendBuf = NULL;
    				
    char *secondMsg = "</stream:stream>";
    sendBuf = malloc(strlen(secondMsg) + 1);
    strcpy(sendBuf, secondMsg);
    gnutls_record_send(gnutls_sess, (const void *) sendBuf, strlen(sendBuf));
    free(sendBuf);
    sendBuf = NULL;
}

/* Frees all allocated memory and closes file descriptors.
 */
void cleanUp(char *stdinBuf)
{
	// shutdown socket file descriptor
 	shutdown(sockfd, SHUT_RDWR);
    close(sockfd);
    
    // free gsasl
    gsasl_free(p);
    
    // shutdown gnutls
    gnutls_bye(gnutls_sess, GNUTLS_SHUT_RDWR);
    gnutls_deinit(gnutls_sess);
    gnutls_certificate_free_credentials(xcred);
    gnutls_global_deinit();
    
    // free memory
    free(myJid);
    free(recipientUsername);
    free(encodedOutput);
    int i;
    for (i=0; i<100; ++i) {
    	if (rosterList[i] != NULL) {
    		free(rosterList[i]->jid);
    		free(rosterList[i]->show);
    		free(rosterList[i]->status);
    		free(rosterList[i]);
    	}
    }
    free(rosterList);
    free(stdinBuf);
}


int main(int argc, char *argv[])
{
	/* part 2 first contact with google */
	establishConnection(argc, argv);
    writeN(sockfd, (const void *) startContact, strlen(startContact));

    /* part 3 sending and receiving xml streams */
    while ((servResp = recv_xml_stream(sockfd)) == NULL);
    while ((servResp = recv_xml_stream(sockfd)) == NULL);
   
    /* part 4 creating a tls secure session with libgnutls */
    writeN(sockfd, (const void *) startTls, strlen(startTls));
    while ((servResp = recv_xml_stream(sockfd)) == NULL);
    performTlsHandshake();
    
    /* part 5 completing an SASL PLAIN authentication with libgsasl */
    retrieveUsernamePassword();
    generateEncodedOutput();
    sendEncodedOutput();

    /* part 6 binding a resource and establishing a session */
    gnutls_record_send(gnutls_sess, (const void *) initiateStream, strlen(initiateStream));
    while ((servResp = recv_tls_xml_stream(gnutls_sess)) == NULL);
    while ((servResp = recv_tls_xml_stream(gnutls_sess)) == NULL);
	
	gnutls_record_send(gnutls_sess, (const void *) startBind, strlen(startBind));
	while ((servResp = recv_tls_xml_stream(gnutls_sess)) == NULL);
    myJid = (char *) malloc(strlen((servResp->data).bind_data.jid)+1);
    strcpy(myJid, (servResp->data).bind_data.jid);
    
	gnutls_record_send(gnutls_sess, (const void *) establishSession, strlen(establishSession));
    while ((servResp = recv_tls_xml_stream(gnutls_sess)) == NULL);
	
	gnutls_record_send(gnutls_sess, (const void *) notifyFriends, strlen(notifyFriends));
	
	/* part 7 handling multiple inputs with select() */
	/* part 8 handling presence information and instant messages */
	/* part 9 ending a session */
	performMainChatSession();
	
	return 0;
}

