/*
 * @file   UID_httpal.c
 *
 * @date   09/dec/2017
 * @author M. Palumbi
 */

/**
 * @file UID_httpal.h
 *
 * http access abstraction layer
 *
 */

#include <string.h>
#include <stdio.h>
#include "UID_httpal.h"




#include <netdb.h>
#include <unistd.h>
#include <stdbool.h>
#include <mbedtls/ssl.h>

#include "mbedtls/config.h"

#include "mbedtls/platform.h"
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"


//#define ENABLE_HTTP_DEBUG 1
#ifdef ENABLE_HTTP_DEBUG
#define UID_LOGLEVEL UID_LOG_DEBUG
#define MBEDTLS_DEBUG_BUFFER_SIZE 2048
#else
//#define UID_LOGLEVEL UID_LOG_ERROR
#endif
#include "UID_log.h"

#define PROTO_HTTP  0
#define PROTO_HTTPS 1


#define NETWORK_SSL_READ_ERROR         41
#define NETWORK_SSL_NOTHING_TO_READ    42
#define NETWORK_SSL_READ_TIMEOUT_ERROR 43
#define NETWORK_SMALL_BUFFER 44
#define NETWORK_SSL_WRITE_ERROR 45
#define NETWORK_SSL_WRITE_TIMEOUT_ERROR 46
#define NETWORK_MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED 47
#define NETWORK_X509_ROOT_CRT_PARSE_ERROR 48
#define NETWORK_ERR_NET_SOCKET_FAILED 49
#define NETWORK_ERR_NET_UNKNOWN_HOST 50
#define NETWORK_ERR_NET_CONNECT_FAILED 51
#define SSL_CONNECTION_ERROR 52

/* This is the value used for ssl read timeout */
#define IOT_SSL_READ_TIMEOUT 20

char *UID_rootCA = DEFAULT_ROOT_CA_LOCATION;

typedef struct {
	bool active;
	int proto;
	mbedtls_net_context server_fd;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt cacert;
	mbedtls_ctr_drbg_context ctr_drbg;

	mbedtls_entropy_context entropy;
	uint32_t flags;
} UID_HttpSession;

static int tlsClose(UID_HttpSession *httpSession);
static int tcpClose(UID_HttpSession *httpSession);

static int tcpConnect(UID_HttpSession *httpSession, char *server, char *port)
{
    int ret = UID_HTTP_GET_ERROR;

	UID_log(UID_LOG_DEBUG," ok\n");
	UID_log(UID_LOG_DEBUG,"  . Connecting to %s/%s...", server, port);
	if((ret = mbedtls_net_connect(&(httpSession->server_fd), server,
								  port, MBEDTLS_NET_PROTO_TCP)) != 0) {
		UID_log(UID_LOG_ERROR," failed\n  ! mbedtls_net_connect returned -0x%x\n\n", -ret);
		switch(ret) {
			case MBEDTLS_ERR_NET_SOCKET_FAILED:
				ret = NETWORK_ERR_NET_SOCKET_FAILED;
				goto clean;
			case MBEDTLS_ERR_NET_UNKNOWN_HOST:
				ret = NETWORK_ERR_NET_UNKNOWN_HOST;
				goto clean;
			case MBEDTLS_ERR_NET_CONNECT_FAILED:
			default:
				ret = NETWORK_ERR_NET_CONNECT_FAILED;
				goto clean;
		};
	}

    // set receive timeout
    struct timeval tv = { .tv_sec = IOT_SSL_READ_TIMEOUT, .tv_usec = 0};
    setsockopt(httpSession->server_fd.fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

	ret = UID_HTTP_OK;

clean:
	httpSession->active = true;
	if ( UID_HTTP_OK != ret) {
		tcpClose(httpSession);
	}
	UID_log(UID_LOG_DEBUG, "#### return %d socket %d\n", ret, httpSession->server_fd.fd);
	return ret;
}



//  https://tls.mbed.org/discussions/generic/mbedtls-takes-long-connection-time


static int tlsConnect(UID_HttpSession *httpSession, char *server, char *port) {
	int ret = 0;
	const char *pers = "aws_iot_tls_wrapper";
	char vrfy_buf[512];
	const char *alpnProtocols[] = { "http/1.1", NULL };

#ifdef ENABLE_HTTP_DEBUG
	unsigned char buf[MBEDTLS_DEBUG_BUFFER_SIZE];
#endif

	mbedtls_net_init(&(httpSession->server_fd));
	mbedtls_ssl_init(&(httpSession->ssl));
	mbedtls_ssl_config_init(&(httpSession->conf));
	mbedtls_ctr_drbg_init(&(httpSession->ctr_drbg));
	mbedtls_x509_crt_init(&(httpSession->cacert));



	UID_log(UID_LOG_DEBUG,"\n  . Seeding the random number generator...");
	mbedtls_entropy_init(&(httpSession->entropy));
	if((ret = mbedtls_ctr_drbg_seed(&(httpSession->ctr_drbg), mbedtls_entropy_func, &(httpSession->entropy),
									(const unsigned char *) pers, strlen(pers))) != 0) {
		UID_log(UID_LOG_ERROR," failed\n  ! mbedtls_ctr_drbg_seed returned -0x%x\n", -ret);
		ret = NETWORK_MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
		goto clean;
	}




	UID_log(UID_LOG_DEBUG,"  . Loading the CA root certificate ...");
	ret = mbedtls_x509_crt_parse_file(&(httpSession->cacert), UID_rootCA);
	if(ret < 0) {
		UID_log(UID_LOG_ERROR," failed\n  !  mbedtls_x509_crt_parse returned -0x%x while parsing root cert\n\n", -ret);
		ret = NETWORK_X509_ROOT_CRT_PARSE_ERROR;
		goto clean;
	}
	UID_log(UID_LOG_DEBUG," ok (%d skipped)\n", ret);




	UID_log(UID_LOG_DEBUG," ok\n");
	UID_log(UID_LOG_DEBUG,"  . Connecting to %s/%s...", server, port);
	if((ret = mbedtls_net_connect(&(httpSession->server_fd), server,
								  port, MBEDTLS_NET_PROTO_TCP)) != 0) {
		UID_log(UID_LOG_ERROR," failed\n  ! mbedtls_net_connect returned -0x%x\n\n", -ret);
		switch(ret) {
			case MBEDTLS_ERR_NET_SOCKET_FAILED:
				ret = NETWORK_ERR_NET_SOCKET_FAILED;
				goto clean;
			case MBEDTLS_ERR_NET_UNKNOWN_HOST:
				ret = NETWORK_ERR_NET_UNKNOWN_HOST;
				goto clean;
			case MBEDTLS_ERR_NET_CONNECT_FAILED:
			default:
				ret = NETWORK_ERR_NET_CONNECT_FAILED;
				goto clean;
		};
	}

	ret = mbedtls_net_set_block(&(httpSession->server_fd));
	if(ret != 0) {
		UID_log(UID_LOG_ERROR," failed\n  ! net_set_(non)block() returned -0x%x\n\n", -ret);
		ret = SSL_CONNECTION_ERROR;
		goto clean;
	} UID_log(UID_LOG_DEBUG," ok\n");

	UID_log(UID_LOG_DEBUG,"  . Setting up the SSL/TLS structure...");
	if((ret = mbedtls_ssl_config_defaults(&(httpSession->conf), MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
										  MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		UID_log(UID_LOG_ERROR," failed\n  ! mbedtls_ssl_config_defaults returned -0x%x\n\n", -ret);
		ret = SSL_CONNECTION_ERROR;
		goto clean;
	}

//	mbedtls_ssl_conf_verify(&(httpSession->conf), _iot_tls_verify_cert, NULL);
	mbedtls_ssl_conf_authmode(&(httpSession->conf), MBEDTLS_SSL_VERIFY_REQUIRED);

	mbedtls_ssl_conf_rng(&(httpSession->conf), mbedtls_ctr_drbg_random, &(httpSession->ctr_drbg));

	mbedtls_ssl_conf_ca_chain(&(httpSession->conf), &(httpSession->cacert), NULL);

//	mbedtls_ssl_conf_read_timeout(&(httpSession->conf), timeout_ms);

	/* Use the AWS IoT ALPN extension for MQTT if port 443 is requested. */
	if(  !strcmp( "443",port)) {
		if((ret = mbedtls_ssl_conf_alpn_protocols(&(httpSession->conf), alpnProtocols)) != 0) {
			UID_log(UID_LOG_ERROR," failed\n  ! mbedtls_ssl_conf_alpn_protocols returned -0x%x\n\n", -ret);
			ret = SSL_CONNECTION_ERROR;
			goto clean;
		}
	}

	/* Assign the resulting configuration to the SSL context. */
	if((ret = mbedtls_ssl_setup(&(httpSession->ssl), &(httpSession->conf))) != 0) {
		UID_log(UID_LOG_ERROR," failed\n  ! mbedtls_ssl_setup returned -0x%x\n\n", -ret);
		ret = SSL_CONNECTION_ERROR;
		goto clean;
	}
	if((ret = mbedtls_ssl_set_hostname(&(httpSession->ssl), server)) != 0) {
		UID_log(UID_LOG_ERROR," failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
		ret = SSL_CONNECTION_ERROR;
		goto clean;
	}
	UID_log(UID_LOG_DEBUG,"\n\nSSL state connect : %d ", httpSession->ssl.state);
	mbedtls_ssl_set_bio(&(httpSession->ssl), &(httpSession->server_fd), mbedtls_net_send, NULL,
						mbedtls_net_recv_timeout);
	UID_log(UID_LOG_DEBUG," ok\n");

	UID_log(UID_LOG_DEBUG,"\n\nSSL state connect : %d ", httpSession->ssl.state);
	UID_log(UID_LOG_DEBUG,"  . Performing the SSL/TLS handshake...");
	while((ret = mbedtls_ssl_handshake(&(httpSession->ssl))) != 0) {
		if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			UID_log(UID_LOG_ERROR," failed\n  ! mbedtls_ssl_handshake returned -0x%x\n", -ret);
			if(ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
				UID_log(UID_LOG_ERROR,"    Unable to verify the server's certificate. "
							  "Either it is invalid,\n"
							  "    or you didn't set ca_file or ca_path "
							  "to an appropriate value.\n"
							  "    Alternatively, you may want to use "
							  "auth_mode=optional for testing purposes.\n");
			}
			ret = SSL_CONNECTION_ERROR;
			goto clean;
		}
	}

	UID_log(UID_LOG_DEBUG," ok\n    [ Protocol is %s ]\n    [ Ciphersuite is %s ]\n", mbedtls_ssl_get_version(&(httpSession->ssl)),
		  mbedtls_ssl_get_ciphersuite(&(httpSession->ssl)));
	if((ret = mbedtls_ssl_get_record_expansion(&(httpSession->ssl))) >= 0) {
		UID_log(UID_LOG_DEBUG,"    [ Record expansion is %d ]\n", ret);
	} else {
		UID_log(UID_LOG_DEBUG,"    [ Record expansion is unknown (compression) ]\n");
	}

UID_log(UID_LOG_DEBUG,"  . Verifying peer X.509 certificate...");

	if((httpSession->flags = mbedtls_ssl_get_verify_result(&(httpSession->ssl))) != 0) {
		UID_log(UID_LOG_ERROR," failed\n");
		mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", httpSession->flags);
		UID_log(UID_LOG_ERROR,"%s\n", vrfy_buf);
		ret = SSL_CONNECTION_ERROR;
	} else {
		UID_log(UID_LOG_DEBUG," ok\n");
		ret = UID_HTTP_OK;
	}

#ifdef ENABLE_HTTP_DEBUG
	if (mbedtls_ssl_get_peer_cert(&(httpSession->ssl)) != NULL) {
		UID_log(UID_LOG_DEBUG,"  . Peer certificate information    ...\n");
		mbedtls_x509_crt_info((char *) buf, sizeof(buf) - 1, "      ", mbedtls_ssl_get_peer_cert(&(httpSession->ssl)));
		UID_log(UID_LOG_DEBUG,"%s\n", buf);
	}
#endif

	mbedtls_ssl_conf_read_timeout(&(httpSession->conf), IOT_SSL_READ_TIMEOUT*1000);

clean:
	httpSession->active = true;
	if ( UID_HTTP_OK != ret) {
		tlsClose(httpSession);
	}
	return ret;
}

static int UID_connect(UID_HttpSession *httpSession, char *server, char *port, int proto) {

	int ret;
	if (httpSession->active) {
		// TODO: check for the active session
		return UID_HTTP_OK;
	}
	httpSession->proto = proto;
	if(proto == PROTO_HTTP) {
		ret = tcpConnect(httpSession, server, port);
		return ret;
	}
	if(proto == PROTO_HTTPS) {
		ret = tlsConnect(httpSession, server, port);
		return ret;
	}

	return UID_HTTP_GET_ERROR; // unknown proto
}


static int tlsWrite(UID_HttpSession *httpSession, char *pMsg, size_t len) {
	size_t written_so_far;
	bool isErrorFlag = false;
	int frags;
	int ret = 0;

	for(written_so_far = 0, frags = 0; written_so_far < len; written_so_far += ret, frags++) {
		while( (ret = mbedtls_ssl_write(&(httpSession->ssl), (unsigned char *)pMsg + written_so_far, len - written_so_far)) <= 0) {
			if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
				UID_log(UID_LOG_ERROR," failed\n  ! mbedtls_ssl_write returned -0x%x\n\n", -ret);
				/* All other negative return values indicate connection needs to be reset.
		 		* Will be caught in ping request so ignored here */
				isErrorFlag = true;
				break;
			}
		}
		if(isErrorFlag) {
			break;
		}
	}

	if(isErrorFlag) {
		return NETWORK_SSL_WRITE_ERROR;
	} else if(written_so_far != len) {
		return NETWORK_SSL_WRITE_TIMEOUT_ERROR;
	}

	return UID_HTTP_OK;
}

static int tcpWrite(UID_HttpSession *httpSession, char *pMsg, size_t len) {
	size_t written_so_far;
	bool isErrorFlag = false;
	int frags;
	int ret = 0;

	for(written_so_far = 0, frags = 0; written_so_far < len; written_so_far += ret, frags++) {
		while( (ret = write(httpSession->server_fd.fd, pMsg + written_so_far, len - written_so_far)) <= 0) {
			if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
				UID_log(UID_LOG_ERROR," failed\n  ! mbedtls_ssl_write returned -0x%x\n\n", -ret);
				/* All other negative return values indicate connection needs to be reset.
		 		* Will be caught in ping request so ignored here */
				isErrorFlag = true;
				break;
			}
		}
		if(isErrorFlag) {
			break;
		}
	}

	if(isErrorFlag) {
		return NETWORK_SSL_WRITE_ERROR;
	} else if(written_so_far != len) {
		return NETWORK_SSL_WRITE_TIMEOUT_ERROR;
	}

	return UID_HTTP_OK;
}


static int UID_write(UID_HttpSession *httpSession, char *pMsg, size_t len) {
	int ret;
	if (!httpSession->active) {
		return UID_HTTP_GET_ERROR;
	}
	if(httpSession->proto == PROTO_HTTPS) {
		ret = tlsWrite(httpSession, pMsg, len);
		return ret;
	}
	if(httpSession->proto == PROTO_HTTP) {
		ret = tcpWrite(httpSession, pMsg, len);
		return ret;
	}

	return UID_HTTP_GET_ERROR; // unknown proto
}

static int tlsRead(UID_HttpSession *httpSession, char *pMsg, size_t len, size_t *read_len) {
	size_t rxLen = 0;
	int ret;

	while (len > 0) {
		// This read will timeout after IOT_SSL_READ_TIMEOUT if there's no data to be read
		ret = mbedtls_ssl_read(&(httpSession->ssl), (unsigned char *)pMsg, len);
		if (ret > 0) {
			rxLen += ret;
			pMsg += ret;
			len -= ret;
		} else if (ret == 0 || (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret /*!= MBEDTLS_ERR_SSL_TIMEOUT*/)) {
			return NETWORK_SSL_READ_ERROR;
		}
	}

	if (len == 0) {
		*read_len = rxLen;
		return UID_HTTP_OK;
	}

	if (rxLen == 0) {
		return NETWORK_SSL_NOTHING_TO_READ;
	} else {
		return NETWORK_SSL_READ_TIMEOUT_ERROR;
	}
}

static int tcpRead(UID_HttpSession *httpSession, char *pMsg, size_t len, size_t *read_len) {
	size_t rxLen = 0;
	int ret;

	while (len > 0) {
		// This read will timeout after IOT_SSL_READ_TIMEOUT if there's no data to be read
		ret = read(httpSession->server_fd.fd, pMsg, len);
		if (ret > 0) {
			rxLen += ret;
			pMsg += ret;
			len -= ret;
		} else if (ret == 0 || (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret /*!= MBEDTLS_ERR_SSL_TIMEOUT*/)) {
			return NETWORK_SSL_READ_ERROR;
		}
	}

	if (len == 0) {
		*read_len = rxLen;
		return UID_HTTP_OK;
	}

	if (rxLen == 0) {
		return NETWORK_SSL_NOTHING_TO_READ;
	} else {
		return NETWORK_SSL_READ_TIMEOUT_ERROR;
	}
}

static int UID_read(UID_HttpSession *httpSession, char *pMsg, size_t len, size_t *read_len) {
	int ret;
	if (!httpSession->active) {
		return UID_HTTP_GET_ERROR;
	}
	if(httpSession->proto == PROTO_HTTPS) {
		ret = tlsRead(httpSession, pMsg, len, read_len);
		return ret;
	}
	if(httpSession->proto == PROTO_HTTP) {
		ret = tcpRead(httpSession, pMsg, len, read_len);
		return ret;
	}

	return UID_HTTP_GET_ERROR; // unknown proto
}

static int tcpClose(UID_HttpSession *httpSession)
{

	UID_log(UID_LOG_DEBUG,"tcpClose()\n");
    if (httpSession->active) {

		mbedtls_net_free(&(httpSession->server_fd));
		httpSession->active = false;
	}



	return UID_HTTP_OK;
}

static int tlsClose(UID_HttpSession *httpSession)
{
	mbedtls_ssl_context *ssl = &(httpSession->ssl);
	int ret = 0;

	UID_log(UID_LOG_DEBUG,"tlsClose()\n");
    if (httpSession->active) {
		do {
			ret = mbedtls_ssl_close_notify(ssl);
		} while(ret == MBEDTLS_ERR_SSL_WANT_WRITE);

		mbedtls_net_free(&(httpSession->server_fd));
		mbedtls_x509_crt_free(&(httpSession->cacert));
		mbedtls_ssl_free(&(httpSession->ssl));
		mbedtls_ssl_config_free(&(httpSession->conf));
		mbedtls_ctr_drbg_free(&(httpSession->ctr_drbg));
		mbedtls_entropy_free(&(httpSession->entropy));
		httpSession->active = false;
	}


	return UID_HTTP_OK;
}

static int UID_close(UID_HttpSession *httpSession)
{
	int ret;
	if (!httpSession->active) {
		return UID_HTTP_OK;
	}
	if(httpSession->proto == PROTO_HTTP) {
		ret = tcpClose(httpSession);
		return ret;
	}
	if(httpSession->proto == PROTO_HTTPS) {
		ret = tlsClose(httpSession);
		return ret;
	}

	return UID_HTTP_GET_ERROR; // unknown proto

}

static int httpReadHeader(UID_HttpSession *conn_fd, char *pMsg, size_t len)
{
    size_t read_len = 0;
    int ret;

    for(;;)
    {
        if (0 == len) return NETWORK_SMALL_BUFFER;
        ret = UID_read(conn_fd, pMsg, 1, &read_len);
        if (0 != ret) return ret;
        if (*pMsg == '\n') {
            *pMsg = 0;
            return UID_HTTP_OK;
        }
        if (*pMsg != '\r') {
            len--;
            pMsg++;
        }
    }
}

static int parseUrl(const char *url, char *server, size_t server_l, char *port, size_t port_l, char *page, size_t page_l, int *proto)
{
    unsigned start = 0;
    unsigned j = 0;

    snprintf(port, port_l, "80");
	*proto = PROTO_HTTP;
    if (strncmp(url, "http://", 7) == 0) {
		start +=7;
	}
    if (strncmp(url, "https://", 7) == 0) {
		*proto = PROTO_HTTPS;
        start +=8;
        snprintf(port, port_l, "443");
    }
    for (j=start; j<strlen(url); j++) if ((url[j] == ':') || (url[j] == '/')) break;

    snprintf(server, server_l, "%.*s", j - start, url + start);

    if (url[j] == ':') {
        start = j+1;
        for (j=start; j<strlen(url); j++) if (url[j] == '/') break;
        snprintf(port, port_l, "%.*s", j - start, url + start);
    }

    start = j;
    for (j=start; j<strlen(url); j++) ;
    snprintf(page, page_l, "%.*s", j - start, url + start);

//UID_log(UID_LOG_DEBUG,"########----> <%s> <%s> <%s>\n", server, port, page);

    return UID_HTTP_OK;
}

/**
 * Get data from url
 *
 * @param[in]  curl   pointer to an initialized UID_HttpOBJ struct
 * @param[in]  url    url to contact
 * @param[out] buffer pointer to buffer to be filled
 * @param[in]  size   size of buffer
 *
 * @return     UID_HTTP_OK no error
 */
int UID_httpget(UID_HttpOBJ *curl, char *url, char *buffer, size_t size)
{
    UID_HttpSession *httpSession = curl;
    char server [40] = "xxxxxxxx";
    char port[10] = "hhhhhhhh";
    char page[256] = "fffffffffffff";
    int ret = UID_HTTP_GET_ERROR;
	int proto;

	UID_log(UID_LOG_DEBUG, "\n---> %s %p %zu\n", url, buffer, size);
    parseUrl(url, server, sizeof(server), port, sizeof(port), page, sizeof(page), &proto);



	ret = UID_connect(httpSession, server, port, proto);
	if (UID_HTTP_OK != ret) goto clean;

    char request[512];
    size_t len = snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: %s\r\nUser-agent: simple-http client\r\n\r\n", page, server);
    ret = UID_write(httpSession, request, len);
    if (UID_HTTP_OK != ret) goto clean;

    char header[512];
    len = 0;
    for(;;)
    {
        ret = httpReadHeader(httpSession, header, sizeof(header));
        if (UID_HTTP_OK != ret) goto clean;
        if (*header == 0) break;
        sscanf(header, "Content-Length: %zd", &len);
    }

	ret = UID_HTTP_GET_ERROR;
    if (len >= size) goto clean;

    ret = UID_read(httpSession, buffer, len, &len);
    if (UID_HTTP_OK != ret) goto clean;
    buffer[len] = 0;

    ret = UID_HTTP_OK;

clean:
    return  ret;
}


#ifdef UID_IMPLEMENTSENDTX
int UID_httppost(UID_HttpOBJ *curl, char *url, char *postdata, char *ret, size_t size)
{
    (void) curl;

    return UID_HTTP_OK;
}
#endif //UID_IMPLEMENTSENDTX

UID_HttpOBJ *UID_httpinit()
{
    UID_log(UID_LOG_DEBUG,"--------------> init\n");
    return calloc(1, sizeof(UID_HttpSession));
}

int UID_httpcleanup(UID_HttpOBJ *curl)
{
    UID_HttpSession *httpSession = curl;

	UID_log(UID_LOG_DEBUG,"--------------> cleanup\n");
	UID_close(httpSession);

	UID_log(UID_LOG_DEBUG,"closed\n");

	free(curl);
    return UID_HTTP_OK;
}
