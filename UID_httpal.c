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
//#include "UID_log.h"




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

#define SUCCESS 0
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

#define ROOT_CA_LOCATION  "./amazon2.pem"
/**
 * @brief TLS Connection Parameters
 *
 * Defines a type containing TLS specific parameters to be passed down to the
 * TLS networking layer to create a TLS secured socket.
 */
typedef struct _TLSDataParams {
	mbedtls_net_context server_fd;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt cacert;
	mbedtls_ctr_drbg_context ctr_drbg;

	mbedtls_entropy_context entropy;
	uint32_t flags;
//	mbedtls_x509_crt clicert;
//	mbedtls_pk_context pkey;
}TLSDataParams;

typedef struct {
	bool active;
	TLSDataParams fd;
} UID_HttpSession;

int _UID_connect(int *conn_fd, char *server, char *port)
{
(void)server;(void)port;
    struct addrinfo hints, *result = NULL;
    int ret = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;


    if (0 != getaddrinfo(server, port, &hints, &result)) goto clean;

    // Create socket after retrieving the inet protocol to use (getaddrinfo)
    if (0 > (*conn_fd = socket(result->ai_family,SOCK_STREAM,0))) goto clean;
    if (0 != connect(*conn_fd, result->ai_addr, result->ai_addrlen) ) goto clean;

    ret = 0;
clean:
    if (NULL != result) freeaddrinfo(result);
    return ret;
}

//#define ENABLE_IOT_DEBUG 1
#ifdef ENABLE_IOT_DEBUG
#define IOT_DEBUG(...)    \
	{\
	printf("DEBUG:   %s L#%d ", __func__, __LINE__);  \
	printf(__VA_ARGS__); \
	printf("\n"); \
	}
#define MBEDTLS_DEBUG_BUFFER_SIZE 2048
#else
#define IOT_DEBUG(...)
#endif

#define IOT_ERROR IOT_DEBUG

//  https://tls.mbed.org/discussions/generic/mbedtls-takes-long-connection-time


int UID_connect(TLSDataParams *tlsDataParams, char *server, char *port) {
	int ret = 0;
	const char *pers = "aws_iot_tls_wrapper";
//	TLSDataParams *tlsDataParams = NULL;
//	char portBuffer[6];
	char vrfy_buf[512];
	const char *alpnProtocols[] = { "http/1.1", NULL };

#ifdef ENABLE_IOT_DEBUG
	unsigned char buf[MBEDTLS_DEBUG_BUFFER_SIZE];
#endif

//	if(NULL == pNetwork) {
//		return NULL_VALUE_ERROR;
//	}
//
//	if(NULL != params) {
//		_iot_tls_set_connect_params(pNetwork, params->pRootCALocation, params->pDeviceCertLocation,
//									params->pDevicePrivateKeyLocation, params->pDestinationURL,
//									params->DestinationPort, params->timeout_ms, params->ServerVerificationFlag);
//	}
//
//	tlsDataParams = &(pNetwork->tlsDataParams);

	mbedtls_net_init(&(tlsDataParams->server_fd));
	mbedtls_ssl_init(&(tlsDataParams->ssl));
	mbedtls_ssl_config_init(&(tlsDataParams->conf));
	mbedtls_ctr_drbg_init(&(tlsDataParams->ctr_drbg));
	mbedtls_x509_crt_init(&(tlsDataParams->cacert));
//	mbedtls_x509_crt_init(&(tlsDataParams->clicert));
//	mbedtls_pk_init(&(tlsDataParams->pkey));

	IOT_DEBUG("\n  . Seeding the random number generator...");
	mbedtls_entropy_init(&(tlsDataParams->entropy));
	if((ret = mbedtls_ctr_drbg_seed(&(tlsDataParams->ctr_drbg), mbedtls_entropy_func, &(tlsDataParams->entropy),
									(const unsigned char *) pers, strlen(pers))) != 0) {
		IOT_ERROR(" failed\n  ! mbedtls_ctr_drbg_seed returned -0x%x\n", -ret);
		return NETWORK_MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
	}

	IOT_DEBUG("  . Loading the CA root certificate ...");
	ret = mbedtls_x509_crt_parse_file(&(tlsDataParams->cacert), ROOT_CA_LOCATION);
	if(ret < 0) {
		IOT_ERROR(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x while parsing root cert\n\n", -ret);
		return NETWORK_X509_ROOT_CRT_PARSE_ERROR;
	}
	IOT_DEBUG(" ok (%d skipped)\n", ret);

	IOT_DEBUG(" ok\n");
//	snprintf(portBuffer, 6, "%d", pNetwork->tlsConnectParams.DestinationPort);
	IOT_DEBUG("  . Connecting to %s/%s...", server, port);
	if((ret = mbedtls_net_connect(&(tlsDataParams->server_fd), server,
								  port, MBEDTLS_NET_PROTO_TCP)) != 0) {
		IOT_ERROR(" failed\n  ! mbedtls_net_connect returned -0x%x\n\n", -ret);
		switch(ret) {
			case MBEDTLS_ERR_NET_SOCKET_FAILED:
				return NETWORK_ERR_NET_SOCKET_FAILED;
			case MBEDTLS_ERR_NET_UNKNOWN_HOST:
				return NETWORK_ERR_NET_UNKNOWN_HOST;
			case MBEDTLS_ERR_NET_CONNECT_FAILED:
			default:
				return NETWORK_ERR_NET_CONNECT_FAILED;
		};
	}

	ret = mbedtls_net_set_block(&(tlsDataParams->server_fd));
	if(ret != 0) {
		IOT_ERROR(" failed\n  ! net_set_(non)block() returned -0x%x\n\n", -ret);
		return SSL_CONNECTION_ERROR;
	} IOT_DEBUG(" ok\n");

	IOT_DEBUG("  . Setting up the SSL/TLS structure...");
	if((ret = mbedtls_ssl_config_defaults(&(tlsDataParams->conf), MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
										  MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		IOT_ERROR(" failed\n  ! mbedtls_ssl_config_defaults returned -0x%x\n\n", -ret);
		return SSL_CONNECTION_ERROR;
	}

//	mbedtls_ssl_conf_verify(&(tlsDataParams->conf), _iot_tls_verify_cert, NULL);
//	if(pNetwork->tlsConnectParams.ServerVerificationFlag == true) {
		mbedtls_ssl_conf_authmode(&(tlsDataParams->conf), MBEDTLS_SSL_VERIFY_REQUIRED);
//	} else {
//		mbedtls_ssl_conf_authmode(&(tlsDataParams->conf), MBEDTLS_SSL_VERIFY_OPTIONAL);
//	}
	mbedtls_ssl_conf_rng(&(tlsDataParams->conf), mbedtls_ctr_drbg_random, &(tlsDataParams->ctr_drbg));

	mbedtls_ssl_conf_ca_chain(&(tlsDataParams->conf), &(tlsDataParams->cacert), NULL);
	// if((ret = mbedtls_ssl_conf_own_cert(&(tlsDataParams->conf), &(tlsDataParams->clicert), &(tlsDataParams->pkey))) !=
	//    0) {
	// 	IOT_ERROR(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
	// 	return SSL_CONNECTION_ERROR;
	// }

//	mbedtls_ssl_conf_read_timeout(&(tlsDataParams->conf), pNetwork->tlsConnectParams.timeout_ms);

	/* Use the AWS IoT ALPN extension for MQTT if port 443 is requested. */
	if(  !strcmp( "443",port)) {
		if((ret = mbedtls_ssl_conf_alpn_protocols(&(tlsDataParams->conf), alpnProtocols)) != 0) {
			IOT_ERROR(" failed\n  ! mbedtls_ssl_conf_alpn_protocols returned -0x%x\n\n", -ret);
			return SSL_CONNECTION_ERROR;
		}
	}

	/* Assign the resulting configuration to the SSL context. */
	if((ret = mbedtls_ssl_setup(&(tlsDataParams->ssl), &(tlsDataParams->conf))) != 0) {
		IOT_ERROR(" failed\n  ! mbedtls_ssl_setup returned -0x%x\n\n", -ret);
		return SSL_CONNECTION_ERROR;
	}
	if((ret = mbedtls_ssl_set_hostname(&(tlsDataParams->ssl), server)) != 0) {
		IOT_ERROR(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
		return SSL_CONNECTION_ERROR;
	}
	IOT_DEBUG("\n\nSSL state connect : %d ", tlsDataParams->ssl.state);
	mbedtls_ssl_set_bio(&(tlsDataParams->ssl), &(tlsDataParams->server_fd), mbedtls_net_send, NULL,
						mbedtls_net_recv_timeout);
	IOT_DEBUG(" ok\n");

	IOT_DEBUG("\n\nSSL state connect : %d ", tlsDataParams->ssl.state);
	IOT_DEBUG("  . Performing the SSL/TLS handshake...");
printf("------------>");
	while((ret = mbedtls_ssl_handshake(&(tlsDataParams->ssl))) != 0) {
printf("@");
		if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			IOT_ERROR(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n", -ret);
			if(ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
				IOT_ERROR("    Unable to verify the server's certificate. "
							  "Either it is invalid,\n"
							  "    or you didn't set ca_file or ca_path "
							  "to an appropriate value.\n"
							  "    Alternatively, you may want to use "
							  "auth_mode=optional for testing purposes.\n");
			}
			return SSL_CONNECTION_ERROR;
		}
	}
printf("<------------\n");

	IOT_DEBUG(" ok\n    [ Protocol is %s ]\n    [ Ciphersuite is %s ]\n", mbedtls_ssl_get_version(&(tlsDataParams->ssl)),
		  mbedtls_ssl_get_ciphersuite(&(tlsDataParams->ssl)));
	if((ret = mbedtls_ssl_get_record_expansion(&(tlsDataParams->ssl))) >= 0) {
		IOT_DEBUG("    [ Record expansion is %d ]\n", ret);
	} else {
		IOT_DEBUG("    [ Record expansion is unknown (compression) ]\n");
	}

	IOT_DEBUG("  . Verifying peer X.509 certificate...");

//	if(pNetwork->tlsConnectParams.ServerVerificationFlag == true) {
		if((tlsDataParams->flags = mbedtls_ssl_get_verify_result(&(tlsDataParams->ssl))) != 0) {
			IOT_ERROR(" failed\n");
			mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", tlsDataParams->flags);
			IOT_ERROR("%s\n", vrfy_buf);
			ret = SSL_CONNECTION_ERROR;
		} else {
			IOT_DEBUG(" ok\n");
			ret = SUCCESS;
		}
//	} else {
//		IOT_DEBUG(" Server Verification skipped\n");
//		ret = SUCCESS;
//	}

#ifdef ENABLE_IOT_DEBUG
	if (mbedtls_ssl_get_peer_cert(&(tlsDataParams->ssl)) != NULL) {
		IOT_DEBUG("  . Peer certificate information    ...\n");
		mbedtls_x509_crt_info((char *) buf, sizeof(buf) - 1, "      ", mbedtls_ssl_get_peer_cert(&(tlsDataParams->ssl)));
		IOT_DEBUG("%s\n", buf);
	}
#endif

//	mbedtls_ssl_conf_read_timeout(&(tlsDataParams->conf), IOT_SSL_READ_TIMEOUT);

	return ret;
}


int UID_write(TLSDataParams *conn_fd, char *pMsg, size_t len) {
	size_t written_so_far;
	bool isErrorFlag = false;
	int frags;
	int ret = 0;

	for(written_so_far = 0, frags = 0; written_so_far < len; written_so_far += ret, frags++) {
		while( (ret = mbedtls_ssl_write(&(conn_fd->ssl), (unsigned char *)pMsg + written_so_far, len - written_so_far)) <= 0) {
			if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
				printf(" failed\n  ! mbedtls_ssl_write returned -0x%x\n\n", -ret);
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

	return SUCCESS;
}


int UID_read(TLSDataParams *conn_fd, char *pMsg, size_t len, size_t *read_len)
{
	size_t rxLen = 0;
	int ret;

	while (len > 0) {
		// This read will timeout after IOT_SSL_READ_TIMEOUT if there's no data to be read
		ret = mbedtls_ssl_read(&(conn_fd->ssl), (unsigned char *)pMsg, len);
		if (ret > 0) {
			rxLen += ret;
			pMsg += ret;
			len -= ret;
		} else if (ret == 0 || (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_TIMEOUT)) {
			return NETWORK_SSL_READ_ERROR;
		}
	}

	if (len == 0) {
		*read_len = rxLen;
		return SUCCESS;
	}

	if (rxLen == 0) {
		return NETWORK_SSL_NOTHING_TO_READ;
	} else {
		return NETWORK_SSL_READ_TIMEOUT_ERROR;
	}
}

int UID_readheader(TLSDataParams *conn_fd, char *pMsg, size_t len)
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
            return SUCCESS;
        }
        if (*pMsg != '\r') {
            len--;
            pMsg++;
        }
    }
}

int _UID_close(int *conn_fd)
{
    if (*conn_fd >= 0) close(*conn_fd);
    return 0;
}

int UID_close(TLSDataParams *tlsDataParams)
{
	mbedtls_ssl_context *ssl = &(tlsDataParams->ssl);
	int ret = 0;
	do {
		ret = mbedtls_ssl_close_notify(ssl);
	} while(ret == MBEDTLS_ERR_SSL_WANT_WRITE);

	mbedtls_net_free(&(tlsDataParams->server_fd));

//	mbedtls_x509_crt_free(&(tlsDataParams->clicert));
//	mbedtls_pk_free(&(tlsDataParams->pkey));
	mbedtls_x509_crt_free(&(tlsDataParams->cacert));
	mbedtls_ssl_free(&(tlsDataParams->ssl));
	mbedtls_ssl_config_free(&(tlsDataParams->conf));
	mbedtls_ctr_drbg_free(&(tlsDataParams->ctr_drbg));
	mbedtls_entropy_free(&(tlsDataParams->entropy));

	return SUCCESS;
}

#define PROTO_HTTP  0
#define PROTO_HTTPS 1

static int parse_url(const char *url, char *server, size_t server_l, char *port, size_t port_l, char *page, size_t page_l, int *proto)
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

//printf("########----> <%s> <%s> <%s>\n", server, port, page);

    return SUCCESS;
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

printf("\n---> %s %p %zu\n", url, buffer, size);
    parse_url(url, server, sizeof(server), port, sizeof(port), page, sizeof(page), &proto);

if(proto == PROTO_HTTP) {
	printf("cannot manage proto http\n");
	return UID_HTTP_GET_ERROR;
}
	if (httpSession->active) {

	}

	if (!httpSession->active) {

		ret = UID_connect(&httpSession->fd, server, port);
printf("--- %d\n",ret);
		if (SUCCESS != ret) goto clean;
		httpSession->active = true;
printf("connected\n");
	}

    char request[512];
    size_t len = snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: %s\r\nUser-agent: simple-http client\r\n\r\n", page, server);
//    printf("\n=================================\n%s\n======================\n", request);
    ret = UID_write(&httpSession->fd, request, len);
    if (SUCCESS != ret) goto clean;
printf("requested\n");
    char header[512];
    len = 0;
    for(;;)
    {
        ret = UID_readheader(&(httpSession->fd), header, sizeof(header));
        if (SUCCESS != ret) goto clean;
//        printf("--- <%s>\n", header);
        if (*header == 0) break;
        sscanf(header, "Content-Length: %zd", &len);
    }
printf("header\n");
    if (len >= size) goto clean;

    ret = UID_read(&httpSession->fd, buffer, len, &len);
    if (SUCCESS != ret) goto clean;
    buffer[len] = 0;
//    printf("\n=================================\n%s\n======================\n", buffer);
printf("body\n");
    ret = 0;

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
    printf("---------------> init\n");
    return calloc(1, sizeof(UID_HttpSession));
}

int UID_httpcleanup(UID_HttpOBJ *curl)
{
    UID_HttpSession *httpSession = curl;

    printf("---------------> cleanup\n");

    if (httpSession->active) {
		httpSession->active = false;
		UID_close(&httpSession->fd);
printf("closed\n");
	}
	free(curl);
    return UID_HTTP_OK;
}
