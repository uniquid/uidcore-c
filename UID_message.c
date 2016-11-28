/*
 * UID_message.c
 *
 *  Created on: 25/oct/2016
 *      Author: M. Palumbi
 */






/*
 * DESCRIPTION
 * Functions related to the RPC messages
 *
 */

#include <string.h>
#include <stdio.h>
#include <time.h>

#include "yajl/yajl_gen.h"
#include "yajl/yajl_tree.h"
#include "UID_message.h"
#include "UID_bchainBTC.h"
#include "UID_dispatch.h"

int UID_createChannel(char *destMachine, UID_ClientChannelCtx *ctx)
{
    UID_ClientProfile *provider;

	if (NULL == (provider = UID_matchProvider(destMachine))) return UID_MSG_NOT_FOUND;
    strncpy(ctx->myid, provider->serviceUserAddress, sizeof(ctx->myid));
    strncpy(ctx->peerid, provider->serviceProviderAddress, sizeof(ctx->peerid));

    return UID_MSG_OK;
}

int UID_formatReqMsg(char *sender, int method, char *params, uint8_t *msg, size_t *size, int *sID)
{
    yajl_gen g;
    const uint8_t *json;
    size_t sz;
    int ret;

    *sID = time(NULL);

    g = yajl_gen_alloc(NULL);
    if (NULL == g) return UID_MSG_GEN_ALLOC_FAIL;

/*
    yajl_gen_map_open(g);
        yajl_gen_string(g, (uint8_t *)"sender", 6);
        yajl_gen_string(g, (uint8_t *)channel_ctx->myid, strlen(channel_ctx->myid));
        yajl_gen_string(g, (uint8_t *)"body", 4);
        yajl_gen_map_open(g);
            yajl_gen_string(g, (uint8_t *)"method", 6);
            yajl_gen_integer(g, method);
            yajl_gen_string(g, (uint8_t *)"params", 6);
            yajl_gen_string(g, (uint8_t *)params, strlen(params));
            yajl_gen_string(g, (uint8_t *)"id", 2);
            yajl_gen_integer(g, *id);
        yajl_gen_map_close(g);
    yajl_gen_map_close(g);

    yajl_gen_get_buf(g, &json, &sz); //get the msg
    //if(sz > size) return
    strncpy((char *)msg, (char *)json, *size);
*/
    ret = UID_MSG_GEN_FAIL;
    if (yajl_gen_status_ok != yajl_gen_string(g, (uint8_t *)params, strlen(params))) goto clean;
    if (yajl_gen_status_ok != yajl_gen_get_buf(g, &json, &sz)) goto clean; //format params string
    sz = snprintf((char *)msg, *size, "{\"sender\":\"%s\",\"body\":{\"method\":%d,\"params\":%s,\"id\":%d}}", sender, method, json, *sID);
    ret = UID_MSG_SMALL_BUFFER;
    if (sz >= *size) goto clean;
    *size = sz + 1;  // add the end of string

    ret = UID_MSG_OK;
clean:
    yajl_gen_clear(g);
    yajl_gen_free(g);

    return ret;
}

int UID_accept_channel(uint8_t *in_msg, size_t in_size, UID_ServerChannelCtx *channel_ctx, uint8_t *first_msg, size_t *out_size)
{
    yajl_val node, v;
    char *s;
    UID_SecurityProfile *contract;
    int ret;

    // parse message
	node = yajl_tree_parse((char *)in_msg, NULL, 0);
    if (node == NULL) return UID_MSG_JPARSE_ERROR;

    ret = UID_MSG_JPARSE_ERROR;
    const char * sender[] = { "sender", (const char *) 0 };
    v = yajl_tree_get(node, sender, yajl_t_string);
    if (v == NULL) goto clean_return;
    s =  YAJL_GET_STRING(v);

    ret = UID_MSG_NO_CONTRACT;  // We dont have a contract. we dont send any answer...
    contract = UID_matchContract(s);
    if (NULL == contract) goto clean_return;
    memcpy(&(channel_ctx->contract), contract, sizeof(channel_ctx->contract));

    ret = UID_MSG_SMALL_BUFFER;
    if (in_size > *out_size) goto clean_return;
    memcpy(first_msg, in_msg, in_size);
    *out_size = in_size;

    ret = UID_MSG_OK;
clean_return:
    yajl_tree_free(node);
    return ret;
}

int UID_parseReqMsg(uint8_t *msg, size_t size, char *sender, size_t ssize, int *method, char *params, size_t psize, int *sID)
{
(void)size;
    yajl_val node, v;
    int ret;

    // parse message
	node = yajl_tree_parse((char *)msg, NULL, 0);
    if (node == NULL) return UID_MSG_JPARSE_ERROR;

// get the sender
    ret = UID_MSG_JPARSE_ERROR;
    const char * _sender[] = { "sender", (const char *) 0 };
    v = yajl_tree_get(node, _sender, yajl_t_string);
    if (v == NULL) goto clean_return;
    char *s =  YAJL_GET_STRING(v);

    ret = UID_MSG_SMALL_BUFFER;
    if (strlen(s) >= ssize) goto clean_return;
    strncpy(sender, s, ssize);

// get the sID
    ret = UID_MSG_JPARSE_ERROR;
    const char * _id[] = { "body", "id", (const char *) 0 };
    v = yajl_tree_get(node, _id, yajl_t_number);
    if (v == NULL) goto clean_return;

    *sID = YAJL_GET_INTEGER(v);

// get the method
    ret = UID_MSG_JPARSE_ERROR;
    const char * _method[] = { "body", "method", (const char *) 0 };
    v = yajl_tree_get(node, _method, yajl_t_number);
    if (v == NULL) goto clean_return;

    *method = YAJL_GET_INTEGER(v);

//get the params
    ret = UID_MSG_JPARSE_ERROR;
    const char * _params[] = { "body", "params", (const char *) 0 };
    v = yajl_tree_get(node, _params, yajl_t_string);
    if (v == NULL) goto clean_return;
    char *res =  YAJL_GET_STRING(v);

    ret = UID_MSG_SMALL_BUFFER;
    if (strlen(res) >= psize) goto clean_return;
    strncpy(params, res, psize);

    ret = UID_MSG_OK;
clean_return:
    if (NULL != node) yajl_tree_free(node);
    return ret;
}

int UID_formatRespMsg(char *sender, char *result, int error, int sID, uint8_t *msg, size_t *size)
{
    int ret;
    yajl_gen g = NULL;

    // build the response
    ret = UID_MSG_GEN_ALLOC_FAIL;
    g = yajl_gen_alloc(NULL);
    if (NULL == g) goto clean_return;

    size_t sz;
    const uint8_t *json;
    ret = UID_MSG_GEN_FAIL;
    if (yajl_gen_status_ok != yajl_gen_string(g, (uint8_t *)result, strlen(result))) goto clean_return;
    if (yajl_gen_status_ok != yajl_gen_get_buf(g, &json, &sz)) goto clean_return; //get the buffer
    sz = snprintf((char *)msg, *size, "{\"sender\":\"%s\",\"body\":{\"result\":%s,\"error\":%d,\"id\":%d}}", sender, json, error, sID);
    ret = UID_MSG_SMALL_BUFFER;
    if (sz >= *size) goto clean_return;
    *size = sz + 1;  // add the end of string

    ret = UID_MSG_OK;
clean_return:
    if (NULL != g) yajl_gen_free(g);
    return ret;
}

//  {"sender":"my3CohS9f57yCqNy4yAPbBRqLaAAJ9oqXV","body":{"method":33,"params":"{\"pippa\":\"lapeppa\"}","id":1477550301}}

int UID_parseRespMsg(uint8_t *msg, size_t size, char *sender, size_t ssize, int *error, char *result, size_t rsize, int *sID)
{
(void)size;
    yajl_val node, v;
    int ret;

    // parse message
	node = yajl_tree_parse((char *)msg, NULL, 0);
    if (node == NULL) return UID_MSG_JPARSE_ERROR;

// get the sender
    ret = UID_MSG_JPARSE_ERROR;
    const char * _sender[] = { "sender", (const char *) 0 };
    v = yajl_tree_get(node, _sender, yajl_t_string);
    if (v == NULL) goto clean_return;
    char *s =  YAJL_GET_STRING(v);

    ret = UID_MSG_SMALL_BUFFER;
    if (strlen(s) >= ssize) goto clean_return;
    strncpy(sender, s, ssize);

// get the sID
    ret = UID_MSG_JPARSE_ERROR;
    const char * _id[] = { "body", "id", (const char *) 0 };
    v = yajl_tree_get(node, _id, yajl_t_number);
    if (v == NULL) goto clean_return;

    *sID = YAJL_GET_INTEGER(v);

// get the error
    ret = UID_MSG_JPARSE_ERROR;
    const char * _error[] = { "body", "error", (const char *) 0 };
    v = yajl_tree_get(node, _error, yajl_t_number);
    if (v == NULL) goto clean_return;

    *error = YAJL_GET_INTEGER(v);

//get the result
    ret = UID_MSG_JPARSE_ERROR;
    const char * _result[] = { "body", "result", (const char *) 0 };
    v = yajl_tree_get(node, _result, yajl_t_string);
    if (v == NULL) goto clean_return;
    char *res =  YAJL_GET_STRING(v);

    ret = UID_MSG_SMALL_BUFFER;
    if (strlen(res) >= rsize) goto clean_return;
    strncpy(result, res, rsize);

    ret = UID_MSG_OK;
clean_return:
    if (NULL != node) yajl_tree_free(node);
    return ret;
}

int UID_closeChannel(UID_ClientChannelCtx *ctx)
{
    (void)ctx;
    return UID_MSG_OK;
}

int UID_closeServerChannel(UID_ServerChannelCtx *ctx)
{
    (void)ctx;
    return UID_MSG_OK;
}
