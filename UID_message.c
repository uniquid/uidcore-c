/*
 * Copyright (c) 2016-2018. Uniquid Inc. or its affiliates. All Rights Reserved.
 *
 * License is in the "LICENSE" file accompanying this file.
 * See the License for the specific language governing permissions and limitations under the License.
 */

 /*
 * @file   UID_message.c
 *
 * @date   25/oct/2016
 * @author M. Palumbi
 */


/**
 * @file UID_message.h
 *
 * Functions related to the RPC messages
 *
 */

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>

#include "yajl/yajl_gen.h"
#include "yajl/yajl_tree.h"
#include "UID_message.h"
#include "UID_bchainBTC.h"
#include "UID_dispatch.h"
#include "UID_time.h"
#include "UID_utils.h"

/**
 * Create the context for the user to talk with the
 * provider entity named <destMachine>
 *
 * look the contracts cache to find contract informations
 *
 * @param[in] destMachine string holding the name of the provider
 * @param[out] ctx        pointer to a struct to be filled with the context
 *                        (contract informations and may be encryption context)
 * @return                0 == no error
 */
int UID_createChannel(char *destMachine, UID_ClientChannelCtx *channel_ctx)
{
    UID_ClientProfile *contract;

    if (NULL == (contract = UID_matchProvider(destMachine))) return UID_MSG_NOT_FOUND;
    memcpy(&(channel_ctx->contract), contract, sizeof(channel_ctx->contract));

    return UID_MSG_OK;
}

/*
 * hash the serialization. Can be used for both request and response.
 *
 * serialization:
 * sprintf(serializeData,"%d%s%" PRId64 "", method, params, id) for the request
 * sprintf(serializeData,"%d%s%" PRId64 "", error, result, id)  for the response
 *
 * es:
 * char serializeData[] = "31param-string1551443586389"
 */
static void hashSerializeddata(int method, char *params, int64_t sID, uint8_t hash[32])
{
    char s_method[5] = {0};
    size_t l_method = 0;
    char s_sID[21] = {0};
    size_t l_sID = 0;
    size_t l_params = strlen(params);
    SHA256_CTX ctx;
    l_method = snprintf(s_method, sizeof(s_method), "%d", method);
    l_sID = snprintf(s_sID, sizeof(s_sID), "%" PRId64, sID);
    // hash the serialized data
    UID_hashMessage_init(l_method+l_params+l_sID, &ctx);
    UID_hashMessage_update(s_method, l_method, &ctx);
    UID_hashMessage_update(params, l_params, &ctx);
    UID_hashMessage_update(s_sID, l_sID, &ctx);
    UID_hashMessage_final(hash, &ctx);

}

/**
 * Format the RPC request message
 *
 * @param[in]     path   BIP32 path of the sender address
 * @param[in]     method the requested RPC method
 * @param[in]     params the RPC params string
 * @param[out]    msg    pointer to a buffer to be filled with the formatted message
 * @param[in,out] size   size of the msg buffer
 * @param[out]    sID    pointer to an int64_t variable to be filled with the generated session ID
 *
 * @return               0 == no error
 */
int UID_formatReqMsg(UID_Bip32Path *path, int method, char *params, uint8_t *msg, size_t *size, int64_t *sID)
{
    yajl_gen g;
    const uint8_t *json;
    size_t sz;
    int ret;

    *sID = UID_getTime();

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

    // hash the data
    BTC_Signature signature = {0};
    uint8_t hash[32] = {0};
    hashSerializeddata(method, params, *sID, hash);
    ret = UID_signMessageHash(hash, path, signature, sizeof(signature));
    if (UID_SIGN_OK != ret) goto clean;

    sz = snprintf((char *)msg, *size, "{\"body\":{\"method\":%d,\"params\":%s,\"id\":%" PRId64 "},\"signature\":\"%s\"}", method, json, *sID, signature);
    ret = UID_MSG_SMALL_BUFFER;
    if (sz >= *size) goto clean;
    *size = sz + 1;  // add the end of string

    ret = UID_MSG_OK;
clean:
    yajl_gen_clear(g);
    yajl_gen_free(g);

    return ret;
}

/**
 * Gets as input the first message in a user<>provider communication
 * and builds the context for the provider, may be performing
 * additional message exchanges needed by
 * encription/authentication
 *
 * Returns the context and the first real RPC message
 *
 * @param[in]	  in_msg input message
 * @param[in]	  in_size size in bytes of the input message
 * @param[out]	  channel_ctx pointer to a struct to be filled with the context
 * 				  (contract informations and may be encryption context)
 * @param[out]	  first_msg pointer to a buffer to be filled with the message
 * @param[in,out] out_size pointer to a size_t variable containing the size of
 * 				  the buffer pointed by first_msg and returning the actual
 * 				  number of bytes copied in the buffer on return
 * @return		  0 == no error
 */
int UID_accept_channel(uint8_t *in_msg, size_t in_size, UID_ServerChannelCtx *channel_ctx, uint8_t *first_msg, size_t *out_size)
{
    yajl_val node, v;
    char *s;
    UID_SecurityProfile *contract;
    int ret;
    const char * _id[] = { "body", "id", (const char *) 0 };
    const char * _method[] = { "body", "method", (const char *) 0 };
    const char * _params[] = { "body", "params", (const char *) 0 };
    const char * _signature[] = { "signature", (const char *) 0 };

    // parse message
    node = yajl_tree_parse((char *)in_msg, NULL, 0);
    if (node == NULL) return UID_MSG_JPARSE_ERROR;

// get the sID
    ret = UID_MSG_JPARSE_ERROR;
    v = yajl_tree_get(node, _id, yajl_t_number);
    if (v == NULL) goto clean_return;

    int64_t sID = YAJL_GET_INTEGER(v);

    int64_t td = UID_getTime() - sID;
    ret = UID_MSG_ID_MISMATCH;
    if (td > UID_MSG_TWINDOW ) goto clean_return;
    if (td < -UID_MSG_TWINDOW ) goto clean_return;

// get the method
    ret = UID_MSG_JPARSE_ERROR;
    v = yajl_tree_get(node, _method, yajl_t_number);
    if (v == NULL) goto clean_return;

    int method = YAJL_GET_INTEGER(v);

//get the params
    ret = UID_MSG_JPARSE_ERROR;
    v = yajl_tree_get(node, _params, yajl_t_string);
    if (v == NULL) goto clean_return;
    s =  YAJL_GET_STRING(v);

//get the signature
    ret = UID_MSG_JPARSE_ERROR;
    v = yajl_tree_get(node, _signature, yajl_t_string);
    if (v == NULL) goto clean_return;
    char *b64signature =  YAJL_GET_STRING(v);

// recover the address
    uint8_t hash[32] = {0};
    BTC_Address address = {0};
    hashSerializeddata(method, s, sID, hash);
    ret = UID_addressFromSignedHash(hash, b64signature, address);
    if(UID_SIGN_OK != ret) goto clean_return;

    ret = UID_MSG_NO_CONTRACT;  // We dont have a contract. we dont send any answer...
    contract = UID_matchContract(address);
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

/**
 * Parses an RPC  request message and returns its components
 *
 * in this implementation msg is a JSON, thus must be a NULL terminated string
 *
 * @param[in]  msg	  message
 * @param[in]  size   size in byte of the message
 * @param[out] method pointer to an int variable to be filled with the method
 * @param[out] params pointer to a buffer filled with the RPC parameter string
 * @param[in]  psize  size of the params buffer
 * @param[out] sID    pointer to an int64_t variable to be filled with the session ID
 *
 * @return     0 == no error
 */
int UID_parseReqMsg(uint8_t *msg, size_t size, int *method, char *params, size_t psize, int64_t *sID)
{
(void)size;
    yajl_val node, v;
    int ret;
    char *s;
    const char * _id[] = { "body", "id", (const char *) 0 };
    const char * _method[] = { "body", "method", (const char *) 0 };
    const char * _params[] = { "body", "params", (const char *) 0 };

    // parse message
    node = yajl_tree_parse((char *)msg, NULL, 0);
    if (node == NULL) return UID_MSG_JPARSE_ERROR;

// get the sID
    ret = UID_MSG_JPARSE_ERROR;
    v = yajl_tree_get(node, _id, yajl_t_number);
    if (v == NULL) goto clean_return;

    *sID = YAJL_GET_INTEGER(v);

// get the method
    ret = UID_MSG_JPARSE_ERROR;
    v = yajl_tree_get(node, _method, yajl_t_number);
    if (v == NULL) goto clean_return;

    *method = YAJL_GET_INTEGER(v);

//get the params
    ret = UID_MSG_JPARSE_ERROR;
    v = yajl_tree_get(node, _params, yajl_t_string);
    if (v == NULL) goto clean_return;
    s =  YAJL_GET_STRING(v);

    ret = UID_MSG_SMALL_BUFFER;
    if (strlen(s) >= psize) goto clean_return;
    strncpy(params, s, psize);

    ret = UID_MSG_OK;
clean_return:
    if (NULL != node) yajl_tree_free(node);
    return ret;
}

/**
 * Format the RPC response message
 *
 * @param[in]     path   BIP32 path of the sender address
 * @param[in]     result the RPC result string
 * @param[in]     error  error
 * @param[in]     sID    session ID
 * @param[out]    msg    pointer to a buffer to be filled with the formatted message
 * @param[in,out] size   size of the msg buffer
 *
 * @return        0 == no error
 */
int UID_formatRespMsg(UID_Bip32Path *path, char *result, int error, int64_t sID, uint8_t *msg, size_t *size)
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

    // hash the data
    BTC_Signature signature = {0};
    uint8_t hash[32] = {0};
    hashSerializeddata(error, result, sID, hash);
    ret = UID_signMessageHash(hash, path, signature, sizeof(signature));
    if (UID_SIGN_OK != ret) goto clean_return;

    sz = snprintf((char *)msg, *size, "{\"body\":{\"result\":%s,\"error\":%d,\"id\":%" PRId64 "},\"signature\":\"%s\"}", json, error, sID, signature);
    ret = UID_MSG_SMALL_BUFFER;
    if (sz >= *size) goto clean_return;
    *size = sz + 1;  // add the end of string

    ret = UID_MSG_OK;
clean_return:
    if (NULL != g) yajl_gen_free(g);
    return ret;
}

//  {"sender":"my3CohS9f57yCqNy4yAPbBRqLaAAJ9oqXV","body":{"method":33,"params":"{\"pippa\":\"lapeppa\"}","id":1477550301}}

/**
 * Parses an RPC  response message and returns its components
 *
 * @param[in]  msg	  message
 * @param[in]  size   size in byte of the message
 * @param[out] sender pointer to a buffer to be filled with the sender address
 * @param[in]  ssize  size of the sender buffer
 * @param[out] error  pointer to an int variable to be filled with the error
 *                    error represent the status of the RPC transport and not
 *                    of the RPC execution
 * @param[out] result pointer to a buffer filled with the RPC result string
 * @param[in]  rsize  size of the result buffer
 * @param[out] sID    pointer to an int64_t variable to be filled with the session ID
 *
 * @return     0 == no error
 */
int UID_parseRespMsg(uint8_t *msg, size_t size, char *sender, size_t ssize, int *error, char *result, size_t rsize, int64_t *sID)
{
(void)size;
    yajl_val node, v;
    int ret;
    char *s;
    const char * _id[] = { "body", "id", (const char *) 0 };
    const char * _error[] = { "body", "error", (const char *) 0 };
    const char * _result[] = { "body", "result", (const char *) 0 };
    const char * _signature[] = { "signature", (const char *) 0 };

    // parse message
    node = yajl_tree_parse((char *)msg, NULL, 0);
    if (node == NULL) return UID_MSG_JPARSE_ERROR;


// get the sID
    ret = UID_MSG_JPARSE_ERROR;
    v = yajl_tree_get(node, _id, yajl_t_number);
    if (v == NULL) goto clean_return;

    *sID = YAJL_GET_INTEGER(v);

// get the error
    ret = UID_MSG_JPARSE_ERROR;
    v = yajl_tree_get(node, _error, yajl_t_number);
    if (v == NULL) goto clean_return;

    *error = YAJL_GET_INTEGER(v);

//get the result
    ret = UID_MSG_JPARSE_ERROR;
    v = yajl_tree_get(node, _result, yajl_t_string);
    if (v == NULL) goto clean_return;
    s =  YAJL_GET_STRING(v);

    ret = UID_MSG_SMALL_BUFFER;
    if (strlen(s) >= rsize) goto clean_return;
    strncpy(result, s, rsize);

//get the signature
    ret = UID_MSG_JPARSE_ERROR;
    v = yajl_tree_get(node, _signature, yajl_t_string);
    if (v == NULL) goto clean_return;
    char *b64signature =  YAJL_GET_STRING(v);

//recover the sender
    ret = UID_MSG_SMALL_BUFFER;
    if (sizeof(BTC_Address) > ssize) goto clean_return;
    uint8_t hash[32] = {0};
    hashSerializeddata(*error, result, *sID, hash);
    ret = UID_addressFromSignedHash(hash, b64signature, sender);
    if(UID_SIGN_OK != ret) goto clean_return;

    ret = UID_MSG_OK;
clean_return:
    if (NULL != node) yajl_tree_free(node);
    return ret;
}

/**
 * Perform all the closing activities for the user
 *
 * @param[in] ctx pointer to the context
 *
 * @return        0 == no error
 */
int UID_closeChannel(UID_ClientChannelCtx *ctx)
{
    (void)ctx;
    return UID_MSG_OK;
}

/**
 * Perform all the closing activities for the provider
 *
 * @param[in] ctx pointer to the context
 *
 * @return        0 == no error
 */
int UID_closeServerChannel(UID_ServerChannelCtx *ctx)
{
    (void)ctx;
    return UID_MSG_OK;
}
