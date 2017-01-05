/*
 *  @file   UID_fillCache.c
 *
 *
 *  @date   05/jan/2016
 *  @author M. Palumbi
 */


/**
 * @file UID_fillCache.h
 *
 * The module implements the filling of cache crontracts from
 * the blockchain
 *
 */

#include <stdio.h>
#include <string.h>
#include "yajl/yajl_tree.h"
#include "yajl/yajl_parse.h"
#include "UID_fillCache.h"
#include "UID_utils.h"
#include "UID_identity.h"



typedef struct  {
    size_t size;
    char  *buffer;
} curl_context;


// callback from curl_easy_perform
// calls yajl_parse to parse the data just received
static size_t curl_callback(void *buffer, size_t size, size_t nmemb, curl_context *ctx)
{
    size_t l = size*nmemb;

    if (l < ctx->size) {
        memcpy(ctx->buffer, buffer, l);
        ctx->buffer += l;
        *ctx->buffer = 0;
        ctx->size -= l;
        return l;
    }
    else {
        return -1;
    }
}

CURLcode curlget(CURL *curl, char *url, char *buffer, size_t size)
{
    curl_context ctx;

    ctx.buffer = buffer;
    ctx.size = size;

    /* Define our callback to get called when there's data to be written */ 
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_callback);
    /* Set a pointer to our struct to pass to the callback */ 
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);
    curl_easy_setopt(curl, CURLOPT_URL, url);

    return curl_easy_perform(curl);
}
static char curlbuffer[3000];
int UID_fillCache(CURL *curl, cache_buffer *secondb)
{
(void)secondb;
    int res;
    char url[256];


    // setup context for the callback
    //ctx.serviceProviderAddress = localIdentity->address;

    // Get ctx.totalItems
    snprintf(url, sizeof(url), UID_GETTXS, "localIdentity->address", 0, 0);
    if(CURLE_OK == curlget(curl, url, curlbuffer, sizeof(curlbuffer))) {
        printf(" --- %s ---\n", curlbuffer);
    }
    res = UID_CONTRACTS_SERV_ERROR;

    return res;
}