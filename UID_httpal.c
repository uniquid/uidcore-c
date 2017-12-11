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
#include "UID_httpal.h"

typedef struct  {
    size_t size;
    char  *buffer;
} curl_context;

// callback from curl_easy_perform
static size_t curl_callback(char *buffer, size_t size, size_t nmemb, void *ctx)
{
    size_t l = size*nmemb;

    if (l < ((curl_context *)ctx)->size) {
        memcpy(((curl_context *)ctx)->buffer, buffer, l);
        ((curl_context *)ctx)->buffer += l;
        *((curl_context *)ctx)->buffer = 0;
        ((curl_context *)ctx)->size -= l;
        return l;
    }
    else {
        return -1;
    }
}

/**
 * Get data from url
 *
 * @param[in]  curl   pointer to an initialized CURL struct
 * @param[in]  url    url to contact
 * @param[out] buffer pointer to buffer to be filled
 * @param[in]  size   size of buffer
 *
 * @return     CURLE_OK no error (see curl documentation)
 */
CURLcode UID_httpget(CURL *curl, char *url, char *buffer, size_t size)
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

typedef struct {
    size_t buffer_size;
    char  *buffer;
} send_tx_context;

/**
 * callback from curl_easy_perform
 * returns the answer for the send from insight-api
 */
static size_t send_tx(char *buffer, size_t size, size_t nmemb, void *ctx)
{
    size_t l = size*nmemb;

    if (l < ((send_tx_context *)ctx)->buffer_size) {
        memcpy(((send_tx_context *)ctx)->buffer, buffer, l);
        ((send_tx_context *)ctx)->buffer += l;
        *((send_tx_context *)ctx)->buffer = 0;
        ((send_tx_context *)ctx)->buffer_size -= l;
        return l;
    }
    else {
        return -1;
    }
}

CURLcode UID_httppost(CURL *curl, char *url, char *postdata, char *ret, size_t size)
{
    send_tx_context ctx;

    /* Define our callback to get called when there's data to be written */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, send_tx);
    /* Set a pointer to our struct to pass to the callback */
    ctx.buffer_size = size;
    ctx.buffer = ret;
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    /* setup post data */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);
    /* perform the request */
    return curl_easy_perform(curl);
}