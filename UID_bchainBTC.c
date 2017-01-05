/*
 * UID_bchainBTC.c
 *
 *  Created on: 5/aug/2016
 *      Author: M. Palumbi
 */
  
 




/* 
 * DESCRIPTION
 * Block chain functions for BTC using insight-api
 * 
 */

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <curl/curl.h>
#include <pthread.h>
#include "sha2.h"
#include "UID_utils.h"
#include "UID_globals.h"
#include "UID_identity.h"
#include "UID_bchainBTC.h"
#include "yajl/yajl_parse.h"

// double buffer for contract cache
// UID_getContracts may fill seconb while current is read
cache_buffer cache0 = { { { {0},{0},{0,{0},0,{{0}}} } }, 0, { { {0},{0},{0} } }, 0, PTHREAD_MUTEX_INITIALIZER };
cache_buffer cache1 = { { { {0},{0},{0,{0},0,{{0}}} } }, 0, { { {0},{0},{0} } }, 0, PTHREAD_MUTEX_INITIALIZER };

cache_buffer *current = &cache0;
cache_buffer *secondb = &cache1;


typedef struct  {
    yajl_handle hand;
    int totalItems;
    int toItems;
//    char *orchestrator;
    char *serviceProviderAddress;
    bool isOrchestrator;
    bool isContract;
    unsigned char *fileData;
    int rd;
} parse_context;


// callback from curl_easy_perform
// calls yajl_parse to parse the data just received
static size_t parse_txs(void *buffer, size_t size, size_t nmemb, void *ctx)
{
    (void)size;(void)nmemb;
    //printf("curl callback called with size = %d nmemb = %d\n", size, nmemb);
    if (((parse_context *)ctx)->hand == NULL)
    {
        sscanf(buffer, "{\"totalItems\":%d", &(((parse_context *)ctx)->totalItems));    
        return nmemb;
    }

    return nmemb;
}

#ifdef DUMMY_CACHE
void fillDummyCache(void)
// fill the Contractrs Cache
{
    // fill the dummy cache
    // user (bip32.org Passphrase user weak hash)
    // tprv8ZgxMBicQKsPfMnootPTR6b8KjS1FbN3ikSynKf1wM7Y7cv8RipNDpdDtr2BuT8EKNsVjKvVe1iZc83J7SRu4gvjGiu8bKxhrRuKZfJXMtZ
    // user1
    // tprv8ZgxMBicQKsPeNN7y2mmmFJf6Mh2FLzzNmHn67gmy7CjwQYucmHwdjFugaFU8A1NwMJWjWrC46fxcTUaSYTLpn7H8oyUYneegarrfvHQYF1
    // provider (bip32.org Passphrase provider weak hash)
    // tprv8ZgxMBicQKsPdLmDgjo8Ed2U8c93oN4kJx2B2UfWmB878YcKiBCWu1WnrDqWZxSCzg9fsZASieJajf3nsckqbboJei53SrfqqEwcFz8sUhr
    strncpy(secondb->contractsCache[0].serviceUserAddress, "my3CohS9f57yCqNy4yAPbBRqLaAAJ9oqXV", sizeof(BTC_Address));          // user     m/0'/0/0
    strncpy(secondb->contractsCache[0].serviceProviderAddress, "mw5oLLjxSNsPRdDgArCZseGEQJVdNYNK5U", sizeof(BTC_Address));      // provider m/0'/0/0
    memset(secondb->contractsCache[0].profile.bit_mask, 0, sizeof(secondb->contractsCache[0].profile.bit_mask));
    strncpy(secondb->contractsCache[1].serviceUserAddress, "myUFCeVGwkJv3PXy4zc1KSWRT8dC5iTvhU", sizeof(BTC_Address));          // user1    m/0'/0/1
    strncpy(secondb->contractsCache[1].serviceProviderAddress, "mtEQ22KCcjpz73hWfNvJoq6tqMEcRUKk3m", sizeof(BTC_Address));      // provider m/0'/0/1
    memset(secondb->contractsCache[1].profile.bit_mask, 0xFF, sizeof(secondb->contractsCache[1].profile.bit_mask));
    secondb->validCacheEntries = 2;
    strncpy(secondb->clientCache[0].serviceProviderName, "LocalMachine", sizeof(((UID_ClientProfile *)0)->serviceProviderName));
    strncpy(secondb->clientCache[0].serviceProviderAddress, "mw5oLLjxSNsPRdDgArCZseGEQJVdNYNK5U", sizeof(((UID_ClientProfile *)0)->serviceProviderAddress));// provider m/0'/0/0
    strncpy(secondb->clientCache[0].serviceUserAddress, "my3CohS9f57yCqNy4yAPbBRqLaAAJ9oqXV", sizeof(((UID_ClientProfile *)0)->serviceUserAddress));        // user     m/0'/0/0
    strncpy(secondb->clientCache[1].serviceProviderName, "UID984fee057c6d", sizeof(((UID_ClientProfile *)0)->serviceProviderName));
    strncpy(secondb->clientCache[1].serviceProviderAddress, "mtEQ22KCcjpz73hWfNvJoq6tqMEcRUKk3m", sizeof(((UID_ClientProfile *)0)->serviceProviderAddress));// provider m/0'/0/1
    strncpy(secondb->clientCache[1].serviceUserAddress, "myUFCeVGwkJv3PXy4zc1KSWRT8dC5iTvhU", sizeof(((UID_ClientProfile *)0)->serviceUserAddress));        // user1     m/0'/0/1
    strncpy(secondb->clientCache[2].serviceProviderName, "nocontract", sizeof(((UID_ClientProfile *)0)->serviceProviderName));
    strncpy(secondb->clientCache[2].serviceProviderAddress, "mtEQ22KCcjpz73hWfNvJoq6tqMEcRUKk3m", sizeof(((UID_ClientProfile *)0)->serviceProviderAddress));// provider m/0'/0/1
    strncpy(secondb->clientCache[2].serviceUserAddress, "n1UevZASvVyNhAB2d5Nm9EaHFeooJZbSP7", sizeof(((UID_ClientProfile *)0)->serviceUserAddress));        // user1     m/0'/0/3
    secondb->validClientEntries = 3;
}
#endif


int UID_getContracts(cache_buffer **cache)
{
    CURL *curl;
    char url[256];
    parse_context ctx;
    int res;

    curl = curl_easy_init();
    /* Define our callback to get called when there's data to be written */ 
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, parse_txs);
    /* Set a pointer to our struct to pass to the callback */ 
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);


    // setup context for the callback
    //ctx.serviceProviderAddress = localIdentity->address;

    // Get ctx.totalItems
    snprintf(url, sizeof(url), UID_GETTXS, "localIdentity->address", 0, 0);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    res = UID_CONTRACTS_SERV_ERROR;
    if(curl_easy_perform(curl) != 0) goto clean_ret; // error contacting server
        
    pthread_mutex_lock(&(secondb->in_use));  // lock the resource

    (secondb->validCacheEntries) = 0; // void the cache

#ifdef DUMMY_CACHE
    fillDummyCache();
#else
    // fill the Contractrs Cache
    {
        //snprintf(url, sizeof(url), UID_GETTXS, localIdentity->address, from, to < ctx.totalItems ? to : ctx.totalItems);
        //curl_easy_setopt(curl, CURLOPT_URL, url);
        //curl_easy_perform(curl);  // perform http request
        
    } ;
#endif
    
    pthread_mutex_unlock(&(secondb->in_use));  // unlock the resource
    *cache = secondb;  // swap the buffers
    secondb = current;
    current = *cache;
    res = UID_CONTRACTS_OK;
    goto clean_ret;

clean_ret:
    /* always cleanup */ 
    curl_easy_cleanup(curl);
    
    return res;
}

static UID_SecurityProfile goodContract; //TODO warning non reantrant code!!!

// retrives the matching contract from the Contracts Cache
UID_SecurityProfile *UID_matchContract(BTC_Address serviceUserAddress)
{
    int i;
    cache_buffer *ptr = current ;
    UID_SecurityProfile *ret_val = NULL;

    pthread_mutex_lock(&(ptr->in_use));  // lock the resource

    for(i=0; i<(ptr->validCacheEntries); i++)
    {
        if (strcmp((ptr->contractsCache)[i].serviceUserAddress, serviceUserAddress) == 0)
        {   // found the contract
            //if ((ptr->contractsCache)[i].profile == 0) break; // profile == 0 contract revoked! return NULL
            memcpy(&goodContract,  (ptr->contractsCache) + i, sizeof(goodContract)); // copy to goodContract
            ret_val = &goodContract; // return pointer to it
            break;
        }
    }

    pthread_mutex_unlock(&(ptr->in_use));  // unlock the resource
    return ret_val;
}

static UID_ClientProfile clientContract; //TODO warning non reantrant code!!!

// retrives the matching contract from the client Cache
UID_ClientProfile *UID_matchProvider(char *name)
{
    int i;
    cache_buffer *ptr = current ;
    UID_ClientProfile *ret_val = NULL;

    pthread_mutex_lock(&(ptr->in_use));  // lock the resource

    for(i=0; i<(ptr->validClientEntries); i++)
    {
        if (strcmp((ptr->clientCache)[i].serviceProviderName, name) == 0)
        {   // found the contract
            memcpy(&clientContract,  (ptr->clientCache) + i, sizeof(clientContract)); // copy to clientContract
            ret_val = &clientContract; // return pointer to it
            break;
        }
    }

    pthread_mutex_unlock(&(ptr->in_use));  // unlock the resource
    return ret_val;
}

typedef struct {
    size_t buffer_size;
    char  *buffer;
} send_tx_context;

/**
 * callback from curl_easy_perform
 * returns the answer for the send from insight-api
 */
static size_t send_tx(void *buffer, size_t size, size_t nmemb, send_tx_context *ctx)
{
    size_t l = size*nmemb;

    if (l < ctx->buffer_size) {
        memcpy(ctx->buffer, buffer, l);
        ctx->buffer += l;
        *ctx->buffer = 0;
        ctx->buffer_size -= l;
        return l;
    }
    else {
        return -1;
    }
}

int UID_sendTx(char *signed_tx, char *ret, size_t size)
{
    CURL *curl;
    CURLcode res;
    send_tx_context ctx;

    curl = curl_easy_init();
    /* Define our callback to get called when there's data to be written */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, send_tx);
    /* Set a pointer to our struct to pass to the callback */
    ctx.buffer_size = size;
    ctx.buffer = ret;
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);

    curl_easy_setopt(curl, CURLOPT_URL, UID_SENDTX);
    /* setup post data */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, signed_tx);
    /* perform the request */
    res = curl_easy_perform(curl);

    /* always cleanup */
    curl_easy_cleanup(curl);

    return res;
}
