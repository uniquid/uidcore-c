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
cache_buffer cache0 = { { { {0},{0},{0} } }, 0, { { {0},{0},{0} } }, 0, PTHREAD_MUTEX_INITIALIZER };
cache_buffer cache1 = { { { {0},{0},{0} } }, 0, { { {0},{0},{0} } }, 0, PTHREAD_MUTEX_INITIALIZER };

cache_buffer *current = &cache0;
cache_buffer *secondb = &cache1;

#define GETTXS "http://appliance2.uniquid.co:8080/insight-api/addrs/%s/txs?from=%d&to=%d"
//#define GETTXS "http://appliance1.uniquid.co:3001/insight-api/addrs/%s/txs?from=%d"

typedef struct  {
    yajl_handle hand;
    int totalItems;
    int toItems;
    char *orchestrator;
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
    printf("curl callback called with size = %d nmemb = %d\n", size, nmemb);
    if (((parse_context *)ctx)->hand == NULL)
    {
        sscanf(buffer, "{\"totalItems\":%d", &(((parse_context *)ctx)->totalItems));    
        return nmemb;
    }

    return nmemb;
}



cache_buffer *UID_getContracts(UID_Identity *localIdentity)
{
    CURL *curl;
    char url[256];
    parse_context ctx;

    curl = curl_easy_init();
    /* Define our callback to get called when there's data to be written */ 
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, parse_txs);
    /* Set a pointer to our struct to pass to the callback */ 
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);


    // setup context for the callback
    ctx.orchestrator = localIdentity->orchestrator;
    ctx.serviceProviderAddress = localIdentity->address;

    // Get ctx.totalItems
    snprintf(url, sizeof(url), GETTXS, localIdentity->address, 0, 0);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    if(curl_easy_perform(curl) != 0) goto clean_ret; // error contacting server
        
    pthread_mutex_lock(&(secondb->in_use));  // lock the resource

    (secondb->validCacheEntries) = 0; // void the cache

    // fill the Contractrs Cache
    {
        //snprintf(url, sizeof(url), GETTXS, localIdentity->address, from, to < ctx.totalItems ? to : ctx.totalItems);
        //curl_easy_setopt(curl, CURLOPT_URL, url);
        //curl_easy_perform(curl);  // perform http request
        
    } ;
    
    pthread_mutex_unlock(&(secondb->in_use));  // unlock the resource
    current = secondb;  // swap the buffers
    goto clean_ret;

clean_ret:
    /* always cleanup */ 
    curl_easy_cleanup(curl);
    
    return current;
}

static UID_SecurityProfile goodContract;

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
