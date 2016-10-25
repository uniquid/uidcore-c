/*
 * UID_bchainBTC.h
 *
 *  Created on: 5/aug/2016
 *      Author: M. Palumbi
 */
 
 
#ifndef __UID_BCHAINBTC_H
#define __UID_BCHAINBTC_H

#include "UID_globals.h"
#include "stdint.h"

#define CONTRACTS_CACHE_SIZE 200 // number of locally cached contracts
#define CLIENT_CACHE_SIZE 50 // number of locally cached client contracts
#define PROFILE_SIZE 40 // OP_RETURN lenght...

typedef struct
{
    BTC_Address serviceUserAddress;
    BTC_Address serviceProviderAddress;
    uint8_t     profile[PROFILE_SIZE];
} UID_SecurityProfile;

typedef struct
{
    char serviceProviderName[16];
    BTC_Address serviceProviderAddress;
    BTC_Address serviceUserAddress;
} UID_ClientProfile;

typedef struct {
    UID_SecurityProfile contractsCache[CONTRACTS_CACHE_SIZE];
    int validCacheEntries;
    UID_ClientProfile clientCache[CLIENT_CACHE_SIZE];
    int validClientEntries;
    pthread_mutex_t in_use;
} cache_buffer;

cache_buffer *UID_getContracts(UID_Identity *localIdentity);
UID_SecurityProfile *UID_matchContract(BTC_Address serviceUserAddress);

uint8_t * sha256sha256_padded64(char *str, uint8_t hash[32] );

#endif

