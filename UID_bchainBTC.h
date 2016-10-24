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

typedef struct 
{
    BTC_Address identityProviderAddress;
    BTC_Address serviceUserAddress; // for compatibility with Stefac implementation
                                    // we store (in binary form) the sha256sha256 of the ascii
                                    // bitcoin base58 rappresentation of the address padded with 
                                    // binary 0 to te lenght of 64 bytes
    BTC_Address serviceProviderAddress;
    BTC_Address contractAddress;
    uint8_t     profile;
} UID_SecurityProfile;

typedef struct {
    UID_SecurityProfile contractsCache[CONTRACTS_CACHE_SIZE];
    int validCacheEntries;
    pthread_mutex_t in_use;
} cache_buffer;

cache_buffer *UID_getContracts(UID_Identity *localIdentity);
UID_SecurityProfile *UID_matchContract(BTC_Address serviceUserAddress);

uint8_t * sha256sha256_padded64(char *str, uint8_t hash[32] );

#endif

