/*
 * UID_identity.h
 *
 *  Created on: 3/aug/2016
 *      Author: M. Palumbi
 */
 
 
#ifndef __UID_IDENTITY_H
#define __UID_IDENTITY_H

#include <stdint.h>

#include "UID_globals.h"

typedef struct 
{
    UID_KeyPair keyPair;
    BTC_Address address;  // address  base58 coded
    BTC_Address orchestrator;
    uint64_t balance;    // bitcoin balance in Satoshi (10e-8 BTC)
} UID_Identity;

UID_Identity *UID_getLocalIdentity(char *keypriv_h, BTC_Address orchestrator);

#endif
