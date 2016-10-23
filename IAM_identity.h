/*
 * IAM_identity.h
 *
 *  Created on: 3/aug/2016
 *      Author: M. Palumbi
 */
 
 
#ifndef __IAM_IDENTITY_H
#define __IAM_IDENTITY_H

#include <stdint.h>

#include "IAM_globals.h"

typedef struct 
{
    IAM_KeyPair keyPair;
    BTC_Address address;  // address  base58 coded
    BTC_Address orchestrator;
    uint64_t balance;    // bitcoin balance in Satoshi (10e-8 BTC)
} IAM_Identity;

IAM_Identity *IAM_getLocalIdentity(char *keypriv_h, BTC_Address orchestrator);

#endif
