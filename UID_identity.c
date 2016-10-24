/*
 * UID_identity.c
 *
 *  Created on: 1/aug/2016
 *      Author: M. Palumbi
 */
  
 




/* 
 * DESCRIPTION
 * IAM identity
 * 
 */
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include "curves.h"
#include "bip32.h"
#include "UID_utils.h"
#include "UID_identity.h"

UID_Identity *UID_fill_Identity(
    BTC_PrivateKey privateKey,
    BTC_PublicKey publicKey,
    BTC_Address address,  // address  base58 coded
    uint64_t    balance,    // bitcoin balance in Satoshi (10e-8 BTC)
    UID_Identity *identity)
{
    memcpy (identity->keyPair.privateKey, privateKey, sizeof(BTC_PrivateKey));
    memcpy (identity->keyPair.publicKey, publicKey, sizeof(BTC_PublicKey));
    strncpy(identity->address, address, sizeof(BTC_Address));


    identity->balance = balance;
    
    return identity;
}

static UID_Identity identity;
char *identityDB = NULL;

static char lbuffer[1024];

UID_Identity *UID_getLocalIdentity(char *keypriv_h, BTC_Address orchestrator)
{
    char privateKey[sizeof(BTC_PrivateKey)*2 + 1]; 
    BTC_Address orchestrator_b;
    HDNode node;
    uint8_t keypriv[32];
    uint8_t chaincode[32] = { 0 };
    uint64_t balance = 10e7;  // satoshi = (10e-8 BTC)
    FILE *id;
    char format[64];

    if (identityDB == NULL) identityDB = "./identity.db";

    if ((id = fopen(identityDB, "r")) != NULL)
    {
        while(fgets(lbuffer, sizeof(lbuffer), id) != NULL)
        {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
            snprintf(format, sizeof(format),  "privateKey: %%%zus\n", sizeof(privateKey) - 1);
            if (sscanf(lbuffer, format,  privateKey) == 1) keypriv_h = privateKey; // if read OK assign to keypriv_h

            snprintf(format, sizeof(format),  "orchestrator: %%%zus\n", sizeof(orchestrator_b) - 1);
            if (sscanf(lbuffer, format,  orchestrator_b) == 1) orchestrator = orchestrator_b; // if read OK assign to keypriv_h
#pragma GCC diagnostic pop

            fscanf(id, "balance: %lld\n", &balance);
        }
        fclose(id);
    }

    if(keypriv_h == NULL) 
    {
        uint8_t seed[32];
        int rnd = open("/dev/random", O_RDONLY);
        if(read(rnd, seed, sizeof(seed)) <= 0) // if we cant read /dev/random use time for seed
            *(int32_t *)seed = time(NULL);
        hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME, &node);
        close(rnd);
    }
	else
	{
	    hdnode_from_xprv(/*depth*/ 0, /*child_num*/ 0, /*chain_code*/ chaincode, /*private_key*/ fromhex(keypriv_h, keypriv), /*curve*/ SECP256K1_NAME, &node);
	}
	hdnode_fill_public_key(&node);
	memcpy(identity.keyPair.privateKey, node.private_key, sizeof(identity.keyPair.privateKey));
	memcpy(identity.keyPair.publicKey, node.public_key, sizeof(identity.keyPair.publicKey));
	ecdsa_get_address(node.public_key, /*version*/ NETWORK_BYTE, identity.address, sizeof(identity.address));
	identity.balance = balance;  // satoshi = (10e-8 BTC)
	
	if (orchestrator != NULL) memcpy(identity.orchestrator, orchestrator, sizeof(identity.orchestrator));

    if ((id = fopen(identityDB, "w")) != NULL)
    {
        fprintf(id, "privateKey: %s\n",  tohex(identity.keyPair.privateKey, sizeof(identity.keyPair.privateKey), privateKey));
        fprintf(id, "orchestrator: %s\n", identity.orchestrator);
        fprintf(id, "balance: %lld\n", identity.balance);
        fclose(id);
    }


    return &identity;
}



