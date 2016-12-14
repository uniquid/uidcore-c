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


static UID_Identity identity;
static HDNode node;

char *identityDB = "./identity.db";

static char lbuffer[1024];

UID_Identity *UID_getLocalIdentity(char *tprv)
{
    char privateKey[256]; 
    uint64_t balance = 10e7;  // satoshi = (10e-8 BTC)
    FILE *id;
    char format[64];


    if ((id = fopen(identityDB, "r")) != NULL)
    {
        while(fgets(lbuffer, sizeof(lbuffer), id) != NULL)
        {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
            snprintf(format, sizeof(format),  "privateKey: %%%zus\n", sizeof(privateKey) - 1);
            if (sscanf(lbuffer, format,  privateKey) == 1) tprv = privateKey; // if read OK assign to tprv

#pragma GCC diagnostic pop

            fscanf(id, "balance: %lld\n", &balance);
        }
        fclose(id);
    }

    if(tprv == NULL) 
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
	    hdnode_deserialize(tprv, &node);
	}
	hdnode_fill_public_key(&node);
	memcpy(identity.keyPair.privateKey, node.private_key, sizeof(identity.keyPair.privateKey));
	memcpy(identity.keyPair.publicKey, node.public_key, sizeof(identity.keyPair.publicKey));
	ecdsa_get_address(node.public_key, /*version*/ NETWORK_BYTE, identity.address, sizeof(identity.address));
	identity.balance = balance;  // satoshi = (10e-8 BTC)
	

    if ((id = fopen(identityDB, "w")) != NULL)
    {
        memset(privateKey, 0, sizeof(privateKey));
        hdnode_serialize_private(&node, 0 /*uint32_t fingerprint*/, privateKey, sizeof(privateKey));
        fprintf(id, "privateKey: %s\n", privateKey);
        fprintf(id, "balance: %lld\n", identity.balance);
        fclose(id);
    }


    return &identity;
}



