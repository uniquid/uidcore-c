/*
 * @file   UID_identity.c
 *
 * @date   1/aug/2016
 * @author M. Palumbi
 */


/**
 * @file   UID_identity.h
 *
 * identity functions
 *
 */
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <inttypes.h>
#include "curves.h"
#include "secp256k1.h"
#include "bip32.h"
#include "UID_utils.h"
#include "UID_identity.h"


static UID_Identity identity;
static HDNode node_m;

static HDNode node_m_44H_0H;  // imprinting
static char tpub[120];
static HDNode node_m_44H_0H_0;  // orchestrator
static HDNode node_m_44H_0H_0_x[2][2];
        //                      ^  ^
        // provider/user________|  |
        // intern/extern___________|

char *identityDB = UID_DEFAULT_IDENTITY_FILE;

static char lbuffer[1024];

static HDNode *UID_deriveAt(UID_Bip32Path *path, HDNode *node)
{
    if (path->p_u > 1 )
        return NULL;
    if (path->account > 1 )
        return NULL;
    memcpy( node, &node_m_44H_0H_0_x[path->p_u][path->account], sizeof(HDNode));
    hdnode_private_ckd(node, path->n);
//    hdnode_fill_public_key(node);
    return node;
}

static void derive_m_44H_0H_x(void)
{
	uint32_t fingerprint;

    // [Chain m/44']
    memcpy(&node_m_44H_0H, &node_m, sizeof(HDNode));
    hdnode_private_ckd_prime(&node_m_44H_0H, 44);

    // [Chain m/44'/0']
    fingerprint = hdnode_fingerprint(&node_m_44H_0H);
    //memcpy(&node_m_44H_0H, &node_m_44H_0H, sizeof(HDNode));
    hdnode_private_ckd_prime(&node_m_44H_0H, 0);
	hdnode_fill_public_key(&node_m_44H_0H);
	hdnode_serialize_public(&node_m_44H_0H, fingerprint, tpub, sizeof(tpub));

    // [Chain m/44'/0'/0]
    memcpy(&node_m_44H_0H_0, &node_m_44H_0H, sizeof(HDNode));
    hdnode_private_ckd(&node_m_44H_0H_0, 0);


    // [Chain m/44'/0'/0/0]
    memcpy(&node_m_44H_0H_0_x[0][0], &node_m_44H_0H_0, sizeof(HDNode));
    hdnode_private_ckd(&node_m_44H_0H_0_x[0][0], 0);
    memcpy(&node_m_44H_0H_0_x[0][1], &node_m_44H_0H_0_x[0][0], sizeof(HDNode));

    // [Chain m/44'/0'/0/0/0]
    hdnode_private_ckd(&node_m_44H_0H_0_x[0][0], 0);

    // [Chain m/44'/0'/0/0/1]
    hdnode_private_ckd(&node_m_44H_0H_0_x[0][1], 1);

    // [Chain m/44'/0'/0/1]
    memcpy(&node_m_44H_0H_0_x[1][0], &node_m_44H_0H_0, sizeof(HDNode));
    hdnode_private_ckd(&node_m_44H_0H_0_x[1][0], 1);
    memcpy(&node_m_44H_0H_0_x[1][1], &node_m_44H_0H_0_x[1][0], sizeof(HDNode));

    // [Chain m/44'/0'/0/1/0]
    hdnode_private_ckd(&node_m_44H_0H_0_x[1][0], 0);

    // [Chain m/44'/0'/0/1/1]
    hdnode_private_ckd(&node_m_44H_0H_0_x[1][1], 1);
}

/**
 * load/create/store/ the machine identity (tprv @ nodo m)
 *
 * if exist the file identityDB, load the identity from it
 * else create a new one
 * stores the identity in the file identityDB
 *
 * @param[in]   tprv  if != NULL use it instead of a random seed
 * @return the machine identity
 */
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

            fscanf(id, "balance: %" PRIu64  "\n", &balance);
        }
        fclose(id);
    }

    if(tprv == NULL) 
    {
        uint8_t seed[32];
        int rnd = open("/dev/random", O_RDONLY);
        if(read(rnd, seed, sizeof(seed)) <= 0) // if we cant read /dev/random use time for seed
            *(int32_t *)seed = time(NULL);
        hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME, &node_m);
        close(rnd);
    }
	else
	{
	    hdnode_deserialize(tprv, &node_m);
	}
	hdnode_fill_public_key(&node_m);
	memcpy(identity.keyPair.privateKey, node_m.private_key, sizeof(identity.keyPair.privateKey));
	memcpy(identity.keyPair.publicKey, node_m.public_key, sizeof(identity.keyPair.publicKey));
	ecdsa_get_address(node_m.public_key, /*version*/ NETWORK_BYTE, identity.address, sizeof(identity.address));
	identity.balance = balance;  // satoshi = (10e-8 BTC)

	derive_m_44H_0H_x();

    if ((id = fopen(identityDB, "w")) != NULL)
    {
        memset(privateKey, 0, sizeof(privateKey));
        hdnode_serialize_private(&node_m, 0 /*uint32_t fingerprint*/, privateKey, sizeof(privateKey));
        fprintf(id, "privateKey: %s\n", privateKey);
        fprintf(id, "balance: %" PRIu64  "\n", identity.balance);
        fclose(id);
    }


    return &identity;
}

char *UID_getTpub(void)
{
    return tpub;
}

int UID_signAt(UID_Bip32Path *path, uint8_t hash[32], uint8_t sig[64])
{
    uint8_t pby = 0;
    HDNode node;

    UID_deriveAt(path, &node);
    ecdsa_sign_digest(&secp256k1, node.private_key, hash, sig, &pby);
    return 0;
}

int UID_getPubkeyAt(UID_Bip32Path *path, uint8_t public_key[33])
{
    HDNode node;
    UID_deriveAt(path, &node);
    hdnode_fill_public_key(&node);
    memcpy(public_key, node.public_key, 33);
    return 0;
}
