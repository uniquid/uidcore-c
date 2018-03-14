/*
 * @file   UID_capBAC.c
 *
 * @date   7/mar/2018
 * @author M. Palumbi
 */


/**
 * @file   UID_capBAC.h
 *
 * Capability access implementation
 *
 */

#include <stdio.h>
#include "UID_capBAC.h"
#include "UID_utils.h"

/**
 * Serializes the capability in order to sign it
 *
 * @param[in]  cap    capability to be serialized
 * @param[out] buffer buffer to be filled with the serialized capability
 * @param[in]  size   size of the output buffer
 *
 * @return           UID_CAPBAC_OK if no error
 */
int UID_prepareToSign(UID_UniquidCapability *cap, char *buffer, size_t size)
{
    char hexbuf[2*sizeof(UID_Rights)+1] = {0};

    tohex((uint8_t *)&(cap->rights), sizeof(UID_Rights), hexbuf);
    int ret = snprintf(buffer, size, "%s%s%s%s%ld%ld", cap->assigner, cap->resourceID, cap->assignee, hexbuf, cap->since, cap->until );

    if (ret < 0) return UID_CAPBAC_SER_ERROR;
    if ((size_t)ret < size) return UID_CAPBAC_OK;
    return UID_CAPBAC_SMALL_BUFFER;
}