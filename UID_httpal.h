/*
 * Copyright (c) 2016-2018. Uniquid Inc. or its affiliates. All Rights Reserved.
 *
 * License is in the "LICENSE" file accompanying this file.
 * See the License for the specific language governing permissions and limitations under the License.
 */

 /**
 * @file   UID_httpal.h
 *
 * @date   09/dec/2017
 * @author M. Palumbi
 */

#ifndef __UID_HTTPAL_H
#define __UID_HTTPAL_H

#include "UID_globals.h"
typedef void  UID_HttpOBJ;

// root CA chain for UID_httpget()
#define DEFAULT_ROOT_CA_LOCATION  "./rootCA.crt"
extern char *UID_rootCA; // = DEFAULT_ROOT_CA_LOCATION;


int UID_httpget(UID_HttpOBJ *curl, char *url, char *buffer, size_t size);
#ifdef UID_IMPLEMENTSENDTX
int UID_httppost(UID_HttpOBJ *curl, char *url, char *postdata, char *ret, size_t size);
#endif //UID_IMPLEMENTSENDTX

UID_HttpOBJ *UID_httpinit(void);
int UID_httpcleanup(UID_HttpOBJ *curl);

#endif // __UID_HTTPAL_H