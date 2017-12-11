/**
 * @file   UID_httpal.h
 *
 * @date   09/dec/2017
 * @author M. Palumbi
 */

#ifndef __UID_HTTPAL_H
#define __UID_HTTPAL_H

#include <curl/curl.h>

CURLcode UID_httpget(CURL *curl, char *url, char *buffer, size_t size);
CURLcode UID_httppost(CURL *curl, char *url, char *postdata, char *ret, size_t size);

#endif // __UID_HTTPAL_H