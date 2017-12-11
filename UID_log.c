/*
 * @file   UID_log.c
 *
 * @date   11/dec/2017
 * @author M. Palumbi
 */

/**
 * @file UID_log.h
 *
 * log function
 *
 */

#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

#include "UID_log.h"

void UID_logImplement( char *fmt, ... )
{
	va_list ap;

	va_start( ap, fmt );
	vprintf( fmt, ap );
	va_end( ap );
}
