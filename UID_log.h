/**
 * @file   UID_log.h
 *
 * @date   11/dec/2017
 * @author M. Palumbi
 */

#ifndef __UID_LOG_H
#define __UID_LOG_H

#define UID_LOG_ERROR 1
#define UID_LOG_WARNING 2
#define UID_LOG_INFO 3
#define UID_LOG_DEBUG 4
#define UID_LOG_VERBOSE 5

void UID_logImplement( char *fmt, ... );

/*
 * usage
 */
//#define UID_LOGLEVEL UID_LOG_WARNING
// UID_log(UID_LOG_WARNING, char *fmt, ... );

#define UID_log(level, ...) UID_log_(level, __VA_ARGS__)
#define UID_log_(level, ...) UID_log ##level(__VA_ARGS__)

#ifndef UID_LOGLEVEL
    #define UID_LOGLEVEL 0
#endif

#if UID_LOGLEVEL >= 1
    #define UID_log1(...) UID_logImplement(__VA_ARGS__)
#else
    #define UID_log1(...)
#endif
#if UID_LOGLEVEL >= 2
    #define UID_log2(...) UID_logImplement(__VA_ARGS__)
#else
    #define UID_log2(...)
#endif
#if UID_LOGLEVEL >= 3
    #define UID_log3(...) UID_logImplement(__VA_ARGS__)
#else
    #define UID_log3(...)
#endif
#if UID_LOGLEVEL >= 4
    #define UID_log4(...) UID_logImplement(__VA_ARGS__)
#else
    #define UID_log4(...)
#endif
#if UID_LOGLEVEL >= 5
    #define UID_log5(...) UID_logImplement(__VA_ARGS__)
#else
    #define UID_log5(...)
#endif

#endif // __UID_LOG_H