/**
 *
 * INTEL CONFIDENTIAL
 * Copyright(c) 2011-2016 Intel Corporation All Rights Reserved.
 *
 * The source code contained or described herein and all documents related to
 * the source code ("Material") are owned by Intel Corporation or its suppliers
 * or licensors. Title to the Material remains with Intel Corporation or its
 * suppliers and licensors. The Material contains trade secrets and proprietary
 * and confidential information of Intel or its suppliers and licensors. The
 * Material is protected by worldwide copyright and trade secret laws and treaty
 * provisions. No part of the Material may be used, copied, reproduced, modified,
 * published, uploaded, posted, transmitted, distributed, or disclosed in any
 * way without Intel's prior express written permission.
 *
 * No license under any patent, copyright, trade secret or other intellectual
 * property right is granted to or conferred upon you by disclosure or delivery
 * of the Materials, either expressly, by implication, inducement, estoppel or
 * otherwise. Any license under such intellectual property rights must be
 * express and approved by Intel(R) in writing.
 *
 */


#include "se_trace.h"
#include <stdarg.h>
#ifdef ANDROID
#include <android/log.h>
#define APP_NAME "SE_APP"
#endif
int se_trace_internal(int debug_level, const char *fmt, ...)
{
    va_list args;
    int ret = 0;

    va_start(args, fmt);
#ifdef ANDROID
    const size_t pMsgLen = 2048;
    char pMsg[pMsgLen];
    (void) debug_level;
    ret = vsnprintf(pMsg, pMsgLen, fmt, args);
    __android_log_print(ANDROID_LOG_ERROR, APP_NAME, "%s\n", pMsg);
#else
    if(SE_TRACE_NOTICE == debug_level)
        ret = vfprintf(stdout, fmt, args);
    else
        ret = vfprintf(stderr, fmt, args);
#endif
    va_end(args);

    return ret;
}
