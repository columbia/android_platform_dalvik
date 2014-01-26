/*
 * Copyright (c) 2010 The Pennsylvania State University
 * Systems and Internet Infrastructure Security Laboratory
 *
 * Authors: William Enck <enck@cse.psu.edu>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * dalvik.system.Taint
 */
#include "Dalvik.h"
#include "native/InternalNativePriv.h"
#include "attr/xattr.h"

#include <errno.h>
#include <stdint.h>

extern char *__progname;

/* tm_counter is used to assign unique identifier to events(branch choices,
 * output activities ...) gathered from different component(Posix.java,
 * dalvikvmvm, frameworks ..) so that we can resolve the ordering issues. */
uint64_t tm_counter = 0;
bool isTMeasureAPPFlag = false;

#define TAINT_XATTR_NAME "user.taint"

/*
 * public static void addTaintString(String str, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintString(const u4* args,
    JValue* pResult)
{
    StringObject *strObj = (StringObject*) args[0];
    u4 tag = args[1];
    ArrayObject *value = NULL;

    if (strObj) {
      value = strObj->array();
      value->taint.tag |= tag;
    }
    RETURN_VOID();
}

/*
 * public static void setTaintString(String str, int tag)
 */

static void Dalvik_dalvik_system_Taint_setTaintString(const u4* args,
    JValue* pResult)
{
    StringObject *strObj = (StringObject*) args[0];
    u4 tag = args[1];
    ArrayObject *value = NULL;

    if (strObj) {
      value = strObj->array();
      value->taint.tag = tag;
    }
    RETURN_VOID();
}


/*
 * public static void addTaintObjectArray(Object[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintObjectArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
    arr->taint.tag |= tag;
    }
    RETURN_VOID();
}

/*
 * public static void addTaintObjectArray(Object[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_setTaintObjectArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
      arr->taint.tag = tag;
    }
    RETURN_VOID();
}


/*
 * public static void addTaintBooleanArray(boolean[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintBooleanArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
      arr->taint.tag |= tag;
    }
    RETURN_VOID();
}


/*
 * public static void setTaintBooleanArray(boolean[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_setTaintBooleanArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
      arr->taint.tag = tag;
    }
    RETURN_VOID();
}


/*
 * public static void addTaintCharArray(char[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintCharArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
      arr->taint.tag |= tag;
    }
    RETURN_VOID();
}

/*
 * public static void setTaintCharArray(char[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_setTaintCharArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
      arr->taint.tag = tag;
    }
    RETURN_VOID();
}


/*
 * public static void addTaintByteArray(byte[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintByteArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
      arr->taint.tag |= tag;
    }
    RETURN_VOID();
}


/*
 * public static void setTaintByteArray(byte[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_setTaintByteArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
      arr->taint.tag = tag;
    }
    RETURN_VOID();
}


/*
 * public static void addTaintIntArray(int[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintIntArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
      arr->taint.tag |= tag;
    }
    RETURN_VOID();
}


/*
 * public static void setTaintIntArray(int[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_setTaintIntArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
      arr->taint.tag = tag;
    }
    RETURN_VOID();
}


/*
 * public static void addTaintShortArray(short[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintShortArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
      arr->taint.tag |= tag;
    }
    RETURN_VOID();
}


/*
 * public static void setTaintShortArray(short[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_setTaintShortArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
      arr->taint.tag = tag;
    }
    RETURN_VOID();
}


/*
 * public static void addTaintLongArray(long[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintLongArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
      arr->taint.tag |= tag;
    }
    RETURN_VOID();
}


/*
 * public static void setTaintLongArray(long[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_setTaintLongArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
      arr->taint.tag = tag;
    }
    RETURN_VOID();
}


/*
 * public static void addTaintFloatArray(float[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintFloatArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
      arr->taint.tag |= tag;
    }
    RETURN_VOID();
}


/*
 * public static void setTaintFloatArray(float[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_setTaintFloatArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
      arr->taint.tag = tag;
    }
    RETURN_VOID();
}


/*
 * public static void addTaintDoubleArray(double[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintDoubleArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
      arr->taint.tag |= tag;
    }
    RETURN_VOID();
}


/*
 * public static void setTaintDoubleArray(double[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_setTaintDoubleArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
      arr->taint.tag = tag;
    }
    RETURN_VOID();
}


/*
 * public static boolean addTaintBoolean(boolean val, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintBoolean(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 tag     = args[1];     /* the tag to add */
    u4* rtaint = (u4*) &args[2]; /* pointer to return taint tag */
    u4 vtaint  = args[3];     /* the existing taint tag on val */
    *rtaint = (vtaint | tag);
    RETURN_BOOLEAN(val);
}

/*
 * public static boolean setTaintBoolean(boolean val, int tag)
 */
static void Dalvik_dalvik_system_Taint_setTaintBoolean(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 tag     = args[1];     /* the tag to add */
    u4* rtaint = (u4*) &args[2]; /* pointer to return taint tag */
    *rtaint = (tag);
    RETURN_BOOLEAN(val);
}


/*
 * public static char addTaintChar(char val, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintChar(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 tag     = args[1];         /* the tag to add */
    u4* rtaint = (u4*) &args[2];  /* pointer to return taint tag */
    u4 vtaint  = args[3];      /* the existing taint tag on val */
    *rtaint = (vtaint | tag);
    RETURN_CHAR(val);
}


/*
 * public static char setTaintChar(char val, int tag)
 */
static void Dalvik_dalvik_system_Taint_setTaintChar(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 tag     = args[1];         /* the tag to add */
    u4* rtaint = (u4*) &args[2];  /* pointer to return taint tag */
    *rtaint = (tag);
    RETURN_CHAR(val);
}


/*
 * public static char addTaintByte(byte val, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintByte(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 tag     = args[1];         /* the tag to add */
    u4* rtaint = (u4*) &args[2];  /* pointer to return taint tag */
    u4 vtaint  = args[3];      /* the existing taint tag on val */
    *rtaint = (vtaint | tag);
    RETURN_BYTE(val);
}


/*
 * public static char setTaintByte(byte val, int tag)
 */
static void Dalvik_dalvik_system_Taint_setTaintByte(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 tag     = args[1];         /* the tag to add */
    u4* rtaint = (u4*) &args[2];  /* pointer to return taint tag */
    *rtaint = (tag);
    RETURN_BYTE(val);
}


/*
 * public static int addTaintInt(int val, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintInt(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 tag     = args[1];      /* the tag to add */
    u4* rtaint = (u4*) &args[2];  /* pointer to return taint tag */
    u4 vtaint  = args[3];      /* the existing taint tag on val */
    *rtaint = (vtaint | tag);
    RETURN_INT(val);
}


/*
 * public static int setTaintInt(int val, int tag)
 */
static void Dalvik_dalvik_system_Taint_setTaintInt(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 tag     = args[1];      /* the tag to add */
    u4* rtaint = (u4*) &args[2];  /* pointer to return taint tag */
    *rtaint = (tag);
    RETURN_INT(val);
}


/*
 * public static int addTaintShort(short val, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintShort(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 tag     = args[1];      /* the tag to add */
    u4* rtaint = (u4*) &args[2];  /* pointer to return taint tag */
    u4 vtaint  = args[3];      /* the existing taint tag on val */
    *rtaint = (vtaint | tag);
    RETURN_SHORT(val);
}


/*
 * public static int setTaintShort(short val, int tag)
 */
static void Dalvik_dalvik_system_Taint_setTaintShort(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 tag     = args[1];      /* the tag to add */
    u4* rtaint = (u4*) &args[2];  /* pointer to return taint tag */
    *rtaint = (tag);
    RETURN_SHORT(val);
}


/*
 * public static long addTaintLong(long val, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintLong(const u4* args,
    JValue* pResult)
{
    u8 val;
    u4 tag     = args[2];         /* the tag to add */
    u4* rtaint = (u4*) &args[3];     /* pointer to return taint tag */
    u4 vtaint  = args[4];         /* the existing taint tag on val */
    memcpy(&val, &args[0], 8);         /* EABI prevents direct store */
    *rtaint = (vtaint | tag);
    RETURN_LONG(val);
}


/*
 * public static long setTaintLong(long val, int tag)
 */
static void Dalvik_dalvik_system_Taint_setTaintLong(const u4* args,
    JValue* pResult)
{
    u8 val;
    u4 tag     = args[2];         /* the tag to add */
    u4* rtaint = (u4*) &args[3];     /* pointer to return taint tag */
    memcpy(&val, &args[0], 8);         /* EABI prevents direct store */
    *rtaint = ( tag);
    RETURN_LONG(val);
}


/*
 * public static float addTaintFloat(float val, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintFloat(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 tag     = args[1];      /* the tag to add */
    u4* rtaint = (u4*) &args[2];  /* pointer to return taint tag */
    u4 vtaint  = args[3];      /* the existing taint tag on val */
    *rtaint = (vtaint | tag);
    RETURN_INT(val);          /* Be opaque; RETURN_FLOAT doesn't work */
}


/*
 * public static float setTaintFloat(float val, int tag)
 */
static void Dalvik_dalvik_system_Taint_setTaintFloat(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 tag     = args[1];      /* the tag to add */
    u4* rtaint = (u4*) &args[2];  /* pointer to return taint tag */
    *rtaint = (tag);
    RETURN_INT(val);          /* Be opaque; RETURN_FLOAT doesn't work */
}


/*
 * public static double addTaintDouble(double val, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintDouble(const u4* args,
    JValue* pResult)
{
    u8 val;
    u4 tag     = args[2];         /* the tag to add */
    u4* rtaint = (u4*) &args[3];     /* pointer to return taint tag */
    u4 vtaint  = args[4];         /* the existing taint tag on val */
    memcpy(&val, &args[0], 8);         /* EABI prevents direct store */
    *rtaint = (vtaint | tag);
    RETURN_LONG(val);             /* Be opaque; RETURN_DOUBLE doesn't work */
}


/*
 * public static double setTaintDouble(double val, int tag)
 */
static void Dalvik_dalvik_system_Taint_setTaintDouble(const u4* args,
    JValue* pResult)
{
    u8 val;
    u4 tag     = args[2];         /* the tag to add */
    u4* rtaint = (u4*) &args[3];     /* pointer to return taint tag */
    memcpy(&val, &args[0], 8);         /* EABI prevents direct store */
    *rtaint = (tag);
    RETURN_LONG(val);             /* Be opaque; RETURN_DOUBLE doesn't work */
}


/*
 * public static int getTaintString(String str)
 */
static void Dalvik_dalvik_system_Taint_getTaintString(const u4* args,
    JValue* pResult)
{
    StringObject *strObj = (StringObject*) args[0];
    ArrayObject *value = NULL;

    if (strObj) {
    value = strObj->array();
    RETURN_INT(value->taint.tag);
    } else {
    RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getTaintObjectArray(Object[] obj)
 */
static void Dalvik_dalvik_system_Taint_getTaintObjectArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
    RETURN_INT(arr->taint.tag);
    } else {
    RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getTaintBooleanArray(boolean[] array)
 */
static void Dalvik_dalvik_system_Taint_getTaintBooleanArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
    RETURN_INT(arr->taint.tag);
    } else {
    RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getTaintCharArray(char[] array)
 */
static void Dalvik_dalvik_system_Taint_getTaintCharArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
    RETURN_INT(arr->taint.tag);
    } else {
    RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getTaintByteArray(byte[] array)
 */
static void Dalvik_dalvik_system_Taint_getTaintByteArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
    RETURN_INT(arr->taint.tag);
    } else {
    RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getTaintIntArray(int[] array)
 */
static void Dalvik_dalvik_system_Taint_getTaintIntArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
    RETURN_INT(arr->taint.tag);
    } else {
    RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getTaintShortArray(short[] array)
 */
static void Dalvik_dalvik_system_Taint_getTaintShortArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
    RETURN_INT(arr->taint.tag);
    } else {
    RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getTaintLongArray(long[] array)
 */
static void Dalvik_dalvik_system_Taint_getTaintLongArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
    RETURN_INT(arr->taint.tag);
    } else {
    RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getTaintFloatArray(float[] array)
 */
static void Dalvik_dalvik_system_Taint_getTaintFloatArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
    RETURN_INT(arr->taint.tag);
    } else {
    RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getTaintDoubleArray(double[] array)
 */
static void Dalvik_dalvik_system_Taint_getTaintDoubleArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
    RETURN_INT(arr->taint.tag);
    } else{
    RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getTaintBoolean(boolean val)
 */
static void Dalvik_dalvik_system_Taint_getTaintBoolean(const u4* args,
    JValue* pResult)
{
    // args[0] = the value
    // args[1] = the return taint
    u4 tag = args[2]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getTaintChar(char val)
 */
static void Dalvik_dalvik_system_Taint_getTaintChar(const u4* args,
    JValue* pResult)
{
    // args[0] = the value
    // args[1] = the return taint
    u4 tag = args[2]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getTaintByte(byte val)
 */
static void Dalvik_dalvik_system_Taint_getTaintByte(const u4* args,
    JValue* pResult)
{
    // args[0] = the value
    // args[1] = the return taint
    u4 tag = args[2]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getTaintInt(int val)
 */
static void Dalvik_dalvik_system_Taint_getTaintInt(const u4* args,
    JValue* pResult)
{
    // args[0] = the value
    // args[1] = the return taint
    u4 tag = args[2]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getTaintShort(int val)
 */
static void Dalvik_dalvik_system_Taint_getTaintShort(const u4* args,
    JValue* pResult)
{
    // args[0] = the value
    // args[1] = the return taint
    u4 tag = args[2]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getTaintLong(long val)
 */
static void Dalvik_dalvik_system_Taint_getTaintLong(const u4* args,
    JValue* pResult)
{
    // args[0:1] = the value
    // args[2] = the return taint
    u4 tag = args[3]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getTaintFloat(float val)
 */
static void Dalvik_dalvik_system_Taint_getTaintFloat(const u4* args,
    JValue* pResult)
{
    // args[0] = the value
    // args[1] = the return taint
    u4 tag = args[2]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getTaintDouble(long val)
 */
static void Dalvik_dalvik_system_Taint_getTaintDouble(const u4* args,
    JValue* pResult)
{
    // args[0:1] = the value
    // args[2] = the return taint
    u4 tag = args[3]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getTaintRef(Object obj)
 */
static void Dalvik_dalvik_system_Taint_getTaintRef(const u4* args,
    JValue* pResult)
{
    // args[0] = the value
    // args[1] = the return taint
    u4 tag = args[2]; /* the existing taint */
    RETURN_INT(tag);
}

static u4 getTaintXattr(int fd)
{
    int ret;
    u4 buf;
    u4 tag = TAINT_CLEAR;

    ret = fgetxattr(fd, TAINT_XATTR_NAME, &buf, sizeof(buf));
    if (ret > 0) {
    tag = buf;
    } else {
    if (errno == ENOATTR) {
        /* do nothing */
    } else if (errno == ERANGE) {
        ALOGW("TaintLog: fgetxattr(%d) contents to large", fd);
    } else if (errno == ENOTSUP) {
        /* XATTRs are not supported. No need to spam the logs */
    } else if (errno == EPERM) {
        /* Strange interaction with /dev/log/main. Suppress the log */
    } else {
        ALOGW("TaintLog: fgetxattr(%d): unknown error code %d", fd, errno);
    }
    }

    return tag;
}

static void setTaintXattr(int fd, u4 tag)
{
    int ret;

    ret = fsetxattr(fd, TAINT_XATTR_NAME, &tag, sizeof(tag), 0);

    if (ret < 0) {
    if (errno == ENOSPC || errno == EDQUOT) {
        ALOGW("TaintLog: fsetxattr(%d): not enough room to set xattr", fd);
    } else if (errno == ENOTSUP) {
        /* XATTRs are not supported. No need to spam the logs */
    } else if (errno == EPERM) {
        /* Strange interaction with /dev/log/main. Suppress the log */
    } else {
        ALOGW("TaintLog: fsetxattr(%d): unknown error code %d", fd, errno);
    }
    }

}

/*
 * public static int getTaintFile(int fd)
 */
static void Dalvik_dalvik_system_Taint_getTaintFile(const u4* args,
    JValue* pResult)
{
    u4 tag;
    int fd = (int)args[0]; // args[0] = the file descriptor
    // args[1] = the return taint
    // args[2] = fd taint

    tag = getTaintXattr(fd);

    if (tag) {
    ALOGI("TaintLog: getTaintFile(%d) = 0x%08x", fd, tag);
    }

    RETURN_INT(tag);
}

/*
 * public static int addTaintFile(int fd, u4 tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintFile(const u4* args,
    JValue* pResult)
{
    u4 otag;
    int fd = (int)args[0]; // args[0] = the file descriptor
    u4 tag = args[1];      // args[1] = the taint tag
    // args[2] = the return taint
    // args[3] = fd taint
    // args[4] = tag taint

    otag = getTaintXattr(fd);

    if (tag) {
    ALOGI("TaintLog: addTaintFile(%d): adding 0x%08x to 0x%08x = 0x%08x",
        fd, tag, otag, tag | otag);
    }

    setTaintXattr(fd, tag | otag);

    RETURN_VOID();
}


/*
 * public static void log(String msg)
 */
static void Dalvik_dalvik_system_Taint_log(const u4* args,
    JValue* pResult)
{
    StringObject* msgObj = (StringObject*) args[0];
    char *msg;

    if (msgObj == NULL) {
    dvmThrowNullPointerException("msgObj == NULL");
    RETURN_VOID();
    }

    msg = dvmCreateCstrFromString(msgObj);
    ALOG(LOG_WARN, "TaintLog", "%s", msg);
    char *curmsg = msg;
    while(strlen(curmsg) > 1013)
    {
        curmsg = curmsg+1013;
        ALOG(LOG_WARN, "TaintLog", "%s", curmsg);
    }
    free(msg);

    RETURN_VOID();
}

/*
 * public static void log(String msg)
 */
static void Dalvik_dalvik_system_TMeasure_log(const u4* args,
    JValue* pResult)
{
    StringObject* msgObj = (StringObject*) args[0];
    char *msg;

    if (msgObj == NULL) {
        dvmThrowNullPointerException("msgObj == NULL");
        RETURN_VOID();
    }

    msg = dvmCreateCstrFromString(msgObj);
    ALOG(LOG_WARN, "TMLog", "%s", msg);
    char *curmsg = msg;
    while(strlen(curmsg) > 1013)
    {
        curmsg = curmsg+1013;
        ALOG(LOG_WARN, "TMLog", "%s", curmsg);
    }
    free(msg);

    RETURN_VOID();
}


/*
 * public static void logPathFromFd(int fd)
 */
static void Dalvik_dalvik_system_Taint_logPathFromFd(const u4* args,
    JValue* pResult)
{
    int fd = (int) args[0];
    pid_t pid;
    char ppath[20]; // these path lengths should be enough
    char rpath[80];
    int err;


    pid = getpid();
    snprintf(ppath, 20, "/proc/%d/fd/%d", pid, fd);
    err = readlink(ppath, rpath, 80);
    if (err >= 0) {
    ALOGW("TaintLog: fd %d -> %s", fd, rpath);
    } else {
    ALOGW("TaintLog: error finding path for fd %d", fd);
    }

    RETURN_VOID();
}

/*
 * public static void logPeerFromFd(int fd)
 */
static void Dalvik_dalvik_system_Taint_logPeerFromFd(const u4* args,
    JValue* pResult)
{
    int fd = (int) args[0];

    ALOGW("TaintLog: logPeerFromFd not yet implemented");

    RETURN_VOID();
}

/*
 *
 */
static void Dalvik_dalvik_system_Taint_incTmCounter(const u4*,  JValue* pResult) {
  RETURN_INT(tm_counter++);
}

/*
 *
 */
static void Dalvik_dalvik_system_Taint_getProgName(const u4*,  JValue* pResult) {
  StringObject* progname = dvmCreateStringFromCstr(__progname);
  RETURN_PTR(progname);
}

/*
 *
 */
static void Dalvik_dalvik_system_Taint_getThreadId(const u4*,  JValue* pResult) {
  //RETURN_INT(self->threadId);
  RETURN_INT(dvmThreadSelf()->threadId);
}

/*
 *
 */
static void Dalvik_dalvik_system_Taint_isTMeasureAPP(const u4*,  JValue* pResult) {
  u4 val = (u4) isTMeasureAPPFlag;
  RETURN_BOOLEAN(val);
}

const DalvikNativeMethod dvm_dalvik_system_Taint[] = {
    { "addTaintString",  "(Ljava/lang/String;I)V",
        Dalvik_dalvik_system_Taint_addTaintString},
    { "setTaintString",  "(Ljava/lang/String;I)V",
        Dalvik_dalvik_system_Taint_setTaintString},
    { "addTaintObjectArray",  "([Ljava/lang/Object;I)V",
        Dalvik_dalvik_system_Taint_addTaintObjectArray},
    { "setTaintObjectArray",  "([Ljava/lang/Object;I)V",
        Dalvik_dalvik_system_Taint_setTaintObjectArray},
    { "addTaintBooleanArray",  "([ZI)V",
        Dalvik_dalvik_system_Taint_addTaintBooleanArray},
    { "setTaintBooleanArray",  "([ZI)V",
        Dalvik_dalvik_system_Taint_setTaintBooleanArray},
    { "addTaintCharArray",  "([CI)V",
        Dalvik_dalvik_system_Taint_addTaintCharArray},
    { "setTaintCharArray",  "([CI)V",
        Dalvik_dalvik_system_Taint_setTaintCharArray},
    { "addTaintByteArray",  "([BI)V",
        Dalvik_dalvik_system_Taint_addTaintByteArray},
    { "setTaintByteArray",  "([BI)V",
        Dalvik_dalvik_system_Taint_setTaintByteArray},
    { "addTaintIntArray",  "([II)V",
        Dalvik_dalvik_system_Taint_addTaintIntArray},
    { "setTaintIntArray",  "([II)V",
        Dalvik_dalvik_system_Taint_setTaintIntArray},
    { "addTaintShortArray",  "([SI)V",
        Dalvik_dalvik_system_Taint_addTaintShortArray},
    { "setTaintShortArray",  "([SI)V",
        Dalvik_dalvik_system_Taint_setTaintShortArray},
    { "addTaintLongArray",  "([JI)V",
        Dalvik_dalvik_system_Taint_addTaintLongArray},
    { "setTaintLongArray",  "([JI)V",
        Dalvik_dalvik_system_Taint_setTaintLongArray},
    { "addTaintFloatArray",  "([FI)V",
        Dalvik_dalvik_system_Taint_addTaintFloatArray},
    { "setTaintFloatArray",  "([FI)V",
        Dalvik_dalvik_system_Taint_setTaintFloatArray},
    { "addTaintDoubleArray",  "([DI)V",
        Dalvik_dalvik_system_Taint_addTaintDoubleArray},
    { "setTaintDoubleArray",  "([DI)V",
        Dalvik_dalvik_system_Taint_setTaintDoubleArray},
    { "addTaintBoolean",  "(ZI)Z",
        Dalvik_dalvik_system_Taint_addTaintBoolean},
    { "setTaintBoolean",  "(ZI)Z",
        Dalvik_dalvik_system_Taint_setTaintBoolean},
    { "addTaintChar",  "(CI)C",
        Dalvik_dalvik_system_Taint_addTaintChar},
    { "setTaintChar",  "(CI)C",
        Dalvik_dalvik_system_Taint_setTaintChar},
    { "addTaintByte",  "(BI)B",
        Dalvik_dalvik_system_Taint_addTaintByte},
    { "setTaintByte",  "(BI)B",
        Dalvik_dalvik_system_Taint_setTaintByte},
    { "addTaintInt",  "(II)I",
        Dalvik_dalvik_system_Taint_addTaintInt},
    { "setTaintInt",  "(II)I",
        Dalvik_dalvik_system_Taint_setTaintInt},
    { "addTaintShort",  "(SI)S",
        Dalvik_dalvik_system_Taint_addTaintShort},
    { "setTaintShort",  "(SI)S",
        Dalvik_dalvik_system_Taint_setTaintShort},
    { "addTaintLong",  "(JI)J",
        Dalvik_dalvik_system_Taint_addTaintLong},
    { "setTaintLong",  "(JI)J",
        Dalvik_dalvik_system_Taint_setTaintLong},
    { "addTaintFloat",  "(FI)F",
        Dalvik_dalvik_system_Taint_addTaintFloat},
    { "setTaintFloat",  "(FI)F",
        Dalvik_dalvik_system_Taint_setTaintFloat},
    { "addTaintDouble",  "(DI)D",
        Dalvik_dalvik_system_Taint_addTaintDouble},
    { "setTaintDouble",  "(DI)D",
        Dalvik_dalvik_system_Taint_setTaintDouble},
    { "getTaintString",  "(Ljava/lang/String;)I",
        Dalvik_dalvik_system_Taint_getTaintString},
    { "getTaintObjectArray",  "([Ljava/lang/Object;)I",
        Dalvik_dalvik_system_Taint_getTaintObjectArray},
    { "getTaintBooleanArray",  "([Z)I",
        Dalvik_dalvik_system_Taint_getTaintBooleanArray},
    { "getTaintCharArray",  "([C)I",
        Dalvik_dalvik_system_Taint_getTaintCharArray},
    { "getTaintByteArray",  "([B)I",
        Dalvik_dalvik_system_Taint_getTaintByteArray},
    { "getTaintIntArray",  "([I)I",
        Dalvik_dalvik_system_Taint_getTaintIntArray},
    { "getTaintShortArray",  "([S)I",
        Dalvik_dalvik_system_Taint_getTaintShortArray},
    { "getTaintLongArray",  "([J)I",
        Dalvik_dalvik_system_Taint_getTaintLongArray},
    { "getTaintFloatArray",  "([F)I",
        Dalvik_dalvik_system_Taint_getTaintFloatArray},
    { "getTaintDoubleArray",  "([D)I",
        Dalvik_dalvik_system_Taint_getTaintDoubleArray},
    { "getTaintBoolean",  "(Z)I",
        Dalvik_dalvik_system_Taint_getTaintBoolean},
    { "getTaintChar",  "(C)I",
        Dalvik_dalvik_system_Taint_getTaintChar},
    { "getTaintByte",  "(B)I",
        Dalvik_dalvik_system_Taint_getTaintByte},
    { "getTaintInt",  "(I)I",
        Dalvik_dalvik_system_Taint_getTaintInt},
    { "getTaintShort",  "(S)I",
        Dalvik_dalvik_system_Taint_getTaintShort},
    { "getTaintLong",  "(J)I",
        Dalvik_dalvik_system_Taint_getTaintLong},
    { "getTaintFloat",  "(F)I",
        Dalvik_dalvik_system_Taint_getTaintFloat},
    { "getTaintDouble",  "(D)I",
        Dalvik_dalvik_system_Taint_getTaintDouble},
    { "getTaintRef",  "(Ljava/lang/Object;)I",
        Dalvik_dalvik_system_Taint_getTaintRef},
    { "getTaintFile",  "(I)I",
        Dalvik_dalvik_system_Taint_getTaintFile},
    { "addTaintFile",  "(II)V",
        Dalvik_dalvik_system_Taint_addTaintFile},
    { "log",  "(Ljava/lang/String;)V",
        Dalvik_dalvik_system_Taint_log},
    { "TMLog",  "(Ljava/lang/String;)V",
        Dalvik_dalvik_system_TMeasure_log},
    { "logPathFromFd",  "(I)V",
        Dalvik_dalvik_system_Taint_logPathFromFd},
    { "logPeerFromFd",  "(I)V",
        Dalvik_dalvik_system_Taint_logPeerFromFd},
    { "incTmCounter",  "()I",
        Dalvik_dalvik_system_Taint_incTmCounter},
    { "getProgName", "()Ljava/lang/String;",
        Dalvik_dalvik_system_Taint_getProgName},
    {"isTMeasureAPP", "()Z",
     Dalvik_dalvik_system_Taint_isTMeasureAPP},
    {"getNativeThreadId", "()I",
     Dalvik_dalvik_system_Taint_getThreadId},
    { NULL, NULL, NULL },
};
