#include <stdio.h>

#include "cpa.h"
#include "cpa_cy_sym.h"

#define MAX_INSTANCES 32
#define BYTE_ALIGNMENT 64
#define MAX_TEST_DATA 16

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_RESET "\x1b[0m"

#ifndef PRINT
#define PRINT(msg, arg...) \
    printf(msg, ##arg)
#endif

#ifndef PRINT_COLOR
#define PRINT_COLOR(color, msg, arg...) \
    printf(color msg ANSI_COLOR_RESET, ##arg)
#endif

#ifndef PRINT_ERR
#define PRINT_ERR(msg, arg...) \
    PRINT_COLOR(ANSI_COLOR_RED, "%s:%d %s() " msg, __FILE__, __LINE__, __func__, ##arg)
#endif

#ifndef PRINT_ERR_STATUS
#define PRINT_ERR_STATUS(func, stat) \
    PRINT_COLOR(ANSI_COLOR_RED, "%s() failed with status %d\n", func, stat)
#endif

#ifndef PRINT_DBG
#define PRINT_DBG(msg, arg...) \
    PRINT("%s:%d %s() " msg, __FILE__, __LINE__, __func__, ##arg)
#endif

#define PRINT_CAPABILITY(cap, sup)     \
    if (CPA_TRUE == sup)               \
        printf(cap ": Supported\n");   \
    else                               \
        printf(cap ": Unsupported\n"); \

#define CHECK_ERR_STATUS(func, stat)  \
    if (CPA_STATUS_SUCCESS != stat)   \
        PRINT_ERR_STATUS(func, stat);

typedef struct _TestData {
    CpaCySymOp op;
    CpaCySymCipherAlgorithm cipherAlgo;
    CpaCySymHashAlgorithm hashAlgo;
    CpaCySymHashMode hashMode;
    Cpa8U *key;
    Cpa32U count;
    Cpa8U bearer;
    Cpa32U fresh;
    Cpa8U dir; /* 0 (uplink) for decrypt, 1 (downlink) for encrypt */
    Cpa32U bitLen;
    Cpa8U *iv;
    Cpa8U *in;
    Cpa8U *out; /* digest for hash */
    Cpa32U keySize;
    Cpa32U ivSize;
    Cpa32U inSize;
    Cpa32U outSize;
} TestData;

int gDebugParam;

CpaStatus execQat(TestData cipherTestData);

CpaStatus checkCyInstanceCapabilities(void);

CpaStatus createBuffers(CpaInstanceHandle cyInstHandle,
                        Cpa32U numBuffers,
                        Cpa32U bufferSize,
                        CpaBufferList **srcBufferList,
                        CpaBufferList **dstBufferList,
                        CpaBoolean inPlaceOp);
void freeBuffers(Cpa32U numBuffers,
                 CpaBufferList **srcBufferList,
                 CpaBufferList **dstBufferList,
                 CpaBoolean inPlaceOp);

void freeInstanceMapping(void);

/*
 ********************
 * Wrapper functions
 ********************
 */
CpaStatus memAllocContig(void **memAddr, Cpa32U sizeBytes, Cpa32U alignment);
CpaStatus memAllocOs(void **memAddr, Cpa32U sizeBytes);

void memFreeContig(void **memAddr);
void memFreeOs(void **memAddr);

/*
 *********************
 * Test set functions
 *********************
 */
CpaStatus genNea1TestData(int testSetId, TestData *ret);
CpaStatus genNea2TestData(int testSetId, TestData *ret);
CpaStatus genNea3TestData(int testSetId, TestData *ret);
CpaStatus genNia1TestData(int testSetId, TestData *ret);
CpaStatus genNia2TestData(int testSetId, TestData *ret);
CpaStatus genNia3TestData(int testSetId, TestData *ret);
CpaStatus genSampleTestData(TestData *ret);

CpaCySymCipherDirection getCipherDirection(TestData testData);

void freeTestData(TestData *testData);

void genIv(TestData *testData);
