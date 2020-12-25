#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_sym.h"
#include "cpa_sample_utils.h"
#include "icp_sal_poll.h"
#include "icp_sal_user.h"
#include "qae_mem.h"

#include "test_data.h"

#define MAX_INSTANCES 32

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
        PRINT_ERR_STATUS(func, stat); \

extern CpaStatus qaeMemInit(void);
extern void qaeMemDestroy(void);

CpaStatus checkCyInstanceCapabilities(void);

void freeInstanceMapping(void);

CpaStatus memAllocContig(void **memAddr, Cpa32U sizeBytes, Cpa32U alignment);
CpaStatus memAllocOs(void **memAddr, Cpa32U sizeBytes);
void memFreeContig(void **memAddr);
void memFreeOs(void **memAddr);

Cpa32U alignment = 64;
CpaInstanceHandle *inst_g = NULL;

static void symCallback(void *callBackTag,
                        CpaStatus status,
                        const CpaCySymOp operationType,
                        void *opData,
                        CpaBufferList *dstBuffer,
                        CpaBoolean verifyResult)
{
    PRINT_DBG("Callback called with status = %d.\n", status); 
}

int main(int argc, const char **argv) {
    CpaStatus stat = CPA_STATUS_SUCCESS;
    char *processName = NULL;
    Cpa16U numInstances = 0;
    CpaInstanceHandle cyInstHandles[MAX_INSTANCES];
    CpaInstanceHandle cyInstHandle = NULL;
    CpaCySymSessionSetupData sessionSetupData = {0};
    TestData cipherTestData = {0};
    Cpa32U sessionCtxSize = 0;
    CpaCySymSessionCtx sessionCtx = NULL;
    Cpa32U numBuffers = 1;
    Cpa32U bufferMetaSize = 0;
    Cpa8U *srcBufferMeta = NULL;
    Cpa8U *dstBufferMeta = NULL;
    CpaBufferList *srcBufferList = NULL;
    CpaBufferList *dstBufferList = NULL;
    /*
     * Allocate memory for bufferlist and array of flat buffers in a contiguous
     * area and carve it up to reduce number of memory allocations required.
     */
    Cpa32U bufferListMemSize = sizeof(CpaBufferList) + (numBuffers * sizeof(CpaFlatBuffer));
    Cpa8U *srcBuffer = NULL;
    Cpa8U *dstBuffer = NULL;
    Cpa8U *ivBuffer = NULL;
    CpaFlatBuffer *flatBuffer = NULL;
    CpaCySymOpData *opData = NULL;
    Cpa32U byteLen = 0;
    CpaBoolean sessionInUse = CPA_FALSE;
    CpaCySymStats64 symStats = {0};

    /*
     * Initialize memory driver usdm_drv for user space
     */
    PRINT_DBG("qaeMemInit()\n");
    stat = qaeMemInit();
    if (CPA_STATUS_SUCCESS != stat)
    {
        PRINT_ERR("Failed to initialise memory driver\n");
        return (int)stat;
    }

    /*
     * Initialize user space access to a QAT endpoint
     */
    processName = "PDCP";
    PRINT_DBG("icp_sal_userStart()\n");
    stat = icp_sal_userStart(processName);
    // stat = icp_sal_userStartMultiProcess(processName, CPA_FALSE);
    if (CPA_STATUS_SUCCESS != stat)
    {
        PRINT_ERR("Failed to start user process 'PDCP'\n");
        qaeMemDestroy();
        return (int)stat;
    }

    /*
     * Discover cryptographic service instance and check capabilities
     */
    PRINT_DBG("cpaCyGetNumInstances()\n");
    stat = cpaCyGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != stat)
    {
        PRINT_ERR_STATUS("cpaCyGetNumInstances", stat);
    }
    else if (0 == numInstances)
    {
        PRINT_ERR("No instances found for 'PDCP'\n");
        PRINT_ERR("Please check your section names");
        PRINT_ERR(" in the config file\n");
        PRINT_ERR("Also make sure to use config file version 2\n");
        stat = CPA_STATUS_FAIL;
    }
    else
    {
        PRINT("%d instances found for 'PDCP'\n", numInstances); 
        stat = checkCyInstanceCapabilities();
        CHECK_ERR_STATUS("checkCyInstanceCapabilities", stat);
    }

    if (CPA_STATUS_SUCCESS == stat && 0 < numInstances)
    {
        // inst_g = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
        // stat = cpaCyGetInstance(numInstances, inst_g)
        PRINT_DBG("cpaCyGetInstances()\n");
        stat = cpaCyGetInstances(numInstances, cyInstHandles);
        CHECK_ERR_STATUS("cpaCyGetInstances", stat);
    }

    /*
     * Start up the cryptographic service instance
     */
    if (CPA_STATUS_SUCCESS == stat)
    {
        /* Fetch the first instance */
        cyInstHandle = cyInstHandles[0];
        PRINT_DBG("cpaCyStartInstance()\n");
        stat = cpaCyStartInstance(cyInstHandle);
        CHECK_ERR_STATUS("cpaCyStartInstance", stat);
    }

    /*
     * Set address translation function
     */
    if (CPA_STATUS_SUCCESS == stat)
    {
        PRINT_DBG("cpaCySetAddressTranslation()\n");
        stat = cpaCySetAddressTranslation(cyInstHandle, (CpaVirtualToPhysical)qaeVirtToPhysNUMA);
        CHECK_ERR_STATUS("cpaCySetAddressTranslation", stat);
    }

    sampleCyStartPolling(cyInstHandle);

    /*
     * Create and initialize a session
     */
    if (CPA_STATUS_SUCCESS == stat)
    {
        cipherTestData = genNea1TestData1();
        // cipherTestData = genSampleTestData();

        sessionSetupData.sessionPriority = CPA_CY_PRIORITY_NORMAL;
        sessionSetupData.symOperation = CPA_CY_SYM_OP_CIPHER;
        sessionSetupData.cipherSetupData.cipherAlgorithm = cipherTestData.algo;
        sessionSetupData.cipherSetupData.pCipherKey = cipherTestData.key;
        sessionSetupData.cipherSetupData.cipherKeyLenInBytes = cipherTestData.keySize;
        sessionSetupData.cipherSetupData.cipherDirection = getCipherDirection(cipherTestData);

        PRINT_DBG("Key: ");
        for (int i = 0; i < sessionSetupData.cipherSetupData.cipherKeyLenInBytes; i++)
        {
            PRINT("%02x ", sessionSetupData.cipherSetupData.pCipherKey[i]);
        }
        PRINT("\n");

        PRINT_DBG("cpaCySymSessionCtxGetSize()\n");
        stat = cpaCySymSessionCtxGetSize(cyInstHandle, &sessionSetupData, &sessionCtxSize);
        CHECK_ERR_STATUS("cpaCySymSessionCtxGetSize", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = memAllocContig((void *)&sessionCtx, sessionCtxSize, alignment);
        CHECK_ERR_STATUS("memAllocContig", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        PRINT_DBG("cpaCySymInitSession()\n");
        stat = cpaCySymInitSession(cyInstHandle, symCallback, &sessionSetupData, sessionCtx);
        // stat = cpaCySymInitSession(cyInstHandle, NULL, &sessionSetupData, sessionCtx);
        CHECK_ERR_STATUS("cpaCySymInitSession", stat);
    }

    /*
     * Invoke symmetric operations (cipher and/or hash) on the session
     */
    if (CPA_STATUS_SUCCESS == stat)
    {
        PRINT_DBG("cpaCyBufferListGetMetaSize()\n");
        stat = cpaCyBufferListGetMetaSize(cyInstHandle, numBuffers, &bufferMetaSize);
        CHECK_ERR_STATUS("cpaCyBufferListGetMetaSize", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = memAllocContig((void *)&srcBufferMeta, bufferMetaSize, alignment);
        CHECK_ERR_STATUS("memAllocContig", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = memAllocContig((void *)&dstBufferMeta, bufferMetaSize, alignment);
        CHECK_ERR_STATUS("memAllocContig", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = memAllocOs((void *)&srcBufferList, bufferListMemSize);
        CHECK_ERR_STATUS("memAllocOs", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = memAllocOs((void *)&dstBufferList, bufferListMemSize);
        CHECK_ERR_STATUS("memAllocOs", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = memAllocContig((void *)&srcBuffer, cipherTestData.inSize, alignment);
        CHECK_ERR_STATUS("memAllocContig", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = memAllocContig((void *)&dstBuffer, cipherTestData.inSize, alignment);
        CHECK_ERR_STATUS("memAllocContig", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = memAllocContig((void *)&ivBuffer, cipherTestData.ivSize, alignment);
        CHECK_ERR_STATUS("memAllocContig", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        memcpy(srcBuffer, cipherTestData.in, cipherTestData.inSize);
        memcpy(ivBuffer, cipherTestData.iv, cipherTestData.ivSize);

        flatBuffer = (CpaFlatBuffer *)(srcBufferList + 1);

        srcBufferList->pBuffers = flatBuffer;
        srcBufferList->numBuffers = numBuffers;
        srcBufferList->pPrivateMetaData = srcBufferMeta;

        flatBuffer->dataLenInBytes = cipherTestData.inSize;
        flatBuffer->pData = srcBuffer;

        flatBuffer = (CpaFlatBuffer *)(dstBufferList + 1);

        dstBufferList->pBuffers = flatBuffer;
        dstBufferList->numBuffers = numBuffers;
        dstBufferList->pPrivateMetaData = dstBufferMeta;


        flatBuffer->dataLenInBytes = cipherTestData.outSize;
        flatBuffer->pData = dstBuffer;

        stat = memAllocOs((void *)&opData, sizeof(CpaCySymOpData));
        CHECK_ERR_STATUS("memAllocOs", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        opData->sessionCtx = sessionCtx;
        opData->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
        opData->pIv = ivBuffer;
        opData->ivLenInBytes = cipherTestData.ivSize;
        opData->cryptoStartSrcOffsetInBytes = 0;
        opData->messageLenToCipherInBytes = cipherTestData.inSize;

        PRINT_DBG("IV: ");
        for (int i = 0; i < opData->ivLenInBytes; i++)
        {
            PRINT("%02x ", opData->pIv[i]);
        }
        PRINT("\n");

        PRINT_DBG("cpaCySymPerformOp()\n");
        stat = cpaCySymPerformOp(cyInstHandle, NULL, opData, srcBufferList, dstBufferList, NULL);
        CHECK_ERR_STATUS("cpaCySymPerformOp", stat);
    }

    sleep(1);

    /*
     * Verify the result
     */
    if (CPA_STATUS_SUCCESS == stat)
    {
        byteLen = cipherTestData.bitLen / 8;
        for (int i = byteLen + 1; i < cipherTestData.outSize; i++)
        {
            dstBuffer[i] = 0x0;
        }
        if ((cipherTestData.bitLen & 0x7) != 0)
        {
            dstBuffer[byteLen] = dstBuffer[byteLen] & (0xff << (8 - (cipherTestData.bitLen % 8)));
        }
        if (0 == memcmp(dstBuffer, cipherTestData.out, cipherTestData.outSize))
        {
            PRINT_COLOR(ANSI_COLOR_GREEN, "Output matches expected output!\n");
        }
        else
        {
            PRINT_COLOR(ANSI_COLOR_RED, "Output does not match expected output\n");
            for (int i = 0; i < cipherTestData.outSize; i++)
            {
                if (0 == memcmp(dstBuffer + i, cipherTestData.out + i, 1))
                {
                    PRINT("%02x ", dstBuffer[i]);
                }
                else
                {
                    PRINT_COLOR(ANSI_COLOR_RED, "%02x ", dstBuffer[i]);
                }
                if (i % 8 == 7)
                {
                    PRINT("\n");
                }
            }
            PRINT("\n");
            stat = CPA_STATUS_FAIL;
        }
    }

    /*
     * Tear down the session
     */
    if (NULL != sessionCtx)
    {
        PRINT_DBG("Wait for the completion of outstanding request\n");
        do
        {
            cpaCySymSessionInUse(sessionCtx, &sessionInUse);
        } while (sessionInUse);
        PRINT_DBG("cpaCySymRemoveSession()\n");
        cpaCySymRemoveSession(cyInstHandle, sessionCtx);
    }

    /*
     * Query the statistics on the instance
     */
    stat = cpaCySymQueryStats64(cyInstHandle, &symStats);
    CHECK_ERR_STATUS("cpaCySymQueryStats64", stat);
    if (CPA_STATUS_SUCCESS == stat)
    {
        PRINT("Number of symmetric operation completed: %llu\n",
            (unsigned long long)symStats.numSymOpCompleted);
    }

    sampleCyStopPolling();

    /*
     * Stop the cryptographic service instance
     */
    if (NULL != cyInstHandle)
    {
        PRINT_DBG("cpaCyStopInstance()\n");
        cpaCyStopInstance(cyInstHandle);
    }

    memFreeOs((void *)&opData);
    memFreeContig((void *)&ivBuffer);
    memFreeContig((void *)&srcBuffer);
    memFreeOs((void *)&srcBufferList);
    memFreeContig((void *)&dstBuffer);
    memFreeOs((void *)&dstBufferList);
    memFreeContig((void *)&srcBufferMeta);
    memFreeContig((void *)&dstBufferMeta);

    memFreeContig((void *)&sessionCtx);
    freeTestData(&cipherTestData);

    /*
     * Close user space access to the QAT endpoint and memory driver
     */
    PRINT_DBG("icp_sal_userStop()\n");
    icp_sal_userStop();
    qaeMemDestroy();

    return (int)stat;
}

CpaStatus checkCyInstanceCapabilities(void)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;
    CpaCyCapabilitiesInfo cap = {0};

    status = cpaCyGetInstances(1, &instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR_STATUS("cpaCyGetInstances", status);
        return status;
    }

    status = cpaCyQueryCapabilities(instanceHandle, &cap);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR_STATUS("cpaCyQueryCapabilities", status);
        return status;
    }

    PRINT("=== Cryptography Instance Capabilities Check ===\n");
    PRINT_CAPABILITY(" Symmetric      ", cap.symSupported);
    PRINT_CAPABILITY(" Symmetric DP   ", cap.symSupported);
    PRINT_CAPABILITY(" Diffie Hellman ", cap.dhSupported);
    PRINT_CAPABILITY(" DSA            ", cap.dsaSupported);
    PRINT_CAPABILITY(" RSA            ", cap.rsaSupported);
    PRINT("================================================\n");

    return CPA_STATUS_SUCCESS;
}

void freeInstanceMapping(void)
{
    if (NULL != inst_g)
    {
        qaeMemFree((void **)&inst_g);
    }
}

CpaStatus memAllocContig(void **memAddr, Cpa32U sizeBytes, Cpa32U alignment)
{
    *memAddr = qaeMemAllocNUMA(sizeBytes, 0, alignment);
    if (NULL == *memAddr)
    {
        return CPA_STATUS_RESOURCE;
    }
    return CPA_STATUS_SUCCESS;
}

CpaStatus memAllocOs(void **memAddr, Cpa32U sizeBytes)
{
    *memAddr = malloc(sizeBytes);
    if (NULL == *memAddr)
    {
        return CPA_STATUS_RESOURCE;
    }
    return CPA_STATUS_SUCCESS;
}

void memFreeContig(void **memAddr)
{
    if (NULL != *memAddr)
    {
        qaeMemFreeNUMA(memAddr);
        *memAddr = NULL;
    }
}

void memFreeOs(void **memAddr)
{
    if (NULL != *memAddr)
    {
        free(*memAddr);
        *memAddr = NULL;
    }
}
