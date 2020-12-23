#include <stdio.h>
#include <string.h>

#include "test_data.h"

#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_sym.h"
#include "icp_sal_poll.h"
#include "icp_sal_user.h"
#include "qae_mem.h"

#define MAX_INSTANCES 32

#ifndef PRINT
#define PRINT(msg, arg...) \
    printf(msg, ##arg)
#endif

#ifndef PRINT_ERR
#define PRINT_ERR(msg, arg...) \
    printf("%s:%d %s() " msg, __FILE__, __LINE__, __func__, ##arg)
#endif

#ifndef PRINT_ERR_STATUS
#define PRINT_ERR_STATUS(func, stat) \
    PRINT_ERR("%s failed with status %d\n", func, stat)
#endif

#ifndef PRINT_DBG
#define PRINT_DBG(msg, arg...) PRINT_ERR(msg, ##arg)
#endif

#define PRINT_CAPABILITY(cap, sup)     \
    if (CPA_TRUE == sup)               \
    {                                  \
        printf(cap ": Supported\n");   \
    }                                  \
    else                               \
    {                                  \
        printf(cap ": Unsupported\n"); \
    }

#define CHECK_ERR_STATUS(func, stat)  \
    if (CPA_STATUS_SUCCESS != stat)   \
    {                                 \
        PRINT_ERR_STATUS(func, stat); \
    }

extern CpaStatus qaeMemInit(void);
extern void qaeMemDestroy(void);

CpaStatus checkCyInstanceCapabilities(void);

void freeInstanceMapping(void);

CpaStatus memAllocContig(void **memAddr, Cpa32U sizeBytes, Cpa32U alignment);
CpaStatus memAllocOs(void **memAddr, Cpa32U sizeBytes);

CpaInstanceHandle *inst_g = NULL;

int main(int argc, const char **argv) {
    CpaStatus stat = CPA_STATUS_SUCCESS;
    char *processName = NULL;
    Cpa16U numInstances = 0;
    CpaInstanceHandle cyInstHandles[MAX_INSTANCES];
    CpaInstanceHandle cyInstHandle = NULL;
    CpaCySymSessionSetupData sessionSetupData = {0};
    TestData nea1testData = {0};
    Cpa32U sessionCtxSize = 0;
    CpaCySymSessionCtx sessionCtx = NULL;
    Cpa32U numBuffers = 1;
    Cpa32U bufferMetaSize = 0;
    Cpa8U *bufferMeta = NULL;
    CpaBufferList *bufferList = NULL;
    /*
     * Allocate memory for bufferlist and array of flat buffers in a contiguous
     * area and carve it up to reduce number of memory allocations required.
     */
    Cpa32U bufferListMemSize = sizeof(CpaBufferList) + (numBuffers * sizeof(CpaFlatBuffer));
    Cpa8U *srcBuffer = NULL;
    Cpa8U *ivBuffer = NULL;
    CpaFlatBuffer *flatBuffer = NULL;
    CpaCySymOpData *opData = NULL;

    /*
     * Initialize memory driver usdm_drv for user space
     */
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
    stat = icp_sal_userStart(processName);
    if (CPA_STATUS_SUCCESS != stat)
    {
        PRINT_ERR("Failed to start user process 'PDCP'\n");
        qaeMemDestroy();
        return (int)stat;
    }

    /*
     * Discover cryptographic service instance and check capabilities
     */
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
        stat = cpaCyStartInstance(cyInstHandle);
        CHECK_ERR_STATUS("cpaCyStartInstance", stat);
    }

    /*
     * Set address translation function
     */
    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = cpaCySetAddressTranslation(cyInstHandle, (CpaVirtualToPhysical)qaeVirtToPhysNUMA);
        CHECK_ERR_STATUS("cpaCySetAddressTranslation", stat);
    }

    /*
     * Create and initialize a session
     */
    if (CPA_STATUS_SUCCESS == stat)
    {
        nea1testData = genNea1TestData();

        sessionSetupData.sessionPriority = CPA_CY_PRIORITY_NORMAL;
        sessionSetupData.symOperation = CPA_CY_SYM_OP_CIPHER;
        sessionSetupData.cipherSetupData.cipherAlgorithm = CPA_CY_SYM_CIPHER_SNOW3G_UEA2;
        sessionSetupData.cipherSetupData.pCipherKey = nea1testData.key;
        sessionSetupData.cipherSetupData.cipherKeyLenInBytes = nea1testData.keySize;
        sessionSetupData.cipherSetupData.cipherDirection = getCipherDirection(nea1testData);

        stat = cpaCySymSessionCtxGetSize(cyInstHandle, &sessionSetupData, &sessionCtxSize);
        CHECK_ERR_STATUS("cpaCySymSessionCtxGetSize", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = memAllocContig((void *)&sessionCtx, sessionCtxSize, 64);
        CHECK_ERR_STATUS("memAllocContig", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = cpaCySymInitSession(cyInstHandle, NULL, &sessionSetupData, sessionCtx);
        CHECK_ERR_STATUS("cpaCySymInitSession", stat);
    }

    /*
     * Invoke symmetric operations (cipher and/or hash) on the session
     */
    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = cpaCyBufferListGetMetaSize(cyInstHandle, numBuffers, &bufferMetaSize);
        CHECK_ERR_STATUS("cpaCyBufferListGetMetaSize", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = memAllocContig((void *)&bufferMeta, bufferMetaSize, 64);
        CHECK_ERR_STATUS("memAllocContig", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = memAllocOs((void *)&bufferList, bufferListMemSize);
        CHECK_ERR_STATUS("memAllocOs", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = memAllocContig((void *)&srcBuffer, nea1testData.inSize, 64);
        CHECK_ERR_STATUS("memAllocContig", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = memAllocContig((void *)&ivBuffer, nea1testData.ivSize, 64);
        CHECK_ERR_STATUS("memAllocContig", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        memcpy(srcBuffer, nea1testData.in, nea1testData.inSize);
        memcpy(ivBuffer, nea1testData.iv, nea1testData.ivSize);

        flatBuffer = (CpaFlatBuffer *)(bufferList + 1);

        bufferList->pBuffers = flatBuffer;
        bufferList->numBuffers = numBuffers;
        bufferList->pPrivateMetaData = bufferMeta;

        flatBuffer->dataLenInBytes = nea1testData.inSize;
        flatBuffer->pData = srcBuffer;

        stat = memAllocOs((void *)&opData, sizeof(CpaCySymOpData));
        CHECK_ERR_STATUS("memAllocOs", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        opData->sessionCtx = sessionCtx;
        opData->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
        opData->pIv = ivBuffer;
        opData->ivLenInBytes = nea1testData.ivSize;
        opData->cryptoStartSrcOffsetInBytes = 0;
        opData->messageLenToCipherInBytes = nea1testData.inSize;

        stat = cpaCySymPerformOp(cyInstHandle, NULL, opData, bufferList, bufferList, NULL);
        CHECK_ERR_STATUS("cpaCySymPerformOp", stat);
    }

    /*
     * Poll the result
     */
    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = icp_sal_CyPollInstance(cyInstHandle, 0);
        CHECK_ERR_STATUS("icp_sal_CyPollInstance", stat);
    }

    /*
     * Verify the result
     */
    if (CPA_STATUS_SUCCESS == stat)
    {
        if (0 == memcmp(srcBuffer, nea1testData.out, nea1testData.outSize))
        {
            PRINT("Output matches expected output!\n");
        }
        else
        {
            PRINT("Output does not match expected output\n");
            stat = CPA_STATUS_FAIL;
        }
    }

    /*
     * Stop the cryptographic service instance
     */
    if (NULL != cyInstHandle)
    {
        cpaCyStopInstance(cyInstHandle);
    }

    /*
     * Close user space access to the QAT endpoint and memory driver
     */
    icp_sal_userStop();
    qaeMemDestroy();

    freeTestData(nea1testData);

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
    if (NULL ==  *memAddr)
    {
        return CPA_STATUS_RESOURCE;
    }
    return CPA_STATUS_SUCCESS;
}
