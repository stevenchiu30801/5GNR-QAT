#include <string.h>
#include <unistd.h>

#include "cpa.h"
#include "cpa_cy_common.h"
#include "cpa_cy_im.h"
#include "cpa_cy_sym.h"
#include "cpa_sample_utils.h"
#include "icp_sal_poll.h"
#include "icp_sal_user.h"
#include "qae_mem.h"

#include "utils.h"

CpaInstanceHandle *inst_g = NULL;

void usage(const char *cmd)
{
    PRINT("Test 5G NR Security with Intel QAT\n");
    PRINT("\n");
    PRINT("Usage: sudo %s [ALGO] [TESTSET]\n", cmd);
    PRINT("Arguments:\n");
    PRINT("    ALGO        Security algorithm - nea1, nea2 or nea3\n");
    PRINT("    TESTSET     Test set number - 1 to 3\n");
}

static void symCallback(void *callBackTag,
                        CpaStatus status,
                        const CpaCySymOp operationType,
                        void *opData,
                        CpaBufferList *dstBuffer,
                        CpaBoolean verifyResult)
{
    PRINT_DBG("Callback called with status = %d.\n", status); 
}

int main(int argc, const char **argv)
{
    TestData cipherTestData = {0};
    int testSetId = 0;
    CpaStatus stat;

    if (argc == 1)
    {
        cipherTestData = genSampleTestData();
    }
    else if (argc == 2 && (0 == strcmp(argv[1], "-h") || 0 == strcmp(argv[1], "--help")))
    {
        usage(argv[0]);
        exit(0);
    }
    else if (argc != 3)
    {
        PRINT("Invalid arguments\n");
        usage(argv[0]);
        exit(1);
    }
    else
    {
        testSetId = atoi(argv[2]);
        if (testSetId > 3 || testSetId < 1)
        {
            PRINT("Invalid test set ID\n");
            usage(argv[0]);
            exit(1);
        }
        if (0 == strcmp(argv[1], "nea1"))
        {
            cipherTestData = genNea1TestData(testSetId);
        }
        else if (0 == strcmp(argv[1], "nea2"))
        {
            cipherTestData = genNea2TestData(testSetId);
        }
        else if (0 == strcmp(argv[1], "nea3"))
        {
            cipherTestData = genNea3TestData(testSetId);
        }
        else
        {
            PRINT("Unknow security algorithm\n");
            usage(argv[0]);
            exit(1);
        }
    }
    stat = execQat(cipherTestData);

    return (int)stat;
}

CpaStatus execQat(TestData cipherTestData)
{
    CpaStatus stat = CPA_STATUS_SUCCESS;
    char *processName = NULL;
    Cpa16U numInstances = 0;
    CpaInstanceHandle cyInstHandles[MAX_INSTANCES];
    CpaInstanceHandle cyInstHandle = NULL;
    CpaCySymSessionSetupData sessionSetupData = {0};
    Cpa32U sessionCtxSize = 0;
    CpaCySymSessionCtx sessionCtx = NULL;
    Cpa32U numBuffers = 1;
    CpaBoolean inPlaceOp = CPA_TRUE;
    CpaBufferList *srcBufferList = NULL;
    CpaBufferList *dstBufferList = NULL;
    CpaFlatBuffer *flatBuffer = NULL;
    Cpa8U *ivBuffer = NULL;
    CpaCySymOpData *opData = NULL;
    Cpa8U *dstBuffer = NULL;
    Cpa32U byteLen = 0;
    CpaBoolean sessionInUse = CPA_FALSE;
    CpaCySymStats64 symStats = {0};
    Cpa32U listIdx = 0;

    gDebugParam = 1;

    /*
     * Initialize memory driver usdm_drv for user space
     */
    PRINT_DBG("qaeMemInit()\n");
    stat = qaeMemInit();
    if (CPA_STATUS_SUCCESS != stat)
    {
        PRINT_ERR("Failed to initialise memory driver\n");
        return stat;
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
        return stat;
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
        sessionSetupData.sessionPriority = CPA_CY_PRIORITY_NORMAL;
        sessionSetupData.symOperation = CPA_CY_SYM_OP_CIPHER;
        sessionSetupData.cipherSetupData.cipherAlgorithm = cipherTestData.algo;
        sessionSetupData.cipherSetupData.pCipherKey = cipherTestData.key;
        sessionSetupData.cipherSetupData.cipherKeyLenInBytes = cipherTestData.keySize;
        sessionSetupData.cipherSetupData.cipherDirection = getCipherDirection(cipherTestData);

        PRINT_DBG("Key: ");
        for (listIdx = 0; listIdx < sessionSetupData.cipherSetupData.cipherKeyLenInBytes; listIdx++)
        {
            PRINT("%02x ", sessionSetupData.cipherSetupData.pCipherKey[listIdx]);
        }
        PRINT("\n");

        PRINT_DBG("cpaCySymSessionCtxGetSize()\n");
        stat = cpaCySymSessionCtxGetSize(cyInstHandle, &sessionSetupData, &sessionCtxSize);
        CHECK_ERR_STATUS("cpaCySymSessionCtxGetSize", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = memAllocContig((void *)&sessionCtx, sessionCtxSize, BYTE_ALIGNMENT);
        CHECK_ERR_STATUS("memAllocContig", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        PRINT_DBG("cpaCySymInitSession()\n");
        stat = cpaCySymInitSession(cyInstHandle,
                                   // symCallback,
                                   NULL,
                                   &sessionSetupData,
                                   sessionCtx);
        CHECK_ERR_STATUS("cpaCySymInitSession", stat);
    }

    /*
     * Invoke symmetric operations (cipher and/or hash) on the session
     */
    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = createBuffers(cyInstHandle,
                             numBuffers,
                             cipherTestData.inSize,
                             &srcBufferList,
                             &dstBufferList,
                             inPlaceOp);
        CHECK_ERR_STATUS("createBuffers", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = memAllocContig((void *)&ivBuffer, cipherTestData.ivSize, BYTE_ALIGNMENT);
        CHECK_ERR_STATUS("memAllocContig", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = memAllocOs((void *)&opData, sizeof(CpaCySymOpData));
        CHECK_ERR_STATUS("memAllocOs", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        flatBuffer = (CpaFlatBuffer *)(srcBufferList + 1);

        memcpy(flatBuffer->pData, cipherTestData.in, cipherTestData.inSize);
        memcpy(ivBuffer, cipherTestData.iv, cipherTestData.ivSize);

        opData->sessionCtx = sessionCtx;
        opData->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
        opData->pIv = ivBuffer;
        opData->ivLenInBytes = cipherTestData.ivSize;
        opData->cryptoStartSrcOffsetInBytes = 0;
        opData->messageLenToCipherInBytes = cipherTestData.inSize;

        PRINT_DBG("IV: ");
        for (listIdx = 0; listIdx < opData->ivLenInBytes; listIdx++)
        {
            PRINT("%02x ", opData->pIv[listIdx]);
        }
        PRINT("\n");

        PRINT_DBG("cpaCySymPerformOp()\n");
        stat = cpaCySymPerformOp(cyInstHandle,
                                 NULL,
                                 opData,
                                 srcBufferList,
                                 dstBufferList,
                                 NULL);
        CHECK_ERR_STATUS("cpaCySymPerformOp", stat);
    }

    // sleep(1);

    /*
     * Verify the result
     */
    if (CPA_STATUS_SUCCESS == stat)
    {
        flatBuffer = (CpaFlatBuffer *)(dstBufferList + 1);
        dstBuffer = flatBuffer->pData;
        byteLen = cipherTestData.bitLen / 8;
        for (listIdx = byteLen + 1; listIdx < cipherTestData.outSize; listIdx++)
        {
            dstBuffer[listIdx] = 0x0;
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
            for (listIdx = 0; listIdx < cipherTestData.outSize; listIdx++)
            {
                if (0 == memcmp(dstBuffer + listIdx, cipherTestData.out + listIdx, 1))
                {
                    PRINT("%02x ", dstBuffer[listIdx]);
                }
                else
                {
                    PRINT_COLOR(ANSI_COLOR_RED, "%02x ", dstBuffer[listIdx]);
                }
                if (listIdx % 8 == 7)
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

    freeBuffers(numBuffers,
                &srcBufferList,
                &dstBufferList,
                inPlaceOp);
    memFreeOs((void *)&opData);
    memFreeContig((void *)&ivBuffer);

    memFreeContig((void *)&sessionCtx);
    freeTestData(&cipherTestData);

    /*
     * Close user space access to the QAT endpoint and memory driver
     */
    PRINT_DBG("icp_sal_userStop()\n");
    icp_sal_userStop();
    qaeMemDestroy();

    return stat;
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

CpaStatus createBuffers(CpaInstanceHandle cyInstHandle,
                        /* Assume source and destination buffer lists have equal number of buffers, and all flat
                         * buffers have the same size */
                        Cpa32U numBuffers,
                        Cpa32U bufferSize,
                        CpaBufferList **srcBufferList,
                        CpaBufferList **dstBufferList,
                        CpaBoolean inPlaceOp)
{
    Cpa32U bufferMetaSize = 0;
    Cpa8U *srcBufferMeta = NULL;
    Cpa8U *dstBufferMeta = NULL;
    /*
     * Allocate memory for bufferlist and array of flat buffers in a contiguous
     * area and carve it up to reduce number of memory allocations required.
     */
    Cpa32U bufferListMemSize = sizeof(CpaBufferList) + (numBuffers * sizeof(CpaFlatBuffer));
    Cpa8U *srcBuffer = NULL;
    Cpa8U *dstBuffer = NULL;
    CpaFlatBuffer *flatBuffer = NULL;
    Cpa32U listIdx = 0;

    CpaStatus stat = CPA_STATUS_SUCCESS;
    if (CPA_STATUS_SUCCESS == stat)
    {
        PRINT_DBG("cpaCyBufferListGetMetaSize()\n");
        stat = cpaCyBufferListGetMetaSize(cyInstHandle, numBuffers, &bufferMetaSize);
        CHECK_ERR_STATUS("cpaCyBufferListGetMetaSize", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = memAllocContig((void *)&srcBufferMeta, bufferMetaSize, BYTE_ALIGNMENT);
        CHECK_ERR_STATUS("memAllocContig", stat);
    }

    if (CPA_STATUS_SUCCESS == stat && CPA_TRUE != inPlaceOp)
    {
        stat = memAllocContig((void *)&dstBufferMeta, bufferMetaSize, BYTE_ALIGNMENT);
        CHECK_ERR_STATUS("memAllocContig", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        stat = memAllocOs((void *)srcBufferList, bufferListMemSize);
        CHECK_ERR_STATUS("memAllocOs", stat);
    }

    if (CPA_STATUS_SUCCESS == stat && CPA_TRUE != inPlaceOp)
    {
        stat = memAllocOs((void *)dstBufferList, bufferListMemSize);
        CHECK_ERR_STATUS("memAllocOs", stat);
    }

    if (CPA_STATUS_SUCCESS == stat)
    {
        (*srcBufferList)->pBuffers = (CpaFlatBuffer *)(*srcBufferList + 1);
        (*srcBufferList)->numBuffers = numBuffers;
        (*srcBufferList)->pPrivateMetaData = srcBufferMeta;

        if (CPA_TRUE != inPlaceOp)
        {
            (*dstBufferList)->pBuffers = (CpaFlatBuffer *)(*dstBufferList + 1);
            (*dstBufferList)->numBuffers = numBuffers;
            (*dstBufferList)->pPrivateMetaData = dstBufferMeta;
        }
        else
        {
            *dstBufferList = *srcBufferList;
        }
    }

    for (listIdx = 1; listIdx <= numBuffers; listIdx++)
    {
        if (CPA_STATUS_SUCCESS == stat)
        {
            stat = memAllocContig((void *)&srcBuffer, bufferSize, BYTE_ALIGNMENT);
            CHECK_ERR_STATUS("memAllocContig", stat);
        }

        if (CPA_STATUS_SUCCESS == stat)
        {
            flatBuffer = (CpaFlatBuffer *)(*srcBufferList + listIdx);

            flatBuffer->dataLenInBytes = bufferSize;
            flatBuffer->pData = srcBuffer;
        }

        if (CPA_STATUS_SUCCESS == stat && CPA_TRUE != inPlaceOp)
        {
            stat = memAllocContig((void *)&dstBuffer, bufferSize, BYTE_ALIGNMENT);
            CHECK_ERR_STATUS("memAllocContig", stat);
        }

        if (CPA_STATUS_SUCCESS == stat && CPA_TRUE != inPlaceOp)
        {
            flatBuffer = (CpaFlatBuffer *)(*dstBufferList + listIdx);

            flatBuffer->dataLenInBytes = bufferSize;
            flatBuffer->pData = dstBuffer;
        }

        if (CPA_STATUS_SUCCESS != stat)
        {
            break;
        }
    }

    return stat;
}

void freeBuffers(Cpa32U numBuffers,
                 CpaBufferList **srcBufferList,
                 CpaBufferList **dstBufferList,
                 CpaBoolean inPlaceOp)
{
    CpaFlatBuffer *flatBuffer = NULL;
    Cpa32U listIdx = 0;
    if (NULL != *srcBufferList)
    {
        for (listIdx = 1; listIdx <= numBuffers; listIdx++)
        {
            flatBuffer = (CpaFlatBuffer *)(*srcBufferList + listIdx);
            memFreeContig((void *)&(flatBuffer->pData));
        }
        memFreeContig((void *)&((*srcBufferList)->pPrivateMetaData));

        memFreeOs((void* )srcBufferList);
        *srcBufferList = NULL;
    }
    if (CPA_TRUE == inPlaceOp)
    {
        *dstBufferList = NULL;
    }
    else if (NULL != *dstBufferList)
    {
        for (listIdx = 1; listIdx <= numBuffers; listIdx++)
        {
            flatBuffer = (CpaFlatBuffer *)(*dstBufferList + listIdx);
            memFreeContig((void *)&(flatBuffer->pData));
        }
        memFreeContig((void *)&((*dstBufferList)->pPrivateMetaData));

        memFreeOs((void* )dstBufferList);
        *dstBufferList = NULL;
    }
}

void freeInstanceMapping(void)
{
    if (NULL != inst_g)
    {
        qaeMemFree((void **)&inst_g);
    }
}
