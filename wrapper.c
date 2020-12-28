#include <stdlib.h>

#include "cpa.h"
#include "qae_mem.h"

#include "utils.h"

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
