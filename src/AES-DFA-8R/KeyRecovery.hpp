#pragma once

#include "Constants.hpp"
#include "DataStructures.hpp"

#include <windows.h>

typedef struct _THREAD_WORKER_ARGS
{
    const PAIR* pPairData;
    INT nRow8FaultKnown;
    INT nCol8Fault;
    const DWORD(*padwCandidates)[CAND_MAX];
    const INT* panCandidatesLen;
    const KNOWN_PT* pKnownPtData;
    BYTE(*pabMasterKeysOutput)[16];

    INT* pnSharedNKeys;
    volatile LONG* plSharedFoundFlag;
    LPCRITICAL_SECTION pCriticalSection;

    INT nStartI0;
    INT nEndI0;
}
THREAD_WORKER_ARGS, * PTHREAD_WORKER_ARGS;

INT R8ExhaustiveSearch(const PAIR* pPair,
    INT nRow8FaultKnown,
    INT nCol8Fault,
    _In_reads_(4) const DWORD(*padwCandidatesK10)[CAND_MAX],
    _In_reads_(4) const INT* panCandidatesLen,
    const KNOWN_PT* pKnownPt,
    _Out_writes_all_(KEYS_MAX * 16) BYTE(*pabMasterKeysOutput)[16]);

INT R8KeyRecoverySingleCT(const PAIR* pPair,
    INT nRow8, INT nCol8,
    const KNOWN_PT* pKnownPt,
    _Out_writes_all_(KEYS_MAX * 16) BYTE(*pabMasterKeys)[16]);

INT R8KeyRecovery(_Inout_updates_(PAIRS_MAX) PAIR* paPairs,
    INT nNumPairs,
    const KNOWN_PT* pKnownPt,
    _Out_writes_all_(KEYS_MAX * 16) BYTE(*pabMasterKeys)[16]);
