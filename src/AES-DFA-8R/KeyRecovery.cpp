#include "AesCore.hpp"
#include "AesData.hpp"
#include "Constants.hpp"
#include "FaultAttackLogic.hpp"
#include "LocaleInitializer.hpp"
#include "KeyRecovery.hpp"
#include "Utilities.hpp"

#include <cstring>
#include <immintrin.h>
#include <iostream>
#include <vector>

static DWORD WINAPI ExhaustiveSearchWorker(LPVOID lpParam)
{
    PTHREAD_WORKER_ARGS pArgs = static_cast<PTHREAD_WORKER_ARGS>(lpParam);
    const PAIR* pPair = pArgs->pPairData;
    const KNOWN_PT* pKnownPt = pArgs->pKnownPtData;

    BOOL bLocalFoundKeyWithKnownPt = FALSE;
    if (pKnownPt->bIsSome && (*pArgs->plSharedFoundFlag == 1))
    {
        bLocalFoundKeyWithKnownPt = TRUE;
    }

    DWORD adwSingleByteMasks[4] = { 0xFFFFFF00, 0xFFFF00FF, 0xFF00FFFF, 0x00FFFFFF };

    alignas(16) BYTE abSubKey10[16];
    alignas(16) BYTE abSubKey9[16];
    BYTE abAllSubKeys[176];
    alignas(16) BYTE abTempCT[16];

    const SIZE_T cLocalBufferMax = 512;
    BYTE abLocalKeys[cLocalBufferMax][16];
    SIZE_T cLocalCount = 0;

    alignas(16) DWORD adwDiff32State8[4];
    for (INT i0 = pArgs->nStartI0; i0 < pArgs->nEndI0; i0++)
    {
        if (bLocalFoundKeyWithKnownPt)
        {
            break;
        }

        abSubKey10[0] = TAKEBYTE(pArgs->padwCandidates[0][i0], 0);
        abSubKey10[13] = TAKEBYTE(pArgs->padwCandidates[0][i0], 1);
        abSubKey10[10] = TAKEBYTE(pArgs->padwCandidates[0][i0], 2);
        abSubKey10[7] = TAKEBYTE(pArgs->padwCandidates[0][i0], 3);

        for (INT i1 = 0; i1 < pArgs->panCandidatesLen[1]; i1++)
        {
            if (bLocalFoundKeyWithKnownPt)
            {
                break;
            }
            abSubKey10[4] = TAKEBYTE(pArgs->padwCandidates[1][i1], 0);
            abSubKey10[1] = TAKEBYTE(pArgs->padwCandidates[1][i1], 1);
            abSubKey10[14] = TAKEBYTE(pArgs->padwCandidates[1][i1], 2);
            abSubKey10[11] = TAKEBYTE(pArgs->padwCandidates[1][i1], 3);

            for (INT i2 = 0; i2 < pArgs->panCandidatesLen[2]; i2++)
            {
                if (bLocalFoundKeyWithKnownPt)
                {
                    break;
                }
                abSubKey10[8] = TAKEBYTE(pArgs->padwCandidates[2][i2], 0);
                abSubKey10[5] = TAKEBYTE(pArgs->padwCandidates[2][i2], 1);
                abSubKey10[2] = TAKEBYTE(pArgs->padwCandidates[2][i2], 2);
                abSubKey10[15] = TAKEBYTE(pArgs->padwCandidates[2][i2], 3);

                for (INT i3 = 0; i3 < pArgs->panCandidatesLen[3]; i3++)
                {
                    if (bLocalFoundKeyWithKnownPt)
                    {
                        break;
                    }
                    abSubKey10[12] = TAKEBYTE(pArgs->padwCandidates[3][i3], 0);
                    abSubKey10[9] = TAKEBYTE(pArgs->padwCandidates[3][i3], 1);
                    abSubKey10[6] = TAKEBYTE(pArgs->padwCandidates[3][i3], 2);
                    abSubKey10[3] = TAKEBYTE(pArgs->padwCandidates[3][i3], 3);

                    K9FromK10(abSubKey10, abSubKey9);
                    __m128i k9ForDec = _mm_load_si128(reinterpret_cast<const __m128i*>(abSubKey9));
                    k9ForDec = _mm_aesimc_si128(k9ForDec);

                    __m128i goodState = _mm_load_si128(reinterpret_cast<const __m128i*>(pPair->rgbCt));
                    __m128i faultyState = _mm_load_si128(reinterpret_cast<const __m128i*>(pPair->rgbFct));
                    __m128i k10m = _mm_load_si128(reinterpret_cast<const __m128i*>(abSubKey10));

                    goodState = _mm_xor_si128(goodState, k10m);
                    faultyState = _mm_xor_si128(faultyState, k10m);

                    goodState = _mm_aesdec_si128(goodState, k9ForDec);
                    faultyState = _mm_aesdec_si128(faultyState, k9ForDec);
                    goodState = _mm_aesdec_si128(goodState, k9ForDec);
                    faultyState = _mm_aesdec_si128(faultyState, k9ForDec);

                    __m128i diffState = _mm_xor_si128(goodState, faultyState);
                    _mm_store_si128(reinterpret_cast<__m128i*>(adwDiff32State8), diffState);

                    INT nRow8Fault = pArgs->nRow8FaultKnown;
                    if (nRow8Fault != -1)
                    {
                        if ((adwDiff32State8[pArgs->nCol8Fault] & adwSingleByteMasks[nRow8Fault]) != 0 ||
                            TAKEBYTE(adwDiff32State8[pArgs->nCol8Fault], nRow8Fault) == 0)
                        {
                            continue;
                        }
                    }
                    else
                    {
                        BOOL bFoundSingleByte = FALSE;
                        for (INT r = 0; r < 4; r++)
                        {
                            if (((adwDiff32State8[pArgs->nCol8Fault] & adwSingleByteMasks[r]) == 0) &&
                                TAKEBYTE(adwDiff32State8[pArgs->nCol8Fault], r) != 0)
                            {
                                nRow8Fault = r;
                                bFoundSingleByte = TRUE;
                                break;
                            }
                        }
                        if (!bFoundSingleByte)
                        {
                            continue;
                        }
                    }

                    // Sinon jsp

                    ReverseKeyExpansion(abSubKey10, abAllSubKeys);

                    if (pKnownPt->bIsSome)
                    {
                        EncryptAES(pKnownPt->rgbPt, abTempCT, abAllSubKeys);
                        if (::memcmp(pKnownPt->rgbCt, abTempCT, 16) == 0)
                        {
                            if (::InterlockedCompareExchange(pArgs->plSharedFoundFlag, 1, 0) == 0)
                            {
                                ::EnterCriticalSection(pArgs->pCriticalSection);
                                if (*pArgs->pnSharedNKeys == 0)
                                {
                                    ::memcpy(pArgs->pabMasterKeysOutput[0], abAllSubKeys, 16);
                                    (*pArgs->pnSharedNKeys) = 1;
                                }
                                ::LeaveCriticalSection(pArgs->pCriticalSection);
                            }
                            bLocalFoundKeyWithKnownPt = TRUE;
                            break;
                        }
                    }
                    else
                    {
                        ::memcpy(abLocalKeys[cLocalCount], abAllSubKeys, 16);
                        cLocalCount++;
                        // Flush si plein
                        if (cLocalCount == cLocalBufferMax)
                        {
                            ::EnterCriticalSection(pArgs->pCriticalSection);
                            for (SIZE_T kk = 0; kk < cLocalCount; kk++)
                            {
                                if ((*pArgs->pnSharedNKeys) < KEYS_MAX)
                                {
                                    ::memcpy(pArgs->pabMasterKeysOutput[*pArgs->pnSharedNKeys],
                                        abLocalKeys[kk], 16);
                                    (*pArgs->pnSharedNKeys)++;
                                }
                                else
                                {
                                    if (::InterlockedCompareExchange(pArgs->plSharedFoundFlag, 2, 0) == 0)
                                    {
                                        std::cerr << "Limite «KEYS_MAX» atteinte.\n";
                                    }
                                    bLocalFoundKeyWithKnownPt = TRUE;
                                    break;
                                }
                            }
                            ::LeaveCriticalSection(pArgs->pCriticalSection);
                            cLocalCount = 0;
                            if (bLocalFoundKeyWithKnownPt)
                            {
                                break;
                            }
                        }
                    }
                }
            }
        }

        if (pKnownPt->bIsSome && (i0 % 10 == 0))
        {
            if ((*pArgs->plSharedFoundFlag) == 1)
            {
                bLocalFoundKeyWithKnownPt = TRUE;
            }
        }
    }

    if (!pKnownPt->bIsSome && !bLocalFoundKeyWithKnownPt && (cLocalCount > 0))
    {
        ::EnterCriticalSection(pArgs->pCriticalSection);
        for (SIZE_T kk = 0; kk < cLocalCount; kk++)
        {
            if ((*pArgs->pnSharedNKeys) < KEYS_MAX)
            {
                ::memcpy(pArgs->pabMasterKeysOutput[*pArgs->pnSharedNKeys],
                    abLocalKeys[kk], 16);
                (*pArgs->pnSharedNKeys)++;
            }
            else
            {
                if (::InterlockedCompareExchange(pArgs->plSharedFoundFlag, 2, 0) == 0)
                {
                    std::cerr << "Limite «KEYS_MAX» atteinte.\n";
                }
                break;
            }
        }
        ::LeaveCriticalSection(pArgs->pCriticalSection);
    }

    return 0;
}

INT R8ExhaustiveSearch(const PAIR* pPair,
    INT nRow8FaultKnown,
    INT nCol8Fault,
    _In_reads_(4) const DWORD(*padwCandidatesK10)[CAND_MAX],
    _In_reads_(4) const INT* panCandidatesLen,
    const KNOWN_PT* pKnownPt,
    _Out_writes_all_(KEYS_MAX * 16) BYTE(*pabMasterKeysOutput)[16])
{
    INT nKeysFound = 0;
    LONG lFoundFlag = 0; // 0 = pas trouvé, 1 = trouvé (known_pt), 2 = overflow

    CRITICAL_SECTION cs;
    if (!::InitializeCriticalSectionAndSpinCount(&cs, 0x00000400))
    {
        std::cerr << "Échec de l'initialisation de la section critique.\n";
        return 0;
    }

    SYSTEM_INFO sysInfo;
    ::GetSystemInfo(&sysInfo);
    INT nNumThreads = static_cast<INT>(sysInfo.dwNumberOfProcessors);
    if (nNumThreads > MAXIMUM_WAIT_OBJECTS)
    {
        nNumThreads = MAXIMUM_WAIT_OBJECTS;
    }
    if (nNumThreads == 0)
    {
        nNumThreads = 1;
    }

    // On parallélise sur la diagonale 0
    if (panCandidatesLen[0] < nNumThreads)
    {
        nNumThreads = (panCandidatesLen[0] > 0) ? panCandidatesLen[0] : 1;
    }

    HANDLE* phThreadHandles = static_cast<HANDLE*>(::malloc(sizeof(HANDLE) * nNumThreads));
    PTHREAD_WORKER_ARGS pThreadArgs = static_cast<PTHREAD_WORKER_ARGS>(::malloc(sizeof(THREAD_WORKER_ARGS) * nNumThreads));
    if (!phThreadHandles || !pThreadArgs)
    {
        std::cerr << "Échec de l'allocation mémoire pour les threads.\n";
        if (phThreadHandles) ::free(phThreadHandles);
        if (pThreadArgs) ::free(pThreadArgs);
        ::DeleteCriticalSection(&cs);
        return 0;
    }

    INT nItemsPerThread = panCandidatesLen[0] / nNumThreads;
    INT nRemainder = panCandidatesLen[0] % nNumThreads;
    INT nCurrentStart = 0;

    for (INT i = 0; i < nNumThreads; i++)
    {
        pThreadArgs[i].pPairData = pPair;
        pThreadArgs[i].nRow8FaultKnown = nRow8FaultKnown;
        pThreadArgs[i].nCol8Fault = nCol8Fault;
        pThreadArgs[i].padwCandidates = padwCandidatesK10;
        pThreadArgs[i].panCandidatesLen = panCandidatesLen;
        pThreadArgs[i].pKnownPtData = pKnownPt;
        pThreadArgs[i].pabMasterKeysOutput = pabMasterKeysOutput;
        pThreadArgs[i].pnSharedNKeys = &nKeysFound;
        pThreadArgs[i].plSharedFoundFlag = &lFoundFlag;
        pThreadArgs[i].pCriticalSection = &cs;

        INT nCountForThisThread = nItemsPerThread + ((i < nRemainder) ? 1 : 0);
        pThreadArgs[i].nStartI0 = nCurrentStart;
        pThreadArgs[i].nEndI0 = nCurrentStart + nCountForThisThread;
        nCurrentStart += nCountForThisThread;

        if (nCountForThisThread > 0)
        {
            phThreadHandles[i] = ::CreateThread(
                nullptr,
                0,
                ExhaustiveSearchWorker,
                &pThreadArgs[i],
                0,
                nullptr
            );
            if (phThreadHandles[i] == NULL)
            {
                std::cerr << "Échec de CreateThread pour i=" << i
                    << ", err=" << ::GetLastError() << "\n";
                for (INT k = 0; k < i; k++)
                {
                    if (phThreadHandles[k] != NULL)
                    {
                        ::WaitForSingleObject(phThreadHandles[k], INFINITE);
                        ::CloseHandle(phThreadHandles[k]);
                    }
                }
                ::free(phThreadHandles);
                ::free(pThreadArgs);
                ::DeleteCriticalSection(&cs);
                return nKeysFound;
            }
        }
        else
        {
            phThreadHandles[i] = NULL;
        }
    }

    for (INT i = 0; i < nNumThreads; i++)
    {
        if (phThreadHandles[i] != NULL)
        {
            ::WaitForSingleObject(phThreadHandles[i], INFINITE);
            ::CloseHandle(phThreadHandles[i]);
        }
    }

    ::free(phThreadHandles);
    ::free(pThreadArgs);
    ::DeleteCriticalSection(&cs);

    if (lFoundFlag == 2) // overflow
    {
        if (nKeysFound > KEYS_MAX)
        {
            nKeysFound = KEYS_MAX;
        }
    }
    return nKeysFound;
}

INT R8KeyRecoverySingleCT(const PAIR* pPair,
    INT nRow8,
    INT nCol8,
    const KNOWN_PT* pKnownPt,
    _Out_writes_all_(KEYS_MAX * 16) BYTE(*pabMasterKeys)[16])
{
    DWORD(*adwCandidates)[CAND_MAX] = static_cast<DWORD(*)[CAND_MAX]>(::malloc(4 * CAND_MAX * sizeof(DWORD)));
    if (!adwCandidates)
    {
        std::cerr << "Échec de l'allocation des «candidats».\n";
        return 0;
    }
    INT anCandidatesLen[4];
    ZeroMemory(anCandidatesLen, sizeof(anCandidatesLen));

    R8FindCandidates(pPair, nRow8, nCol8, adwCandidates, anCandidatesLen);

    UINT64 ullNbCand = 1ULL;
    for (INT i = 0; i < 4; i++)
    {
        ullNbCand *= static_cast<UINT64>(anCandidatesLen[i]);
    }

    /*
    if (nRow8 != -1)
    {
        std::cerr << "     (et ligne=" << nRow8 << ")\n";
    }
    */

    // PrintNumberCandidates(anCandidatesLen, ullNbCand);

    
    /*
    if (pKnownPt->bIsSome)
    {
        std::cerr << "Filtrage avec texte clair connu.\n";
    }
    else
    {
        std::cerr << " Pas de texte clair connu -> collecte de toutes les clés.\n";
    }
    */

    INT nFound = 0;
    if ((ullNbCand > 0ULL) && (anCandidatesLen[0] > 0))
    {
        nFound = R8ExhaustiveSearch(pPair, nRow8, nCol8,
            adwCandidates,
            anCandidatesLen,
            pKnownPt,
            pabMasterKeys);
    }
    else
    {
        std::cerr << "Pas de candidats dans diag0 -> ignoré.\n";
    }

    ::free(adwCandidates);
    // std::cerr << "Nombre de clés pour cette hypothèse :  " << nFound << "\n";
    return nFound;
}

INT R8KeyRecovery(_Inout_updates_(PAIRS_MAX) PAIR* paPairs,
    INT nNumPairs,
    const KNOWN_PT* pKnownPt,
    _Out_writes_all_(KEYS_MAX * 16) BYTE(*pabMasterKeys)[16])
{
    if (nNumPairs == 0) return 0;

    PAIR* pPair = &paPairs[0];
    // std::cerr << "Traitement d'une seule paire CT :\n";
    // PrintPairInfo(pPair);

    INT nRow8Fault = -1;
    INT nCol8Start = 0;
    INT nCol8End = 4;

    if (pPair->nFaultPos >= 0 && pPair->nFaultPos < 16)
    {
        nRow8Fault = pPair->nFaultPos % 4;
        nCol8Start = pPair->nFaultPos / 4;
        nCol8End = nCol8Start + 1;
    }

    INT nTotalKeys = 0;
    for (INT nCol8 = nCol8Start; nCol8 < nCol8End; nCol8++)
    {
        INT nCur = R8KeyRecoverySingleCT(pPair, nRow8Fault, nCol8,
            pKnownPt,
            &pabMasterKeys[nTotalKeys]);
        nTotalKeys += nCur;

        if (nTotalKeys >= KEYS_MAX)
        {
            break;
        }
        if (pKnownPt->bIsSome && (nTotalKeys > 0))
        {
            break;
        }
    }

    if (nTotalKeys >= KEYS_MAX && !(pKnownPt->bIsSome && nTotalKeys > 0))
    {
        std::cerr << "Limite KEYS_MAX. Certaines clés pourraient manquer.\n";
    }
    return nTotalKeys;
}
