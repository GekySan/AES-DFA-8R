#include "AesCore.hpp"
#include "FaultAttackLogic.hpp"

#include <vector>
#include <cstring>


INT GetDiffMC(INT nRow,
    const INT* panFaultList,
    INT nFaultListLen,
    _Out_writes_(DIFF_MC_MAX) DWORD* pdwListDiff)
{
    INT nListDiffLen = 0;
    INT nRowStart = 0;
    INT nRowEnd = 4;
    BYTE rgbCol[4];
    if (pdwListDiff != nullptr && DIFF_MC_MAX > 0) {
        ZeroMemory(pdwListDiff, (size_t)DIFF_MC_MAX * sizeof(DWORD));
    }
    else if (DIFF_MC_MAX == 0) {}

    if (nRow != -1)
    {
        nRowStart = nRow;
        nRowEnd = nRow + 1;
    }

    for (INT nPos = nRowStart; nPos < nRowEnd; nPos++)
    {
        for (INT i = 0; i < nFaultListLen; i++)
        {
            if (nListDiffLen >= DIFF_MC_MAX) {
                goto end_loops;
            }

            ZeroMemory(rgbCol, 4);
            rgbCol[nPos] = static_cast<BYTE>(panFaultList[i]);
            MixColumn(rgbCol);
            pdwListDiff[nListDiffLen++] = BYTES_TO_WORD(rgbCol);
        }
    }
end_loops:;

    return nListDiffLen;
}

INT R8GetDiffMC(INT nCol8,
    INT nCol9,
    DWORD dwDiffCol,
    _Out_writes_(DIFF_MC_MAX) DWORD* pdwDiffMCList)
{
    INT anFaultList[255];
    INT nFaultListLen = 0;

    INT nRow9 = -1;
    if (nCol8 != -1)
    {
        nRow9 = (nCol8 + 3 * nCol9) % 4;
    }

    if (dwDiffCol != 0)
    {
        INT nDiffVal = static_cast<INT>(TAKEBYTE(dwDiffCol, nRow9));
        for (INT c1 = 1; c1 < 255; c1++)
        {
            INT c2 = nDiffVal ^ c1;
            if (c1 > c2)
            {
                continue;
            }
            anFaultList[nFaultListLen++] =
                static_cast<INT>(g_sbox[c1] ^ g_sbox[c2]);
        }
    }
    else
    {
        for (INT i = 0; i < 255; i++)
        {
            anFaultList[i] = i + 1;
        }
        nFaultListLen = 255;
    }

    return GetDiffMC(nRow9, anFaultList, nFaultListLen, pdwDiffMCList);
}

INT K10CandFromDiffMC(const PAIR* pPair,
    INT nCol,
    const DWORD* pdwDiffMCList,
    INT nDiffMCListLen,
    _Out_writes_(CAND_MAX) DWORD* pdwCandidates)
{
    BYTE rgbGood[4], rgbFaulty[4];
    for (INT i = 0; i < 4; i++)
    {
        rgbGood[i] = pPair->rgbCt[g_positions[nCol][i]];
        rgbFaulty[i] = pPair->rgbFct[g_positions[nCol][i]];
    }

    INT nCandTotal = 0;
    for (INT i = 0; i < nDiffMCListLen; i++)
    {
        if (nCandTotal >= CAND_MAX)
        {
            break;
        }
        DWORD dwWanted = pdwDiffMCList[i];
        BYTE bW0 = TAKEBYTE(dwWanted, 0);
        BYTE bW1 = TAKEBYTE(dwWanted, 1);
        BYTE bW2 = TAKEBYTE(dwWanted, 2);
        BYTE bW3 = TAKEBYTE(dwWanted, 3);

        std::vector<WORD> vecHalf1;
        vecHalf1.reserve(65536);

        for (INT k0 = 0; k0 < 256; k0++)
        {
            BYTE bDiff0 = static_cast<BYTE>(g_invSbox[rgbGood[0] ^ (BYTE)k0]
                ^ g_invSbox[rgbFaulty[0] ^ (BYTE)k0]);
            if (bDiff0 != bW0)
            {
                continue;
            }
            for (INT k1 = 0; k1 < 256; k1++)
            {
                BYTE bDiff1 = static_cast<BYTE>(g_invSbox[rgbGood[1] ^ (BYTE)k1]
                    ^ g_invSbox[rgbFaulty[1] ^ (BYTE)k1]);
                if (bDiff1 == bW1)
                {
                    WORD wPair = static_cast<WORD>(((k1 << 8) & 0xFF00) | (k0 & 0x00FF));
                    vecHalf1.push_back(wPair);
                }
            }
        }

        std::vector<WORD> vecHalf2;
        vecHalf2.reserve(65536);

        for (INT k2 = 0; k2 < 256; k2++)
        {
            BYTE bDiff2 = static_cast<BYTE>(g_invSbox[rgbGood[2] ^ (BYTE)k2]
                ^ g_invSbox[rgbFaulty[2] ^ (BYTE)k2]);
            if (bDiff2 != bW2)
            {
                continue;
            }
            for (INT k3 = 0; k3 < 256; k3++)
            {
                BYTE bDiff3 = static_cast<BYTE>(g_invSbox[rgbGood[3] ^ (BYTE)k3]
                    ^ g_invSbox[rgbFaulty[3] ^ (BYTE)k3]);
                if (bDiff3 == bW3)
                {
                    WORD wPair = static_cast<WORD>(((k3 << 8) & 0xFF00) | (k2 & 0x00FF));
                    vecHalf2.push_back(wPair);
                }
            }
        }

        for (auto w12 : vecHalf1)
        {
            if (nCandTotal >= CAND_MAX)
            {
                break;
            }
            BYTE bK0 = static_cast<BYTE>(w12 & 0x00FF);
            BYTE bK1 = static_cast<BYTE>((w12 >> 8) & 0x00FF);

            for (auto w34 : vecHalf2)
            {
                if (nCandTotal >= CAND_MAX)
                {
                    break;
                }
                BYTE bK2 = static_cast<BYTE>(w34 & 0x00FF);
                BYTE bK3 = static_cast<BYTE>((w34 >> 8) & 0x00FF);

                DWORD dwCandidate =
                    ((DWORD)bK3 << 24) | ((DWORD)bK2 << 16)
                    | ((DWORD)bK1 << 8) | (DWORD)bK0;

                pdwCandidates[nCandTotal++] = dwCandidate;
            }
        }
    }
    return nCandTotal;
}

VOID R8FindCandidates(const PAIR* pPair,
    INT nRow8,
    INT nCol8,
    _Out_writes_all_(4 * CAND_MAX) DWORD(*padwCandidates)[CAND_MAX],
    _Out_writes_(4) INT anCandidatesLen[4])
{
    BYTE rgbTmp[4];
    ZeroMemory(rgbTmp, 4);

    DWORD dwDiffCol = 0;

    for (INT nCol9 = 0; nCol9 < 4; nCol9++)
    {
        DWORD adwDiffMC[DIFF_MC_MAX];
        INT nLen = R8GetDiffMC(nCol8, nCol9, dwDiffCol, adwDiffMC);
        anCandidatesLen[nCol9] = K10CandFromDiffMC(pPair, nCol9,
            adwDiffMC, nLen,
            padwCandidates[nCol9]);
    }
}
