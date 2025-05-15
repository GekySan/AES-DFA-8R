#pragma once

#include "AesData.hpp"
#include "Constants.hpp"
#include "DataStructures.hpp"

INT  GetDiffMC(INT nRow, const INT* panFaultList, INT nFaultListLen,
    _Out_writes_(DIFF_MC_MAX) DWORD* pdwListDiff);

INT  R8GetDiffMC(INT nCol8, INT nCol9, DWORD dwDiffCol,
    _Out_writes_(DIFF_MC_MAX) DWORD* pdwDiffMCList);

INT  K10CandFromDiffMC(const PAIR* pPair, INT nCol,
    const DWORD* pdwDiffMCList, INT nDiffMCListLen,
    _Out_writes_(CAND_MAX) DWORD* pdwCandidates);

VOID R8FindCandidates(const PAIR* pPair, INT nRow8, INT nCol8,
    _Out_writes_all_(4 * CAND_MAX) DWORD(*padwCandidates)[CAND_MAX],
    _Out_writes_(4) INT anCandidatesLen[4]);
