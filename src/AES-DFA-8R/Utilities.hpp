#pragma once

#include "DataStructures.hpp"

#include <cstdint>
#include <windows.h>

VOID PrintPairInfo(const PAIR* pPair);
INT  BitLength(UINT64 ullValue);
VOID PrintNumberCandidates(const INT anCandidatesLen[4], UINT64 ullNbCand);
BYTE CharToNibble(CHAR c);
INT  HexToBytes(_In_reads_(nHexLen) const CHAR* szHex,
    INT nHexLen,
    _Out_writes_(nByteArrayLen) BYTE* pbArray,
    INT nByteArrayLen);
VOID PrintHex(_In_reads_(nLen) const BYTE* pbBuffer, INT nLen);
