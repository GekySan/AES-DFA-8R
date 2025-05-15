#pragma once

#include "AesData.hpp" 
#include "Constants.hpp"

#include <immintrin.h>
#include <windows.h>

VOID  MixColumn(_Inout_updates_bytes_(4) BYTE a[4]);

VOID  K9FromK10(_In_reads_bytes_(16) const BYTE* pbSubKey10,
    _Out_writes_bytes_(16) BYTE* pbSubKey9);

VOID  ReverseKeyExpansion(_In_reads_bytes_(16) const BYTE* pbSubKey10,
    _Out_writes_bytes_(176) BYTE* pbAllSubKeys);

VOID  EncryptAES(_In_reads_bytes_(16)  const BYTE* pbInput,
    _Out_writes_bytes_(16) BYTE* pbOutput,
    _In_reads_bytes_(176) const BYTE* pbAllSubKeys);
