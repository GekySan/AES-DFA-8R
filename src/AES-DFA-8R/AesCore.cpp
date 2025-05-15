#include "AesCore.hpp"

#include <cstring>

VOID MixColumn(_Inout_updates_bytes_(4) BYTE a[4])
{
    BYTE bT = a[0] ^ a[1] ^ a[2] ^ a[3];
    BYTE bU = a[0];
    BYTE bV;

    bV = static_cast<BYTE>(a[0] ^ a[1]);
    bV = XTIME(bV);
    a[0] ^= bV ^ bT;

    bV = static_cast<BYTE>(a[1] ^ a[2]);
    bV = XTIME(bV);
    a[1] ^= bV ^ bT;

    bV = static_cast<BYTE>(a[2] ^ a[3]);
    bV = XTIME(bV);
    a[2] ^= bV ^ bT;

    bV = static_cast<BYTE>(a[3] ^ bU);
    bV = XTIME(bV);
    a[3] ^= bV ^ bT;
}

VOID K9FromK10(_In_reads_bytes_(16) const BYTE* pbSubKey10,
    _Out_writes_bytes_(16) BYTE* pbSubKey9)
{
    pbSubKey9[12] = static_cast<BYTE>(pbSubKey10[12] ^ pbSubKey10[8]);
    pbSubKey9[13] = static_cast<BYTE>(pbSubKey10[13] ^ pbSubKey10[9]);
    pbSubKey9[14] = static_cast<BYTE>(pbSubKey10[14] ^ pbSubKey10[10]);
    pbSubKey9[15] = static_cast<BYTE>(pbSubKey10[15] ^ pbSubKey10[11]);

    pbSubKey9[8] = static_cast<BYTE>(pbSubKey10[8] ^ pbSubKey10[4]);
    pbSubKey9[9] = static_cast<BYTE>(pbSubKey10[9] ^ pbSubKey10[5]);
    pbSubKey9[10] = static_cast<BYTE>(pbSubKey10[10] ^ pbSubKey10[6]);
    pbSubKey9[11] = static_cast<BYTE>(pbSubKey10[11] ^ pbSubKey10[7]);

    pbSubKey9[4] = static_cast<BYTE>(pbSubKey10[4] ^ pbSubKey10[0]);
    pbSubKey9[5] = static_cast<BYTE>(pbSubKey10[5] ^ pbSubKey10[1]);
    pbSubKey9[6] = static_cast<BYTE>(pbSubKey10[6] ^ pbSubKey10[2]);
    pbSubKey9[7] = static_cast<BYTE>(pbSubKey10[7] ^ pbSubKey10[3]);

    pbSubKey9[0] = static_cast<BYTE>(pbSubKey10[0] ^ g_sbox[pbSubKey9[13]] ^ g_rcon[9]);
    pbSubKey9[1] = static_cast<BYTE>(pbSubKey10[1] ^ g_sbox[pbSubKey9[14]]);
    pbSubKey9[2] = static_cast<BYTE>(pbSubKey10[2] ^ g_sbox[pbSubKey9[15]]);
    pbSubKey9[3] = static_cast<BYTE>(pbSubKey10[3] ^ g_sbox[pbSubKey9[12]]);
}

VOID ReverseKeyExpansion(_In_reads_bytes_(16) const BYTE* pbSubKey10,
    _Out_writes_bytes_(176) BYTE* pbAllSubKeys)
{
    CopyMemory(pbAllSubKeys + 160, pbSubKey10, 16);

    for (INT r = 9; r >= 0; --r)
    {
        BYTE* pbCurrent = pbAllSubKeys + r * 16;
        const BYTE* pbNext = pbAllSubKeys + (r + 1) * 16;

        pbCurrent[12] = static_cast<BYTE>(pbNext[12] ^ pbNext[8]);
        pbCurrent[13] = static_cast<BYTE>(pbNext[13] ^ pbNext[9]);
        pbCurrent[14] = static_cast<BYTE>(pbNext[14] ^ pbNext[10]);
        pbCurrent[15] = static_cast<BYTE>(pbNext[15] ^ pbNext[11]);

        pbCurrent[8] = static_cast<BYTE>(pbNext[8] ^ pbNext[4]);
        pbCurrent[9] = static_cast<BYTE>(pbNext[9] ^ pbNext[5]);
        pbCurrent[10] = static_cast<BYTE>(pbNext[10] ^ pbNext[6]);
        pbCurrent[11] = static_cast<BYTE>(pbNext[11] ^ pbNext[7]);

        pbCurrent[4] = static_cast<BYTE>(pbNext[4] ^ pbNext[0]);
        pbCurrent[5] = static_cast<BYTE>(pbNext[5] ^ pbNext[1]);
        pbCurrent[6] = static_cast<BYTE>(pbNext[6] ^ pbNext[2]);
        pbCurrent[7] = static_cast<BYTE>(pbNext[7] ^ pbNext[3]);

        pbCurrent[0] = static_cast<BYTE>(pbNext[0] ^ g_sbox[pbCurrent[13]] ^ g_rcon[r]);
        pbCurrent[1] = static_cast<BYTE>(pbNext[1] ^ g_sbox[pbCurrent[14]]);
        pbCurrent[2] = static_cast<BYTE>(pbNext[2] ^ g_sbox[pbCurrent[15]]);
        pbCurrent[3] = static_cast<BYTE>(pbNext[3] ^ g_sbox[pbCurrent[12]]);
    }
}

VOID EncryptAES(_In_reads_bytes_(16)  const BYTE* pbInput,
    _Out_writes_bytes_(16) BYTE* pbOutput,
    _In_reads_bytes_(176) const BYTE* pbAllSubKeys)
{
    __m128i block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pbInput));
    __m128i key0 = _mm_load_si128(reinterpret_cast<const __m128i*>(pbAllSubKeys + 0));
    block = _mm_xor_si128(block, key0);

    for (INT i = 1; i < 10; i++)
    {
        __m128i keyi = _mm_load_si128(reinterpret_cast<const __m128i*>(pbAllSubKeys + i * 16));
        block = _mm_aesenc_si128(block, keyi);
    }

    __m128i keyLast = _mm_load_si128(reinterpret_cast<const __m128i*>(pbAllSubKeys + 160));
    block = _mm_aesenclast_si128(block, keyLast);

    _mm_storeu_si128(reinterpret_cast<__m128i*>(pbOutput), block);
}
