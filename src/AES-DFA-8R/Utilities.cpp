#include "LocaleInitializer.hpp"
#include "Utilities.hpp"

#include <intrin.h>
#include <iostream>
#include <iomanip>
#include <string>

VOID PrintPairInfo(const PAIR* pPair)
{
    std::cerr << "    - Texte chiffré correct : ";
    for (INT i = 0; i < 16; i++)
    {
        std::cerr << std::hex << std::setw(2) << std::setfill('0') << static_cast<INT>(pPair->rgbCt[i]);
    }
    std::cerr << std::dec << "\n    - Texte chiffré fauté : ";
    for (INT i = 0; i < 16; i++)
    {
        std::cerr << std::hex << std::setw(2) << std::setfill('0') << static_cast<INT>(pPair->rgbFct[i]);
    }
    std::cerr << std::dec;

    if (pPair->nFaultPos >= 0)
    {
        std::cerr << "\n    - Pos. Faute = " << pPair->nFaultPos
            << " => ligne=" << (pPair->nFaultPos % 4)
            << ", col=" << (pPair->nFaultPos / 4);
    }
    else
    {
        std::cerr << "\n    - Position de faute inconnue";
    }
    std::cerr << std::endl;
}

INT BitLength(UINT64 ullValue)
{
    unsigned long idx;
    if (_BitScanReverse64(&idx, ullValue))
    {
        return static_cast<INT>(idx + 1);
    }
    return 0;
}

VOID PrintNumberCandidates(const INT anCandidatesLen[4], UINT64 ullNbCand)
{
    std::cerr << "Candidats diagonaux K10 : Diagonale 0 = " << anCandidatesLen[0]
        << ", Diagonale 1 = " << anCandidatesLen[1]
        << ", Diagonale 2 = " << anCandidatesLen[2]
        << ", Diagonale 3 = " << anCandidatesLen[3]
        << "\nTotal -> " << ullNbCand
        << " (2^" << BitLength(ullNbCand) << ")\n";
}

BYTE CharToNibble(CHAR c)
{
    if (c >= '0' && c <= '9') return static_cast<BYTE>(c - '0');
    if (c >= 'A' && c <= 'F') return static_cast<BYTE>(c - 'A' + 10);
    if (c >= 'a' && c <= 'f') return static_cast<BYTE>(c - 'a' + 10);
    return 255;
}

INT HexToBytes(_In_reads_(nHexLen) const CHAR* szHex,
    INT nHexLen,
    _Out_writes_(nByteArrayLen) BYTE* pbArray,
    INT nByteArrayLen)
{
    INT iHex = 0;
    INT iByte = 0;
    BOOL bHighNibble = TRUE;

    while ((iHex < nHexLen) && (iByte < nByteArrayLen))
    {
        BYTE nibble = CharToNibble(szHex[iHex++]);
        if (nibble == 255)
        {
            continue;
        }

        if (bHighNibble)
        {
            pbArray[iByte] = static_cast<BYTE>(nibble << 4);
        }
        else
        {
            pbArray[iByte] |= nibble;
            iByte++;
        }
        bHighNibble = !bHighNibble;
    }

    if (iByte == nByteArrayLen && bHighNibble)
    {
        return EXIT_SUCCESS;
    }

    if (iByte == nByteArrayLen && !bHighNibble)
    {
        return EXIT_SUCCESS;
    }

    if ((iByte == nByteArrayLen) && bHighNibble) return EXIT_SUCCESS;

    if (iByte == nByteArrayLen && !bHighNibble) {
        return EXIT_SUCCESS;
    }


    if (iByte < nByteArrayLen) return EXIT_FAILURE;
    if (!bHighNibble) return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

VOID PrintHex(_In_reads_(nLen) const BYTE* pbBuffer, INT nLen)
{
    std::ios_base::fmtflags oldFlags = std::cout.flags();
    char oldFill = std::cout.fill();

    for (INT i = 0; i < nLen; ++i)
    {
        std::cout << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(pbBuffer[i]);
    }

    std::cout.flags(oldFlags);
    std::cout.fill(oldFill);
    std::cout << std::dec << "\n";
}
