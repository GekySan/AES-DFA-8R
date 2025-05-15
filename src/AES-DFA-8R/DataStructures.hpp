#pragma once

#include <windows.h>

typedef struct _PAIR
{
    BYTE rgbCt[16];      // Ciphertext «bon»
    BYTE rgbFct[16];     // Ciphertext «faute»
    INT  nFaultPos;      // Position du fault dans l'état AES (0..15)
}
PAIR, * PPAIR;

typedef struct _KNOWN_PT
{
    BYTE rgbPt[16];  // plaintext
    BYTE rgbCt[16];  // ciphertext
    BOOL bIsSome;    // TRUE si on dispose d'une paire connue, FALSE sinon
}
KNOWN_PT, * PKNOWN_PT;
