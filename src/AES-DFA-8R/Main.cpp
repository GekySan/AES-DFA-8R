#include "AesData.hpp"
#include "Constants.hpp"
#include "DataStructures.hpp"
#include "KeyRecovery.hpp"
#include "LocaleInitializer.hpp"
#include "Utilities.hpp"

#include <array>
#include <charconv>
#include <cstdint>
#include <format> 
#include <iostream>
#include <string>
#include <string_view>
#include <vector>
#include <windows.h>

static bool read_hex_block(std::string_view prompt,
    std::array<char, 33>& out32)
{
    std::cout << prompt;
    std::string buffer;
    std::getline(std::cin, buffer);

    if (buffer.size() != 32 ||
        buffer.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
    {
        std::cerr << "Chaîne hexadécimale invalide – 32 nibbles attendus.\n";
        return false;
    }
    std::copy(buffer.begin(), buffer.end(), out32.begin());
    out32[32] = '\0';
    return true;
}

static bool read_fault_pos(int& n)
{
    std::cout << "Position de la faute (0-15) ? ";
    std::string buf;
    std::getline(std::cin, buf);
    auto [p, ec] = std::from_chars(buf.data(), buf.data() + buf.size(), n);
    if (ec != std::errc{} || n < 0 || n > 15)
    {
        std::cerr << "Nombre invalide.\n";
        return false;
    }
    std::cout << std::format("-> t = 113 + {} = {}\n", n, 113 + n);
    return true;
}

int main()
{
    PAIR  aPairs[PAIRS_MAX]{};
    KNOWN_PT stKnownPt{};

    std::array<char, 33> szPlain{}, szCTgood{}, szCTfault{};

    if (!read_hex_block("Texte clair  (32 hex) : ", szPlain) ||
        !read_hex_block("Texte chiffré (32 hex) : ", szCTgood) ||
        !read_hex_block("Texte chiffré fauté (32 hex) : ", szCTfault))
        return EXIT_FAILURE;

    int nFaultPos{};
    if (!read_fault_pos(nFaultPos))
        return EXIT_FAILURE;

    if (HexToBytes(szCTgood.data(), 32, aPairs[0].rgbCt, 16) ||
        HexToBytes(szCTfault.data(), 32, aPairs[0].rgbFct, 16) ||
        HexToBytes(szPlain.data(), 32, stKnownPt.rgbPt, 16) ||
        HexToBytes(szCTgood.data(), 32, stKnownPt.rgbCt, 16))
    {
        std::cerr << "Erreur de conversion hexadécimale.\n";
        return EXIT_FAILURE;
    }
    aPairs[0].nFaultPos = nFaultPos;
    stKnownPt.bIsSome = TRUE; // 1

    std::vector<std::array<BYTE, 16>> abMasterKeys(KEYS_MAX);
    SecureZeroMemory(abMasterKeys.data(),
        abMasterKeys.size() * sizeof(abMasterKeys[0]));

    const INT nKeysFound = R8KeyRecovery(
        aPairs,
        PAIRS_MAX,
        &stKnownPt,
        reinterpret_cast<BYTE(*)[16]>(abMasterKeys.data()));

    if (nKeysFound == 0)
    {
        std::cout << "Aucune clé trouvée.\n";
    }
    else
    {
        std::cout << std::format("\n――――――――――――――――――― CLÉ(S) TROUVÉE(S) ({}) ―――――――――――――――――――\n", nKeysFound);
        for (INT i = 0; i < nKeysFound; ++i)
            PrintHex(abMasterKeys[i].data(), 16);
        std::cout << std::format("――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――\n", nKeysFound);
    }
    return EXIT_SUCCESS;
}
