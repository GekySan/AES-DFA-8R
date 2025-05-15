#pragma once

constexpr int DIFF_MC_MAX	= 1 << 10;
constexpr int CAND_MAX		= 1 << 10;
constexpr int PAIRS_MAX		= 1;
constexpr int KEYS_MAX		= 1 << 10;

#define XTIME(b)        ((static_cast<BYTE>((b) << 1)) ^ (static_cast<BYTE>((b) >> 7) * 0x1B))
#define BYTES_TO_WORD(a)   (*(reinterpret_cast<const DWORD*>(a)))
#define TAKEBYTE(w,n)      static_cast<BYTE>(( (w) >> (8*(n)) ) & 0xFF)
