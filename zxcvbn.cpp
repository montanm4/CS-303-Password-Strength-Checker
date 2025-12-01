/**********************************************************************************
 * C++ implementation of the zxcvbn password strength estimation method.
 * Converted from C implementation
 * Copyright (c) 2015-2017 Tony Evans
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 **********************************************************************************/

#include <zxcvbn.h>
#include <cctype>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <cfloat>
#include <cstdio>
#include <vector>
#include <memory>
#include <algorithm>
#include <string>

#ifdef USE_DICT_FILE
#include <fstream>
#endif

#ifdef _WIN32
#include "stdafx.h"
#endif

// Constants
constexpr int MIN_SEQUENCE_LEN = 3;

#ifndef ZXCVBN_DETAIL_LEN
constexpr int ZXCVBN_DETAIL_LEN = 100;
#endif

constexpr int MIN_YEAR = 1901;
constexpr int MAX_YEAR = 2050;
constexpr int MIN_SPATIAL_LEN = 3;
constexpr int MIN_REPEAT_LEN = 2;
constexpr double MULTI_END_ADDITION = 1.0;
constexpr double MULTI_MID_ADDITION = 1.75;
constexpr int MAX_SEQUENCE_STEP = 5;

/*################################################################################*
 * Utility Functions
 *################################################################################*/

namespace {

/**
 * Binomial coefficient calculation
 */
double nCk(int n, int k) {
    if (k > n) return 0.0;
    if (!k) return 1.0;
    
    double r = 1.0;
    for (int d = 1; d <= k; ++d) {
        r *= n--;
        r /= d;
    }
    return r;
}

/**
 * Binary search for a character in a string
 */
const uint8_t* CharBinSearch(uint8_t ch, const uint8_t* ents, unsigned int numEnts, unsigned int sizeEnt) {
    while (numEnts > 0) {
        const uint8_t* mid = ents + (numEnts >> 1) * sizeEnt;
        int dif = ch - *mid;
        
        if (!dif) return mid;
        
        if (dif > 0) {
            ents = mid + sizeEnt;
            --numEnts;
        }
        numEnts /= 2;
    }
    return nullptr;
}

/**
 * Calculate potential number of different characters
 */
int Cardinality(const uint8_t* str, int len) {
    int card = 0;
    int types = 0;
    
    while (len > 0) {
        int c = *str++ & 0xFF;
        if (!c) break;
        
        if (std::islower(c))      types |= 1;
        else if (std::isupper(c)) types |= 2;
        else if (std::isdigit(c)) types |= 4;
        else if (c <= 0x7F)       types |= 8;
        else                      types |= 16;
        --len;
    }
    
    if (types & 1)  card += 26;
    if (types & 2)  card += 26;
    if (types & 4)  card += 10;
    if (types & 8)  card += 33;
    if (types & 16) card += 100;
    
    return card;
}

/**
 * Allocate and initialize a ZxcMatch_t struct
 */
ZxcMatch_t* AllocMatch() {
    auto* p = new ZxcMatch_t();
    std::memset(p, 0, sizeof(ZxcMatch_t));
    return p;
}

/**
 * Add new match to sorted linked list
 */
void AddResult(ZxcMatch_t** headRef, ZxcMatch_t* nu, int maxLen) {
    // Adjust entropy based on position
    if (nu->Begin) {
        if (nu->Length >= maxLen)
            nu->MltEnpy = nu->Entrpy + MULTI_END_ADDITION * std::log(2.0);
        else
            nu->MltEnpy = nu->Entrpy + MULTI_MID_ADDITION * std::log(2.0);
    } else {
        nu->MltEnpy = nu->Entrpy;
    }

    // Find correct insert point
    while (*headRef && ((*headRef)->Length < nu->Length))
        headRef = &((*headRef)->Next);

    // Add or replace entry
    if (*headRef && ((*headRef)->Length == nu->Length)) {
        if ((*headRef)->MltEnpy <= nu->MltEnpy) {
            delete nu;
        } else {
            nu->Next = (*headRef)->Next;
            delete *headRef;
            *headRef = nu;
        }
    } else {
        nu->Next = *headRef;
        *headRef = nu;
    }
}

/**
 * Check for repeated matches and add them
 */
void AddMatchRepeats(ZxcMatch_t** result, ZxcMatch_t* match, const uint8_t* passwd, int maxLen) {
    int len = match->Length;
    const uint8_t* rpt = passwd + len;
    int repeatCount = 2;

    while (maxLen >= (len * repeatCount)) {
        if (std::strncmp(reinterpret_cast<const char*>(passwd), 
                        reinterpret_cast<const char*>(rpt), len) == 0) {
            auto* p = AllocMatch();
            p->Entrpy = match->Entrpy + std::log(repeatCount);
            p->Type = static_cast<ZxcTypeMatch_t>(match->Type + MULTIPLE_MATCH);
            p->Length = len * repeatCount;
            p->Begin = match->Begin;
            AddResult(result, p, maxLen);
        } else {
            break;
        }
        ++repeatCount;
        rpt += len;
    }
}

} // anonymous namespace

/*################################################################################*
 * Dictionary Matching Code
 *################################################################################*/

#ifdef USE_DICT_FILE

using FileHandle = std::ifstream;

inline void MyOpenFile(FileHandle& f, const char* name) {
    f.open(name, std::ifstream::in | std::ifstream::binary);
}

inline bool MyReadFile(FileHandle& f, void* buf, unsigned int num) {
    return static_cast<bool>(f.read(static_cast<char*>(buf), num));
}

inline void MyCloseFile(FileHandle& f) {
    f.close();
}

#include "dict-crc.h"

constexpr size_t MAX_DICT_FILE_SIZE = 100 + WORD_FILE_SIZE;
constexpr uint64_t CHK_INIT = 0xffffffffffffffffULL;

static const uint64_t CrcTable[16] = {
    0x0000000000000000ULL, 0x7d08ff3b88be6f81ULL, 0xfa11fe77117cdf02ULL, 0x8719014c99c2b083ULL,
    0xdf7adabd7a6e2d6fULL, 0xa2722586f2d042eeULL, 0x256b24ca6b12f26dULL, 0x5863dbf1e3ac9decULL,
    0x95ac9329ac4bc9b5ULL, 0xe8a46c1224f5a634ULL, 0x6fbd6d5ebd3716b7ULL, 0x12b5926535897936ULL,
    0x4ad64994d625e4daULL, 0x37deb6af5e9b8b5bULL, 0xb0c7b7e3c7593bd8ULL, 0xcdcf48d84fe75459ULL
};

constexpr unsigned int MAGIC = 'z' + ('x' << 8) + ('c' << 16) + ('v' << 24);

static unsigned int NumNodes, NumChildLocs, NumRanks, NumWordEnd, NumChildMaps;
static unsigned int SizeChildMapEntry, NumLargeCounts, NumSmallCounts, SizeCharSet;
static unsigned int* DictNodes = nullptr;
static uint8_t* WordEndBits = nullptr;
static unsigned int* ChildLocs = nullptr;
static unsigned short* Ranks = nullptr;
static uint8_t* ChildMap = nullptr;
static uint8_t* EndCountLge = nullptr;
static uint8_t* EndCountSml = nullptr;
static char* CharSet = nullptr;

/**
 * Calculate CRC-64
 */
uint64_t CalcCrc64(uint64_t crc, const void* v, unsigned int len) {
    const auto* data = static_cast<const uint8_t*>(v);
    while (len--) {
        crc = CrcTable[(crc ^ (*data >> 0)) & 0x0f] ^ (crc >> 4);
        crc = CrcTable[(crc ^ (*data >> 4)) & 0x0f] ^ (crc >> 4);
        ++data;
    }
    return crc;
}

/**
 * Initialize dictionary from file
 */
int ZxcvbnInit(const char* filename) {
    if (DictNodes) return 1;
    
    FileHandle f;
    MyOpenFile(f, filename);
    
    if (!f) return 0;
    
    uint64_t crc = CHK_INIT;
    unsigned int i, dictSize;

    // Read and validate magic number and header
    if (!MyReadFile(f, &i, sizeof(i))) i = 0;
    if (!MyReadFile(f, &NumNodes, sizeof(NumNodes))) i = 0;
    if (!MyReadFile(f, &NumChildLocs, sizeof(NumChildLocs))) i = 0;
    if (!MyReadFile(f, &NumRanks, sizeof(NumRanks))) i = 0;
    if (!MyReadFile(f, &NumWordEnd, sizeof(NumWordEnd))) i = 0;
    if (!MyReadFile(f, &NumChildMaps, sizeof(NumChildMaps))) i = 0;
    if (!MyReadFile(f, &SizeChildMapEntry, sizeof(SizeChildMapEntry))) i = 0;
    if (!MyReadFile(f, &NumLargeCounts, sizeof(NumLargeCounts))) i = 0;
    if (!MyReadFile(f, &NumSmallCounts, sizeof(NumSmallCounts))) i = 0;
    if (!MyReadFile(f, &SizeCharSet, sizeof(SizeCharSet))) i = 0;

    // Validate header data
    if (NumNodes >= (1 << 17)) i = 1;
    if (NumChildLocs >= (1 << BITS_CHILD_MAP_INDEX)) i = 2;
    if (NumChildMaps >= (1 << BITS_CHILD_PATT_INDEX)) i = 3;
    if ((SizeChildMapEntry * 8) < SizeCharSet) i = 4;
    if (NumLargeCounts >= (1 << 9)) i = 5;
    if (NumSmallCounts != NumNodes) i = 6;

    if (i != MAGIC) {
        MyCloseFile(f);
        return 0;
    }

    // Calculate CRC of header
    crc = CalcCrc64(crc, &i, sizeof(i));
    crc = CalcCrc64(crc, &NumNodes, sizeof(NumNodes));
    crc = CalcCrc64(crc, &NumChildLocs, sizeof(NumChildLocs));
    crc = CalcCrc64(crc, &NumRanks, sizeof(NumRanks));
    crc = CalcCrc64(crc, &NumWordEnd, sizeof(NumWordEnd));
    crc = CalcCrc64(crc, &NumChildMaps, sizeof(NumChildMaps));
    crc = CalcCrc64(crc, &SizeChildMapEntry, sizeof(SizeChildMapEntry));
    crc = CalcCrc64(crc, &NumLargeCounts, sizeof(NumLargeCounts));
    crc = CalcCrc64(crc, &NumSmallCounts, sizeof(NumSmallCounts));
    crc = CalcCrc64(crc, &SizeCharSet, sizeof(SizeCharSet));

    // Allocate and read dictionary data
    dictSize = NumNodes * sizeof(*DictNodes) + NumChildLocs * sizeof(*ChildLocs) +
               NumRanks * sizeof(*Ranks) + NumWordEnd + NumChildMaps * SizeChildMapEntry +
               NumLargeCounts + NumSmallCounts + SizeCharSet;

    if (dictSize < MAX_DICT_FILE_SIZE) {
        DictNodes = new unsigned int[dictSize / sizeof(unsigned int) + 1];
        if (!MyReadFile(f, DictNodes, dictSize)) {
            delete[] DictNodes;
            DictNodes = nullptr;
        }
    }

    MyCloseFile(f);

    if (!DictNodes) return 0;

    // Verify CRC
    crc = CalcCrc64(crc, DictNodes, dictSize);
    if (std::memcmp(&crc, WordCheck, sizeof(crc))) {
        delete[] DictNodes;
        DictNodes = nullptr;
        return 0;
    }

    // Set up pointers to dictionary sections
    ChildLocs = DictNodes + NumNodes;
    Ranks = reinterpret_cast<unsigned short*>(ChildLocs + NumChildLocs);
    WordEndBits = reinterpret_cast<uint8_t*>(Ranks + NumRanks);
    ChildMap = WordEndBits + NumWordEnd;
    EndCountLge = ChildMap + NumChildMaps * SizeChildMapEntry;
    EndCountSml = EndCountLge + NumLargeCounts;
    CharSet = reinterpret_cast<char*>(EndCountSml + NumSmallCounts);
    CharSet[SizeCharSet] = 0;

    return 1;
}

/**
 * Free dictionary data
 */
void ZxcvbnUnInit() {
    if (DictNodes) {
        delete[] DictNodes;
        DictNodes = nullptr;
    }
}

#else
#include "dict-src.h"
#endif

// Leet conversion strings
static const uint8_t L33TChr[] = "abcegilostxz";
static const uint8_t L33TCnv[] = "!i $s %x (c +t 0o 1il2z 3e 4a 5s 6g 7lt8b 9g <c @a [c {c |il";
constexpr int LEET_NORM_MAP_SIZE = 3;

// Struct definitions
struct DictMatchInfo {
    int Rank;
    int Caps;
    int Lower;
    int NumLeet;
    uint8_t Leeted[sizeof(L33TChr)];
    uint8_t UnLeet[sizeof(L33TChr)];
};

struct DictWork {
    uint32_t StartLoc;
    int Ordinal;
    int PwdLength;
    int Begin;
    int Caps;
    int Lower;
    int NumPossChrs;
    uint8_t Leeted[sizeof(L33TChr)];
    uint8_t UnLeet[sizeof(L33TChr)];
    uint8_t LeetCnv[sizeof(L33TCnv) / LEET_NORM_MAP_SIZE + 1];
    uint8_t First;
    uint8_t PossChars[CHARSET_SIZE];
};

namespace {

/**
 * List possible characters from map
 */
int ListPossibleChars(uint8_t* list, const uint8_t* map) {
    int len = 0;
    unsigned int k = 0;
    
    for (unsigned int i = 0; i < SizeChildMapEntry; ++i, ++map) {
        if (!*map) {
            k += 8;
            continue;
        }
        for (unsigned int j = 0; j < 8; ++j) {
            if (*map & (1 << j)) {
                *list++ = CharSet[k];
                ++len;
            }
            ++k;
        }
    }
    *list = 0;
    return len;
}

/**
 * Increment leet character count
 */
void AddLeetChr(uint8_t c, int isLeet, uint8_t* leeted, uint8_t* unLeet) {
    const uint8_t* p = CharBinSearch(c, L33TChr, sizeof(L33TChr) - 1, 1);
    if (p) {
        int i = p - L33TChr;
        if (isLeet > 0) {
            leeted[i] += 1;
        } else if (isLeet < 0) {
            leeted[i] += 1;
            unLeet[i] -= 1;
        } else {
            unLeet[i] += 1;
        }
    }
}

/**
 * Calculate dictionary match entropy
 */
void DictionaryEntropy(ZxcMatch_t* m, DictMatchInfo* extra, const uint8_t* pwd) {
    double e = 0.0;
    
    // Add entropy for uppercase letters
    if (extra->Caps) {
        if (extra->Caps == m->Length) {
            e += std::log(2.0);
        } else if ((extra->Caps == 1) && 
                   (std::isupper(*pwd) || std::isupper(pwd[m->Length - 1]))) {
            e += std::log(2.0);
        } else {
            int up = extra->Caps;
            int lo = extra->Lower;
            int i = std::min(up, lo);
            
            for (lo += up; i >= 0; --i)
                e += nCk(lo, i);
            if (e > 0.0)
                e = std::log(e);
        }
    }
    
    // Add entropy for leet substitutions
    if (extra->NumLeet) {
        double d = 0.0;
        for (int i = sizeof(extra->Leeted) - 1; i >= 0; --i) {
            int sb = extra->Leeted[i];
            if (sb) {
                int un = extra->UnLeet[i];
                int j = m->Length - extra->NumLeet;
                if ((j >= 0) && (un > j))
                    un = j;
                j = std::min(sb, un);
                for (un += sb; j >= 0; --j) {
                    d += nCk(un, j);
                }
            }
        }
        if (d > 0.0)
            d = std::log(d);
        if (d < std::log(2.0))
            d = std::log(2.0);
        e += d;
    }
    
    // Add entropy from word rank
    e += std::log(static_cast<double>(extra->Rank));
    m->Entrpy = e;
}

// Forward declaration
void DoDictMatch(const uint8_t* passwd, int start, int maxLen, DictWork* wrk,
                 ZxcMatch_t** result, DictMatchInfo* extra, int lev);

/**
 * Perform dictionary matching
 */
void DictionaryMatch(ZxcMatch_t** result, const uint8_t* passwd, int start, int maxLen) {
    DictWork wrk{};
    DictMatchInfo extra{};
    
    wrk.Ordinal = 1;
    wrk.StartLoc = ROOT_NODE_LOC;
    wrk.Begin = start;
    DoDictMatch(passwd + start, 0, maxLen, &wrk, result, &extra, 0);
}

/**
 * Match user-provided dictionary words
 */
void UserMatch(ZxcMatch_t** result, const char* words[], const uint8_t* passwd, 
               int start, int maxLen) {
    if (!words) return;
    
    passwd += start;
    for (int rank = 0; words[rank]; ++rank) {
        DictMatchInfo extra{};
        uint8_t leetChr[sizeof(L33TCnv) / LEET_NORM_MAP_SIZE + 1]{};
        uint8_t tempLeet[3];
        int len = 0;
        int caps = 0;
        int lowers = 0;
        int leets = 0;
        const auto* wrd = reinterpret_cast<const uint8_t*>(words[rank]);
        const uint8_t* pwd = passwd;
        
        while (*wrd) {
            const uint8_t* q;
            uint8_t d = std::tolower(*wrd++);
            uint8_t c = *pwd++;
            
            if (std::isupper(c)) {
                c = std::tolower(c);
                ++caps;
            } else if (std::islower(c)) {
                ++lowers;
            }
            
            // Check for leet conversion
            q = CharBinSearch(c, L33TCnv, sizeof(L33TCnv) / LEET_NORM_MAP_SIZE, LEET_NORM_MAP_SIZE);
            if (q) {
                unsigned int i = (q - L33TCnv) / LEET_NORM_MAP_SIZE;
                if (leetChr[i]) {
                    tempLeet[0] = c;
                    tempLeet[1] = leetChr[i];
                    tempLeet[2] = 0;
                    q = tempLeet;
                }
                
                c = d + 1;
                for (unsigned int j = 0; (*q > ' ') && (j < LEET_NORM_MAP_SIZE); ++j, ++q) {
                    if (d == *q) {
                        c = d;
                        if (i) {
                            leetChr[i] = c;
                            AddLeetChr(c, 1, extra.Leeted, extra.UnLeet);
                            ++leets;
                        }
                        break;
                    }
                }
                if (c != d) {
                    len = 0;
                    break;
                }
            } else if (c == d) {
                if (CharBinSearch(c, L33TChr, sizeof(L33TChr) - 1, 1)) {
                    AddLeetChr(c, 0, extra.Leeted, extra.UnLeet);
                }
            } else {
                len = 0;
                break;
            }
            
            if (++len > maxLen) {
                len = 0;
                break;
            }
        }
        
        if (len) {
            auto* p = AllocMatch();
            p->Type = leets ? USER_LEET_MATCH : USER_MATCH;
            p->Length = len;
            p->Begin = start;
            
            extra.Caps = caps;
            extra.Lower = lowers;
            extra.NumLeet = leets;
            extra.Rank = rank + 1;
            DictionaryEntropy(p, &extra, passwd);
            AddMatchRepeats(result, p, passwd, maxLen);
            AddResult(result, p, maxLen);
        }
    }
}

} // anonymous namespace

/*################################################################################*
 * Spatial Matching Code (Keyboard Patterns)
 *################################################################################*/

struct Keyboard {
    const uint8_t* Keys;
    const uint8_t* Shifts;
    int NumKeys;
    int NumNear;
    int NumShift;
    int NumBlank;
};

struct SpatialMatchInfo {
    int Keyb;
    int Turns;
    int Shifts;
};

// Shift mappings
static const uint8_t UK_Shift[] = "!1\"2$4%5&7(9)0*8:;<,>.?/@'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz^6_-{[|\\}]~#\2433\2444\254`";
static const uint8_t US_Shift[] = "!1\"'#3$4%5&7(9)0*8:;<,>.?/@2AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz^6_-{[|\\}]~`";

// Keyboard layouts (data tables remain the same)
static const uint8_t UK_Qwerty[48 * 7] = {
    '#', '\'',']',   0,   0,   0,   0,    '\'',';', '[', ']', '#',   0, '/',
    ',', 'm', 'k', 'l', '.',   0,   0,    '-', '0',   0,   0, '=', '[', 'p',
    '.', ',', 'l', ';', '/',   0,   0,    '/', '.', ';', '\'',  0,   0,   0,
    '0', '9',   0,   0, '-', 'p', 'o',    '1', '`',   0,   0, '2', 'q',   0,
    '2', '1',   0,   0, '3', 'w', 'q',    '3', '2',   0,   0, '4', 'e', 'w',
    '4', '3',   0,   0, '5', 'r', 'e',    '5', '4',   0,   0, '6', 't', 'r',
    '6', '5',   0,   0, '7', 'y', 't',    '7', '6',   0,   0, '8', 'u', 'y',
    '8', '7',   0,   0, '9', 'i', 'u',    '9', '8',   0,   0, '0', 'o', 'i',
    ';', 'l', 'p', '[','\'', '/', '.',    '=', '-',   0,   0,   0, ']', '[',
    '[', 'p', '-', '=', ']', '\'',';',    '\\',  0,   0, 'a', 'z',   0,   0,
    ']', '[', '=',   0,   0, '#','\'',    '`',   0,   0,   0, '1',   0,   0,
    'a',   0, 'q', 'w', 's', 'z','\\',    'b', 'v', 'g', 'h', 'n',   0,   0,
    'c', 'x', 'd', 'f', 'v',   0,   0,    'd', 's', 'e', 'r', 'f', 'c', 'x',
    'e', 'w', '3', '4', 'r', 'd', 's',    'f', 'd', 'r', 't', 'g', 'v', 'c',
    'g', 'f', 't', 'y', 'h', 'b', 'v',    'h', 'g', 'y', 'u', 'j', 'n', 'b',
    'i', 'u', '8', '9', 'o', 'k', 'j',    'j', 'h', 'u', 'i', 'k', 'm', 'n',
    'k', 'j', 'i', 'o', 'l', ',', 'm',    'l', 'k', 'o', 'p', ';', '.', ',',
    'm', 'n', 'j', 'k', ',',   0,   0,    'n', 'b', 'h', 'j', 'm',   0,   0,
    'o', 'i', '9', '0', 'p', 'l', 'k',    'p', 'o', '0', '-', '[', ';', 'l',
    'q',   0, '1', '2', 'w', 'a',   0,    'r', 'e', '4', '5', 't', 'f', 'd',
    's', 'a', 'w', 'e', 'd', 'x', 'z',    't', 'r', '5', '6', 'y', 'g', 'f',
    'u', 'y', '7', '8', 'i', 'j', 'h',    'v', 'c', 'f', 'g', 'b',   0,   0,
    'w', 'q', '2', '3', 'e', 's', 'a',    'x', 'z', 's', 'd', 'c',   0,   0,
    'y', 't', '6', '7', 'u', 'h', 'g',    'z', '\\','a', 's', 'x',   0,   0
};

static const uint8_t US_Qwerty[47 * 7] = {
    '\'',';', '[', ']',   0,   0, '/',    ',', 'm', 'k', 'l', '.',   0,   0,
    '-', '0',   0,   0, '=', '[', 'p',    '.', ',', 'l', ';', '/',   0,   0,
    '/', '.', ';','\'',   0,   0,   0,    '0', '9',   0,   0, '-', 'p', 'o',
    '1', '`',   0,   0, '2', 'q',   0,    '2', '1',   0,   0, '3', 'w', 'q',
    '3', '2',   0,   0, '4', 'e', 'w',    '4', '3',   0,   0, '5', 'r', 'e',
    '5', '4',   0,   0, '6', 't', 'r',    '6', '5',   0,   0, '7', 'y', 't',
    '7', '6',   0,   0, '8', 'u', 'y',    '8', '7',   0,   0, '9', 'i', 'u',
    '9', '8',   0,   0, '0', 'o', 'i',    ';', 'l', 'p', '[','\'', '/', '.',
    '=', '-',   0,   0,   0, ']', '[',    '[', 'p', '-', '=', ']','\'', ';',
    '\\',']',   0,   0,   0,   0,   0,    ']', '[', '=',   0,'\\',   0,'\'',
    '`',   0,   0,   0, '1',   0,   0,    'a',   0, 'q', 'w', 's', 'z',   0,
    'b', 'v', 'g', 'h', 'n',   0,   0,    'c', 'x', 'd', 'f', 'v',   0,   0,
    'd', 's', 'e', 'r', 'f', 'c', 'x',    'e', 'w', '3', '4', 'r', 'd', 's',
    'f', 'd', 'r', 't', 'g', 'v', 'c',    'g', 'f', 't', 'y', 'h', 'b', 'v',
    'h', 'g', 'y', 'u', 'j', 'n', 'b',    'i', 'u', '8', '9', 'o', 'k', 'j',
    'j', 'h', 'u', 'i', 'k', 'm', 'n',    'k', 'j', 'i', 'o', 'l', ',', 'm',
    'l', 'k', 'o', 'p', ';', '.', ',',    'm', 'n', 'j', 'k', ',',   0,   0,
    'n', 'b', 'h', 'j', 'm',   0,   0,    'o', 'i', '9', '0', 'p', 'l', 'k',
    'p', 'o', '0', '-', '[', ';', 'l',    'q',   0, '1', '2', 'w', 'a',   0,
    'r', 'e', '4', '5', 't', 'f', 'd',    's', 'a', 'w', 'e', 'd', 'x', 'z',
    't', 'r', '5', '6', 'y', 'g', 'f',    'u', 'y', '7', '8', 'i', 'j', 'h',
    'v', 'c', 'f', 'g', 'b',   0,   0,    'w', 'q', '2', '3', 'e', 's', 'a',
    'x', 'z', 's', 'd', 'c',   0,   0,    'y', 't', '6', '7', 'u', 'h', 'g',
    'z',   0, 'a', 's', 'x',   0,   0,
};

static const uint8_t Dvorak[47 * 7] = {
    '\'',  0, '1', '2', ',', 'a',   0,    ',','\'', '2', '3', '.', 'o', 'a',
    '-', 's', '/', '=',   0,   0, 'z',    '.', ',', '3', '4', 'p', 'e', 'o',
    '/', 'l', '[', ']', '=', '-', 's',    '0', '9',   0,   0, '[', 'l', 'r',
    '1', '`',   0,   0, '2','\'',   0,    '2', '1',   0,   0, '3', ',','\'',
    '3', '2',   0,   0, '4', '.', ',',    '4', '3',   0,   0, '5', 'p', '.',
    '5', '4',   0,   0, '6', 'y', 'p',    '6', '5',   0,   0, '7', 'f', 'y',
    '7', '6',   0,   0, '8', 'g', 'f',    '8', '7',   0,   0, '9', 'c', 'g',
    '9', '8',   0,   0, '0', 'r', 'c',    ';',   0, 'a', 'o', 'q',   0,   0,
    '=', '/', ']',   0,'\\',   0, '-',    '[', '0',   0,   0, ']', '/', 'l',
    '\\','=',   0,   0,   0,   0,   0,    ']', '[',   0,   0,   0, '=', '/',
    '`',   0,   0,   0, '1',   0,   0,    'a',   0,'\'', ',', 'o', ';',   0,
    'b', 'x', 'd', 'h', 'm',   0,   0,    'c', 'g', '8', '9', 'r', 't', 'h',
    'd', 'i', 'f', 'g', 'h', 'b', 'x',    'e', 'o', '.', 'p', 'u', 'j', 'q',
    'f', 'y', '6', '7', 'g', 'd', 'i',    'g', 'f', '7', '8', 'c', 'h', 'd',
    'h', 'd', 'g', 'c', 't', 'm', 'b',    'i', 'u', 'y', 'f', 'd', 'x', 'k',
    'j', 'q', 'e', 'u', 'k',   0,   0,    'k', 'j', 'u', 'i', 'x',   0,   0,
    'l', 'r', '0', '[', '/', 's', 'n',    'm', 'b', 'h', 't', 'w',   0,   0,
    'n', 't', 'r', 'l', 's', 'v', 'w',    'o', 'a', ',', '.', 'e', 'q', ';',
    'p', '.', '4', '5', 'y', 'u', 'e',    'q', ';', 'o', 'e', 'j',   0,   0,
    'r', 'c', '9', '0', 'l', 'n', 't',    's', 'n', 'l', '/', '-', 'z', 'v',
    't', 'h', 'c', 'r', 'n', 'w', 'm',    'u', 'e', 'p', 'y', 'i', 'k', 'j',
    'v', 'w', 'n', 's', 'z',   0,   0,    'w', 'm', 't', 'n', 'v',   0,   0,
    'x', 'k', 'i', 'd', 'b',   0,   0,    'y', 'p', '5', '6', 'f', 'i', 'u',
    'z', 'v', 's', '-',   0,   0,   0
};

static const uint8_t PC_Keypad[15 * 9] = {
    '*', '/',   0,   0,   0, '-', '+', '9', '8',
    '+', '9', '*', '-',   0,   0,   0,   0, '6',
    '-', '*',   0,   0,   0,   0,   0, '+', '9',
    '.', '0', '2', '3',   0,   0,   0,   0,   0,
    '/',   0,   0,   0,   0, '*', '9', '8', '7',
    '0',   0, '1', '2', '3', '.',   0,   0,   0,
    '1',   0,   0, '4', '5', '2', '0',   0,   0,
    '2', '1', '4', '5', '6', '3', '.', '0',   0,
    '3', '2', '5', '6',   0,   0,   0, '.', '0',
    '4',   0,   0, '7', '8', '5', '2', '1',   0,
    '5', '4', '7', '8', '9', '6', '3', '2', '1',
    '6', '5', '8', '9', '+',   0,   0, '3', '2',
    '7',   0,   0,   0, '/', '8', '5', '4',   0,
    '8', '7',   0, '/', '*', '9', '6', '5', '4',
    '9', '8', '/', '*', '-', '+',   0, '6', '5'
};

static const uint8_t MacKeypad[16 * 9] = {
    '*', '/',   0,   0,   0,   0,   0, '-', '9',
    '+', '6', '9', '-',   0,   0,   0,   0, '3',
    '-', '9', '/', '*',   0,   0,   0, '+', '6',
    '.', '0', '2', '3',   0,   0,   0,   0,   0,
    '/', '=',   0,   0,   0, '*', '-', '9', '8',
    '0',   0, '1', '2', '3', '.',   0,   0,   0,
    '1',   0,   0, '4', '5', '2', '0',   0,   0,
    '2', '1', '4', '5', '6', '3', '.', '0',   0,
    '3', '2', '5', '6', '+',   0,   0, '.', '0',
    '4',   0,   0, '7', '8', '5', '2', '1',   0,
    '5', '4', '7', '8', '9', '6', '3', '2', '1',
    '6', '5', '8', '9', '-', '+',   0, '3', '2',
    '7',   0,   0,   0, '=', '8', '5', '4',   0,
    '8', '7',   0, '=', '/', '9', '6', '5', '4',
    '9', '8', '=', '/', '*', '-', '+', '6', '5',
    '=',   0,   0,   0,   0, '/', '9', '8', '7'
};

static const Keyboard Keyboards[] = {
    { US_Qwerty, US_Shift, sizeof(US_Qwerty) / 7, 7, sizeof(US_Shift) / 2, 66 },
    { Dvorak,    US_Shift, sizeof(Dvorak) / 7,    7, sizeof(US_Shift) / 2, 66 },
    { UK_Qwerty, UK_Shift, sizeof(UK_Qwerty) / 7, 7, sizeof(UK_Shift) / 2, 66 },
    { MacKeypad, nullptr, sizeof(MacKeypad) / 9, 9, 0, 44 },
    { PC_Keypad, nullptr, sizeof(PC_Keypad) / 9, 9, 0, 44 }
};

namespace {

/**
 * Match spatial pattern on keyboard
 */
int DoSptlMatch(const uint8_t* passwd, int maxLen, const Keyboard* keyb, SpatialMatchInfo* extra) {
    int shiftCount = 0;
    int turns = 0;
    int dir = -1;
    int len = 0;
    uint8_t prevChar = 0;
    
    for (; *passwd && (len < maxLen); ++passwd, ++len) {
        const uint8_t* key;
        int s = 0;
        uint8_t curChar = *passwd;
        
        // Try to unshift the character
        if (keyb->Shifts) {
            key = CharBinSearch(curChar, keyb->Shifts, keyb->NumShift, 2);
            if (key) {
                curChar = key[1];
                s = 1;
            }
        }
        
        if (prevChar) {
            int i = 0;
            key = CharBinSearch(prevChar, keyb->Keys, keyb->NumKeys, keyb->NumNear);
            if (key) {
                for (i = keyb->NumNear - 1; i > 0; --i) {
                    if (key[i] == curChar) break;
                }
            }
            
            if (i) {
                turns += (i != dir);
                dir = i;
                shiftCount += s;
            } else {
                break;
            }
        }
        prevChar = curChar;
    }
    
    if (len >= MIN_SPATIAL_LEN) {
        extra->Turns = turns;
        extra->Shifts = shiftCount;
        return len;
    }
    return 0;
}

/**
 * Try to match spatial patterns
 */
void SpatialMatch(ZxcMatch_t** result, const uint8_t* passwd, int start, int maxLen) {
    passwd += start;
    
    for (int curLen = maxLen; curLen >= MIN_SPATIAL_LEN; ) {
        int len = 0;
        
        for (unsigned int indx = 0; indx < (sizeof(Keyboards) / sizeof(Keyboards[0])); ++indx) {
            SpatialMatchInfo extra{};
            const auto* k = &Keyboards[indx];
            len = DoSptlMatch(passwd, curLen, k, &extra);
            
            if (len > 0) {
                double degree = (k->NumNear - 1) - static_cast<double>(k->NumBlank) / k->NumKeys;
                int s = k->Keys;
                if (k->Shifts) s *= 2;
                
                // Estimate number of possible patterns
                double entropy = 0.0;
                for (int i = 2; i <= len; ++i) {
                    int possTurns = std::min(extra.Turns, i - 1);
                    for (int j = 1; j <= possTurns; ++j) {
                        entropy += nCk(i - 1, j - 1) * std::pow(degree, j) * s;
                    }
                }
                if (entropy > 0.0)
                    entropy = std::log(entropy);
                
                // Add entropy for shifted keys
                if (extra.Shifts) {
                    int shift = extra.Shifts;
                    int unshift = len - shift;
                    double d = 0.0;
                    int j = std::min(shift, unshift);
                    
                    for (int i = 0; i <= j; ++i) {
                        d += nCk(len, i);
                    }
                    if (d > 0.0)
                        entropy += std::log(d);
                }
                
                auto* p = AllocMatch();
                p->Type = SPATIAL_MATCH;
                p->Begin = start;
                p->Entrpy = entropy;
                p->Length = len;
                AddMatchRepeats(result, p, passwd, maxLen);
                AddResult(result, p, maxLen);
            }
        }
        curLen = len - 1;
    }
}

} // anonymous namespace

/*################################################################################*
 * Date Matching Code
 *################################################################################*/

static const char* const Formats[] = {
    "yyyy", "d?m?yy", "ddmmyy", "dmyyyy", "dd?m?yy", "d?mm?yy",
    "ddmyyyy", "dmmyyyy", "yyyymmd", "yyyymdd", "d?m?yyyy",
    "dd?mm?yy", "ddmmyyyy", "yyyy?m?d", "yyyymmdd", "dd?m?yyyy",
    "d?mm?yyyy", "yyyy?mm?d", "yyyy?m?dd", "dd?mm?yyyy", "yyyy?mm?dd",
    nullptr
};

static const char DateSeperators[] = "/\\-_. ";

namespace {

/**
 * Try to match date patterns
 */
void DateMatch(ZxcMatch_t** result, const uint8_t* passwd, int start, int maxLen) {
    passwd += start;
    int prevLen = 0;
    
    for (int curFmt = 0; Formats[curFmt]; ++curFmt) {
        int len = 0;
        int year = 0, mon = 0, day = 0;
        int fail = 0;
        int yrLen = 0;
        uint8_t sep = 0;
        const uint8_t* p = passwd;
        
        for (const char* fmt = Formats[curFmt]; *fmt && !fail; ++fmt) {
            if (*fmt == '?') {
                if (!sep && std::strchr(DateSeperators, *p))
                    sep = *p;
                fail = (*p != sep);
            } else if (std::isdigit(*p)) {
                if (*fmt == 'd') {
                    day = 10 * day + *p - '0';
                } else if (*fmt == 'm') {
                    mon = 10 * mon + *p - '0';
                } else {
                    year = 10 * year + *p - '0';
                    ++yrLen;
                }
            } else {
                fail = 1;
            }
            ++p;
            ++len;
            if (len >= maxLen) break;
        }
        
        if (len < 4) fail = 1;
        
        if (!fail) {
            if (((yrLen > 3) || (len <= 4)) && ((year < MIN_YEAR) || (year > MAX_YEAR)))
                fail = 1;
            else if (len > 4) {
                if ((mon > 12) && (day < 13)) std::swap(mon, day);
                if ((mon < 1) || (mon > 12) || (day < 1) || (day > 31))
                    fail = 1;
            }
        }
        
        if (!fail && (len > prevLen)) {
            double e;
            if (len <= 4)
                e = std::log(MAX_YEAR - MIN_YEAR + 1.0);
            else if (yrLen > 3)
                e = std::log(31 * 12 * (MAX_YEAR - MIN_YEAR + 1.0));
            else
                e = std::log(31 * 12 * 100.0);
            
            if (sep) e += std::log(4.0);
            
            auto* p = AllocMatch();
            p->Entrpy = e;
            p->Type = DATE_MATCH;
            p->Length = len;
            p->Begin = start;
            AddMatchRepeats(result, p, passwd, maxLen);
            AddResult(result, p, maxLen);
            prevLen = len;
        }
    }
}

} // anonymous namespace

/*################################################################################*
 * Repeat Matching Code
 *################################################################################*/

namespace {

/**
 * Try to match repeated characters
 */
void RepeatMatch(ZxcMatch_t** result, const uint8_t* passwd, int start, int maxLen) {
    passwd += start;
    uint8_t c = *passwd;
    int len;
    
    // Count repeated characters
    for (len = 1; (len < maxLen) && (c == passwd[len]); ++len) {}
    
    if (len >= MIN_REPEAT_LEN) {
        double card = Cardinality(&c, 1);
        for (int i = len; i >= MIN_REPEAT_LEN; --i) {
            auto* p = AllocMatch();
            p->Type = REPEATS_MATCH;
            p->Begin = start;
            p->Length = i;
            p->Entrpy = std::log(card * i);
            AddResult(result, p, maxLen);
        }
    }
    
    // Try to match repeated sequences
    for (len = maxLen / 2; len >= MIN_REPEAT_LEN; --len) {
        const uint8_t* rpt = passwd + len;
        int repeatCount = 2;
        
        while (maxLen >= (len * repeatCount)) {
            if (std::strncmp(reinterpret_cast<const char*>(passwd),
                           reinterpret_cast<const char*>(rpt), len) == 0) {
                int c1 = Cardinality(passwd, len);
                auto* p = AllocMatch();
                p->Entrpy = std::log(static_cast<double>(c1)) * len + std::log(repeatCount);
                p->Type = static_cast<ZxcTypeMatch_t>(BRUTE_MATCH + MULTIPLE_MATCH);
                p->Length = len * repeatCount;
                p->Begin = start;
                AddResult(result, p, maxLen);
            } else {
                break;
            }
            ++repeatCount;
            rpt += len;
        }
    }
}

} // anonymous namespace

/*################################################################################*
 * Sequence Matching Code
 *################################################################################*/

namespace {

/**
 * Try to match incrementing/decrementing character sequences
 */
void SequenceMatch(ZxcMatch_t** result, const uint8_t* passwd, int start, int maxLen) {
    passwd += start;
    const uint8_t* pwd = passwd;
    
    uint8_t first = passwd[0];
    int dir = passwd[1] - first;
    int len = 0;
    bool isDigits = false;
    int setLow, setHigh;
    
    // Determine character set
    if (std::islower(*passwd)) {
        setLow = 'a';
        setHigh = 'z';
    } else if (std::isupper(*passwd)) {
        setLow = 'A';
        setHigh = 'Z';
    } else if (std::isdigit(*passwd)) {
        setLow = '0';
        setHigh = '9';
        if ((first == '0') && std::isdigit(passwd[1]) && (dir > MAX_SEQUENCE_STEP)) {
            dir = passwd[1] - ('9' + 1);
        }
        isDigits = true;
    } else {
        return;
    }
    
    // Check if valid sequence
    if (dir && (dir <= MAX_SEQUENCE_STEP) && (dir >= -MAX_SEQUENCE_STEP)) {
        ++len;
        while (true) {
            uint8_t next = passwd[0] + dir;
            
            if (isDigits && (dir > 0) && (next == ('9' + 1)) && (passwd[1] == '0')) {
                ++len;
                ++passwd;
                break;
            }
            if (isDigits && (dir < 0) && (passwd[0] == '0') && (passwd[1] == ('9' + 1 + dir))) {
                ++len;
                ++passwd;
                break;
            }
            if ((next > setHigh) || (next < setLow) || (passwd[1] != next))
                break;
            
            ++len;
            ++passwd;
            if (len >= maxLen) break;
        }
    }
    
    if (len >= MIN_SEQUENCE_LEN) {
        double e;
        if ((first == 'a') || (first == 'A') || (first == 'z') || (first == 'Z') ||
            (first == '0') || (first == '1') || (first == '9'))
            e = std::log(2.0);
        else if (isDigits)
            e = std::log(10.0);
        else if (std::isupper(first))
            e = std::log(26 * 2.0);
        else
            e = std::log(26.0);
        
        if (dir < 0) e += std::log(2.0);
        
        for (int i = len; i >= MIN_SEQUENCE_LEN; --i) {
            auto* p = AllocMatch();
            p->Type = SEQUENCE_MATCH;
            p->Begin = start;
            p->Length = i;
            p->Entrpy = e + std::log(static_cast<double>(i));
            AddMatchRepeats(result, p, pwd, maxLen);
            AddResult(result, p, maxLen);
        }
    }
}

} // anonymous namespace

/*################################################################################*
 * Main Zxcvbn Code
 *################################################################################*/

struct Node {
    ZxcMatch_t* Paths = nullptr;
    double Dist = DBL_MAX;
    ZxcMatch_t* From = nullptr;
    int Visit = 0;
};

/**
 * Main zxcvbn password entropy estimation function
 */
double ZxcvbnMatch(const char* pwd, const char* userDict[], ZxcMatch_t** info) {
    int fullLen = std::strlen(pwd);
    int len = fullLen;
    const auto* passwd = reinterpret_cast<const uint8_t*>(pwd);
    
    // Create nodes
    std::vector<Node> nodes(len + 2);
    int i = Cardinality(passwd, len);
    double e = std::log(static_cast<double>(i));
    
    // Limit length for detailed analysis
    if (len > ZXCVBN_DETAIL_LEN)
        len = ZXCVBN_DETAIL_LEN;
    
    // Do matching for all password parts
    for (i = 0; i < len; ++i) {
        int maxLen = len - i;
        UserMatch(&(nodes[i].Paths), userDict, passwd, i, maxLen);
        DictionaryMatch(&(nodes[i].Paths), passwd, i, maxLen);
        DateMatch(&(nodes[i].Paths), passwd, i, maxLen);
        SpatialMatch(&(nodes[i].Paths), passwd, i, maxLen);
        SequenceMatch(&(nodes[i].Paths), passwd, i, maxLen);
        RepeatMatch(&(nodes[i].Paths), passwd, i, maxLen);
    }
    
    // Reverse dictionary check
    std::vector<uint8_t> revPwd(len + 1);
    for (i = len - 1, int j = 0; i >= 0; --i, ++j)
        revPwd[j] = pwd[i];
    revPwd[len] = 0;
    
    for (i = 0; i < len; ++i) {
        ZxcMatch_t* path = nullptr;
        int maxLen = len - i;
        DictionaryMatch(&path, revPwd.data(), i, maxLen);
        UserMatch(&path, userDict, revPwd.data(), i, maxLen);
        
        while (path) {
            ZxcMatch_t* nxt = path->Next;
            path->Next = nullptr;
            path->Begin = len - (path->Begin + path->Length);
            AddResult(&(nodes[path->Begin].Paths), path, maxLen);
            path = nxt;
        }
    }
    
    // Add brute force matches
    std::vector<uint8_t> bruteFlags(len + 1, 0);
    for (i = 0; i < len; ++i) {
        ZxcMatch_t* path = nodes[i].Paths;
        while (path) {
            bruteFlags[path->Begin] |= 1;
            bruteFlags[path->Begin + path->Length] |= 2;
            path = path->Next;
        }
    }
    bruteFlags[0] = 1;
    bruteFlags[len] = 2;
    
    for (i = 0; i < len; ++i) {
        if (!bruteFlags[i]) continue;
        int maxLen = len - i;
        
        for (int j = i + 1; j <= len; ++j) {
            if (bruteFlags[j]) {
                auto* zp = AllocMatch();
                zp->Type = BRUTE_MATCH;
                zp->Begin = i;
                zp->Length = j - i;
                zp->Entrpy = e * (j - i);
                AddResult(&(nodes[i].Paths), zp, maxLen);
            }
        }
    }
    
    // Handle very long passwords
    if (fullLen > len) {
        auto* zp = AllocMatch();
        zp->Type = LONG_PWD_MATCH;
        zp->Begin = len;
        zp->Length = len - fullLen;
        zp->Entrpy = std::log(2 * (fullLen - len));
        AddResult(&(nodes[i].Paths), zp, fullLen - len);
        ++len;
    }
    
    // Dijkstra's algorithm
    nodes[0].Dist = 0.0;
    
    for (i = 0; i < len; ++i) {
        double minDist = DBL_MAX;
        int minIdx = 0;
        
        for (int j = 0; j < len; ++j) {
            if (!nodes[j].Visit && (nodes[j].Dist < minDist)) {
                minIdx = j;
                minDist = nodes[j].Dist;
            }
        }
        
        auto& np = nodes[minIdx];
        np.Visit = 1;
        e = np.Dist;
        
        for (auto* zp = np.Paths; zp; zp = zp->Next) {
            Node* ep = (zp->Length >= 0) ? &nodes[minIdx + zp->Length] : &nodes[minIdx + 1];
            double d = e + zp->MltEnpy;
            
            if (!ep->Visit && (d < ep->Dist)) {
                ep->Dist = d;
                ep->From = zp;
            }
        }
    }
    
    e = nodes[len].Dist / std::log(2.0);
    
    // Construct info on password parts
    if (info) {
        *info = nullptr;
        
        for (auto* zp = nodes[len].From; zp; ) {
            i = zp->Begin;
            auto* xp = nodes[i].Paths;
            nodes[i].Paths = nullptr;
            
            while (xp) {
                auto* p = xp->Next;
                if (xp == zp) {
                    xp->Entrpy /= std::log(2.0);
                    xp->MltEnpy /= std::log(2.0);
                    if (xp->Length < 0)
                        xp->Length = -xp->Length;
                    
                    xp->Next = *info;
                    *info = xp;
                } else {
                    delete xp;
                }
                xp = p;
            }
            zp = nodes[i].From;
        }
    }
    
    // Free all paths
    for (i = 0; i <= len; ++i) {
        auto* zp = nodes[i].Paths;
        while (zp) {
            auto* p = zp->Next;
            delete zp;
            zp = p;
        }
    }
    
    return e;
}

/**
 * Free match info
 */
void ZxcvbnFreeInfo(ZxcMatch_t* info) {
    while (info) {
        auto* p = info->Next;
        delete info;
        info = p;
    }
}
