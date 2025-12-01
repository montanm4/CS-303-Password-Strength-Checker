#include "zxcvbn.h"
#include "zxcvbn.cpp"

#include <iostream>
#include <cstring>
#include <cstdint>

/**********************************************************************************
 * Internal checks: Validate if the first element of each group is sorted in
 *                  ascending order. CharBinSearch(...)
 * Returns 0 on success.
 * Returns element index [1..] of first error entry that is less than previous one.
 */
static int check_order(const uint8_t *entries, unsigned int numEntries, unsigned int sizeEntries) {
    const uint8_t *last = nullptr;

    if (!entries) return 0;

    for (unsigned int i = 0; i < numEntries; ++i, entries += sizeEntries) {
        if (last && *last > *entries) {
            std::cout << "Entry#" << i << " [" << (i * sizeEntries) << "]:  '"
                      << static_cast<char>(*last) << "' > '" << static_cast<char>(*entries)
                      << "'  (0x" << std::hex << static_cast<int>(*last) 
                      << " > 0x" << static_cast<int>(*entries) << std::dec << ")\n    A:  ";
            
            for (unsigned int j = 0; j < sizeEntries; ++j) {
                std::cout << "'" << (last[j] ? static_cast<char>(last[j]) : ' ') << "' ";
            }
            std::cout << "\n    >\n    B:  ";
            
            for (unsigned int j = 0; j < sizeEntries; ++j) {
                std::cout << "'" << (entries[j] ? static_cast<char>(entries[j]) : ' ') << "' ";
            }
            std::cout << std::endl;

            return i;
        }
        last = entries;
    }

    return 0; /* cannot be a misordered position; first possible one: 1 */
}

/**********************************************************************************
 * Internal checks: Checks keyboard data integrity.
 * Returns 0 on success.
 * Otherwise, number of errors are reported.
 */
static unsigned int selftest_keyboards() {
    unsigned int errors = 0;
    const Keyboard_t *k;
    unsigned int indx;

    for (k = Keyboards, indx = 0; indx < (sizeof Keyboards / sizeof Keyboards[0]); ++indx, ++k) {
        /* if one of these assertions fails, we cannot use binary search algorithm */
        if (k->Shifts && std::strlen(reinterpret_cast<const char*>(k->Shifts)) % 2 == 1) {
            std::cout << "Error: Keyboard[" << indx 
                      << "]: Shifts-string has odd number of entries" << std::endl;
            ++errors;
        }

        int errPos;
        if ((errPos = check_order(k->Shifts, k->NumShift, 2))) {
            std::cout << "Error: Keyboard[" << indx 
                      << "]: Error above in sort order of Shifts-string near item #" 
                      << errPos << std::endl;
            ++errors;
        }

        if ((errPos = check_order(k->Keys, k->NumKeys, k->NumNear))) {
            std::cout << "Error: Keyboard[" << indx 
                      << "]: Error above in sort order of keyboard-entries! Problem near item #" 
                      << errPos << std::endl;
            ++errors;
            continue;
        }

        /* For each key (c0), check all its neighbours (ci):
         * Does the neighbour key (c1==ci) have an entry (cx) in the opposite direction [rev_idx]
         * pointing back to the current key c0?
         * c0: ...ci..   -->   c1: ..cx...   -->   cx==c0?
         */
        const uint8_t *keys = k->Keys;
        int blanks = 0;
        
        for (int i = 0; i < k->NumKeys; ++i) {
            uint8_t c0 = keys[i * k->NumNear];

            for (int j = 0; j < k->NumNear - 1; ++j) {
                /* rev_idx: reverse/opposite index to find opposite key location [0..6|8] --> [0..6|8] */
                int revIdx = (j + (k->NumNear - 1) / 2) % (k->NumNear - 1);
                uint8_t ci = keys[i * k->NumNear + j + 1];

                if (ci) {
                    const uint8_t *c1 = CharBinSearch(ci, keys, k->NumKeys, k->NumNear);
                    
                    if (c1) {
                        if (ci == c0) {
                            std::cout << "Error: Keyboard[" << indx 
                                      << "]:  recursion - key '" << static_cast<char>(*c1) 
                                      << "' cannot be its own neighbour" << std::endl;
                            ++errors;
                        } else {
                            uint8_t cx = c1[1 + revIdx];
                            
                            if (cx) {
                                if (cx != c0) {
                                    std::cout << "Error: Keyboard[" << indx 
                                              << "]:  c0='" << static_cast<char>(c0) 
                                              << "':...(ci=" << static_cast<char>(ci) 
                                              << ")... ->  c1='" << static_cast<char>(*c1) 
                                              << "':...(cx=" << static_cast<char>(cx) 
                                              << ")... --!--> c0='" << static_cast<char>(c0) 
                                              << "':... " << std::endl;
                                    ++errors;
                                }
                            } else { /* reverse pointer is NULL */
                                std::cout << "Error: Keyboard[" << indx 
                                          << "]:  reverse entry missing in row c1='" 
                                          << static_cast<char>(*c1) << "'[" << (1 + revIdx) 
                                          << "] pointing back to c0='" << static_cast<char>(c0) 
                                          << "'!" << std::endl;
                                ++errors;
                            }
                        }
                    } else {
                        std::cout << "Error: Keyboard[" << indx 
                                  << "]:  no entry (neighbour list) found for src-char c1==ci='" 
                                  << static_cast<char>(ci) << "'" << std::endl;
                        ++errors;
                    }
                } else { /* blank neighbour key reference found */
                    ++blanks;
                }
            }
        }
        
        if (blanks != k->NumBlank) {
            std::cout << "Error: Keyboard[" << indx 
                      << "]:  number of blank keys announced (" << k->NumBlank 
                      << ") does not match number of blank keys counted (" << blanks 
                      << ")" << std::endl;
            ++errors;
        }
    }
    
    return errors;
}

int main() {
    unsigned int errors = selftest_keyboards(); /* currently only these */
    
    if (errors) {
        std::cout << "Failed: [KEYBOARDS] - selftest returned " << errors 
                  << " error(s)." << std::endl;
    }

    return errors ? 1 : 0;
}
