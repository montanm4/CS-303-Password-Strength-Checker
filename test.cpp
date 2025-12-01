/**********************************************************************************
 * Program to test the C implementation of the zxcvbn password strength estimator.
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

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <sys/time.h>
#include <zxcvbn.h>

// For pre-compiled headers under windows
#ifdef _WIN32
#include "stdafx.h"
#endif

const std::vector<const char*> UsrDict = {
    "Onename.Twoname@example.com", "Onename", "Twoname", "example.com", "example",
    nullptr
};

static void CalcPass(const std::string& pwd, bool quiet)
{
    double entropy;
    const char* pwdCStr = pwd.c_str();
    
    if (!quiet)
    {
        // Output the details of how the entropy figure was calculated
        int len, chkLen;
        struct timeval t1, t2;
        ZxcMatch_t *info, *p;
        double multiWordExtra = 0.0;

        gettimeofday(&t1, nullptr);
        entropy = ZxcvbnMatch(pwdCStr, UsrDict.data(), &info);
        gettimeofday(&t2, nullptr);
        
        for(p = info; p != nullptr; p = p->Next)
            multiWordExtra += p->Entrpy;

        len = pwd.length();
        multiWordExtra = entropy - multiWordExtra;
        std::cout << "Pass " << pwd << " \tLength " << len 
                  << "\tEntropy bits=" << entropy 
                  << " log10=" << (entropy * 0.301029996)
                  << "\tMulti-word extra bits=" << multiWordExtra << std::endl;
        
        p = info;
        chkLen = 0;
        const char* pwdPtr = pwdCStr;
        
        while(p != nullptr)
        {
            switch(static_cast<int>(p->Type))
            {
                case BRUTE_MATCH:                     std::cout << "  Type: Bruteforce     ";   break;
                case DICTIONARY_MATCH:                std::cout << "  Type: Dictionary     ";   break;
                case DICT_LEET_MATCH:                 std::cout << "  Type: Dict+Leet      ";   break;
                case USER_MATCH:                      std::cout << "  Type: User Words     ";   break;
                case USER_LEET_MATCH:                 std::cout << "  Type: User+Leet      ";   break;
                case REPEATS_MATCH:                   std::cout << "  Type: Repeated       ";   break;
                case SEQUENCE_MATCH:                  std::cout << "  Type: Sequence       ";   break;
                case SPATIAL_MATCH:                   std::cout << "  Type: Spatial        ";   break;
                case DATE_MATCH:                      std::cout << "  Type: Date           ";   break;
                case YEAR_MATCH:                      std::cout << "  Type: Year           ";   break;
                case LONG_PWD_MATCH:                  std::cout << "  Type: Extra-long     ";   break;
                case BRUTE_MATCH+MULTIPLE_MATCH:      std::cout << "  Type: Bruteforce(Rep)";   break;
                case DICTIONARY_MATCH+MULTIPLE_MATCH: std::cout << "  Type: Dictionary(Rep)";   break;
                case DICT_LEET_MATCH+MULTIPLE_MATCH:  std::cout << "  Type: Dict+Leet(Rep) ";   break;
                case USER_MATCH+MULTIPLE_MATCH:       std::cout << "  Type: User Words(Rep)";   break;
                case USER_LEET_MATCH+MULTIPLE_MATCH:  std::cout << "  Type: User+Leet(Rep) ";   break;
                case REPEATS_MATCH+MULTIPLE_MATCH:    std::cout << "  Type: Repeated(Rep)  ";   break;
                case SEQUENCE_MATCH+MULTIPLE_MATCH:   std::cout << "  Type: Sequence(Rep)  ";   break;
                case SPATIAL_MATCH+MULTIPLE_MATCH:    std::cout << "  Type: Spatial(Rep)   ";   break;
                case DATE_MATCH+MULTIPLE_MATCH:       std::cout << "  Type: Date(Rep)      ";   break;
                case YEAR_MATCH+MULTIPLE_MATCH:       std::cout << "  Type: Year(Rep)      ";   break;
                case LONG_PWD_MATCH+MULTIPLE_MATCH:   std::cout << "  Type: Extra-long(Rep)";   break;
                default:                              std::cout << "  Type: Unknown" << p->Type << " ";   break;
            }
            
            chkLen += p->Length;
            std::cout << "  Length " << p->Length 
                      << "  Entropy " << p->Entrpy 
                      << " (" << (p->Entrpy * 0.301029996) << ") ";
            
            for(int n = 0; n < p->Length; ++n, ++pwdPtr)
                std::cout << *pwdPtr;
            std::cout << std::endl;
            
            p = p->Next;
        }
        
        ZxcvbnFreeInfo(info);
        t2.tv_sec -= t1.tv_sec;
        t2.tv_usec -= t1.tv_usec;
        t2.tv_usec += t2.tv_sec * 1000000;
        std::cout << "    Calculation Time " << (t2.tv_usec/1000.0) << "ms" << std::endl;
        
        if (chkLen != len)
            std::cout << "*** Password length (" << len 
                      << ") != sum of length of parts (" << chkLen << ") ***" << std::endl;
    }
    else
    {
        // Only get the final entropy figure
        entropy = ZxcvbnMatch(pwdCStr, UsrDict.data(), nullptr);
        std::cout << "Pass " << pwd << " \tEntropy " << entropy << std::endl;
    }
}

static int DoChecks(const std::string& filename)
{
    char line[5000];
    int lineNum = 0;
    int wordCount = 0;
    int failCount = 0;
    int lessCount = 0;
    int moreCount = 0;
    
    std::ifstream file(filename);
    if (!file.is_open())
    {
        std::cout << "Failed to open " << filename << std::endl;
        return 1;
    }
    
    while(file.getline(line, sizeof(line)))
    {
        ++lineNum;
        size_t lineLen = std::strlen(line);
        
        // Skip blank lines or those starting with #
        if (lineLen < 3 || line[0] == '#')
            continue;
        
        char* pwd = line;
        // Skip leading whitespace
        while(*pwd && (*pwd <= ' '))
            ++pwd;

        // Make password null terminated
        char* separator = std::strchr(pwd, '\t');
        if (separator == nullptr)
            separator = std::strstr(pwd, "  ");
        if (separator == nullptr)
        {
            std::cout << "Bad test condition on line " << lineNum << std::endl;
            failCount = 1;
            break;
        }
        *separator++ = 0;

        // Skip whitespace before entropy value
        while(*separator && (*separator <= ' '))
            ++separator;
        if (!*separator)
        {
            std::cout << "Bad test condition on line " << lineNum << std::endl;
            failCount = 1;
            break;
        }

        double expectedEntropy = std::atof(separator);
        if (expectedEntropy < 0.0 || expectedEntropy > 10000.0)
        {
            std::cout << "Bad entropy value on line " << lineNum << std::endl;
            failCount = 1;
            break;
        }
        
        double calculatedEntropy = ZxcvbnMatch(pwd, UsrDict.data(), nullptr);
        double ratio = calculatedEntropy / expectedEntropy;
        
        // More than 1% difference is a fail
        if (ratio > 1.01)
        {
            ++moreCount;
            if (failCount < 10)
            {
                std::cout << "Line " << lineNum 
                          << " Calculated entropy " << calculatedEntropy
                          << ", expected " << expectedEntropy 
                          << "  <" << pwd << ">" << std::endl;
                ++failCount;
            }
        }
        else if (ratio < 1.0/1.01)
        {
            ++lessCount;
            if (failCount < 10)
            {
                std::cout << "Line " << lineNum 
                          << " Calculated entropy " << calculatedEntropy
                          << ", expected " << expectedEntropy 
                          << "  <" << pwd << ">" << std::endl;
                ++failCount;
            }
        }
        ++wordCount;
    }
    
    file.close();
    std::cout << "Tested " << wordCount << " words, " 
              << lessCount << " with low entropy, " 
              << moreCount << " with high" << std::endl;
    return failCount;
}

int main(int argc, char **argv)
{
    bool quiet = false;
    bool checks = false;
    bool white = false;

    if (!ZxcvbnInit("zxcvbn.dict"))
    {
        std::cout << "Failed to open dictionary file" << std::endl;
        return 1;
    }
    
    if (argc > 1 && argv[1][0] == '-')
    {
        std::string option(argv[1]);
        
        if (option == "-qs" || option == "-sq")
            quiet = white = true;
        if (option == "-t")
            checks = true;
        if (option == "-q")
            quiet = true;
        if (option == "-s")
            white = true;
            
        if (!checks && !quiet && !white)
        {
            const char* progName = std::strrchr(argv[0], '/');
            progName = (progName == nullptr) ? argv[0] : progName + 1;
            
            std::cout << "Usage: " << progName << " [ -q | -qs ] [ pwd1 pwd2 ... ]\n"
                      << "          Output entropy of given passwords. If no passwords on command line read\n"
                      << "           them from stdin.\n"
                      << "          -q option stops password analysis details from being output.\n"
                      << "          -s Ignore anything from space on a line when reading from stdin.\n"
                      << "       " << progName << " -t file\n"
                      << "          Read the file and check for correct results." << std::endl;
            return 1;
        }
    }
    
    if (checks)
    {
        for(int i = 2; i < argc; ++i)
        {
            int result = DoChecks(argv[i]);
            if (result)
                return 1;
        }
        return 0;
    }
    
    int startIdx = 1 + (quiet ? 1 : 0) + (white ? 1 : 0);
    if (startIdx >= argc)
    {
        // No test passwords on command line, so get them from stdin
        std::string line;
        while(std::getline(std::cin, line))
        {
            // Remove trailing whitespace
            while(!line.empty() && line.back() <= ' ')
                line.pop_back();
            
            // Handle white space option
            if (white)
            {
                size_t spacePos = line.find(' ');
                if (spacePos != std::string::npos)
                    line = line.substr(0, spacePos);
            }
            
            if (!line.empty())
                CalcPass(line, quiet);
        }
    }
    else
    {
        // Do the test passwords on the command line
        for(int i = startIdx; i < argc; ++i)
        {
            CalcPass(argv[i], quiet);
        }
    }
    
    ZxcvbnUnInit();
    return 0;
}
