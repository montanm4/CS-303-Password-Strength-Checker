/**********************************************************************************
 * Program to generate the dictionary for the C implementation of the zxcvbn password estimator.
 * Copyright (c) 2025 Tony Evans
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

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <string>
#include <fstream>
#include <list>
#include <set>
#include <vector>
#include <map>
#include <memory>
#include <limits>
#include <cstdlib>
#include <cstring>
#include <cmath>

using namespace std;

class Node;
typedef std::shared_ptr<Node> NodeSPtr;
typedef std::weak_ptr<Node> NodeWPtr;
typedef std::map<char, NodeSPtr> NodeMap_t;

typedef unsigned int Check_t;

/**********************************************************************************
 * Class to perform CRC checksum calculation.
 */
class TrieCheck
{
public:
    typedef uint64_t Check_t;
    static const Check_t CHK_INIT = 0xffffffffffffffff;
    TrieCheck()          { Init(); }
    void Init()          { mCrc = CHK_INIT; }
    operator Check_t() const { return Result(); }
    Check_t  Result()  const { return mCrc; }
    bool operator ! () const { return mCrc == CHK_INIT; }
    void operator () (const void *, unsigned int);
protected:
    Check_t mCrc;
};

/**********************************************************************************
 * Class to hold a node within the trie
 */
class Node
{
public:
    Node();
    Node(const Node &);
    ~Node();
    Node & operator = (const Node &);
    void          SetEnd()           { mEnd = true; }
    bool          IsEnd() const      { return mEnd; }
    int           Height() const     { return mHeight; }

    // Scan the trie and count nodes
    int           NodeCount()        { ClearCounted(); return CountNodes(); }

    int           CalcAddress()      { int a = 0; ClearCounted(); a = CalcAddr(a, true); return CalcAddr(a, false); }
    Node         *GetParent()        { return mParent; }
    unsigned int  GetAddr() const    { return mAddr; }
    NodeMap_t::iterator ChildBegin() { return mChild.begin(); }
    NodeMap_t::iterator ChildEnd()   { return mChild.end(); }
    unsigned int  GetNumChild()      { return mChild.size(); }
    int           GetNumEnds() const { return mEndings; }
    NodeSPtr      FindChild(char);
    std::string   GetChildChars();

    TrieCheck::Check_t CalcCheck();
    int         CalcEndings();
    int         CalcHeight();
    NodeSPtr    AddChild(char);
    void        ChangeChild(NodeSPtr &, NodeSPtr &);
    void        ClearCounted();
    void        SetCounted()    { mCounted = true; }
    bool        IsCounted() const { return mCounted; }
protected:
    int      CountNodes();
    int      CalcAddr(int, bool);

    NodeMap_t    mChild;
    Node        *mParent;
    int          mEndings;
    int          mHeight;
    unsigned int mAddr;
    TrieCheck    mCheck;
    bool         mEnd;
    bool         mCounted;
};

/**********************************************************************************
 * Static table used for the crc implementation.
 */
static const TrieCheck::Check_t CrcTable[16] =
{
    0x0000000000000000, 0x7d08ff3b88be6f81, 0xfa11fe77117cdf02, 0x8719014c99c2b083,
    0xdf7adabd7a6e2d6f, 0xa2722586f2d042ee, 0x256b24ca6b12f26d, 0x5863dbf1e3ac9dec,
    0x95ac9329ac4bc9b5, 0xe8a46c1224f5a634, 0x6fbd6d5ebd3716b7, 0x12b5926535897936,
    0x4ad64994d625e4da, 0x37deb6af5e9b8b5b, 0xb0c7b7e3c7593bd8, 0xcdcf48d84fe75459
};

// Update the crc value with new data.
void TrieCheck::operator () (const void *v, unsigned int len)
{
    Check_t crc = mCrc;
    const unsigned char *data = reinterpret_cast<const unsigned char *>(v);
    while(len--)
    {
        crc = CrcTable[(crc ^ (*data >> 0)) & 0x0f] ^ (crc >> 4);
        crc = CrcTable[(crc ^ (*data >> 4)) & 0x0f] ^ (crc >> 4);
        ++data;
    }
    mCrc = crc;
}

Node::Node()
{
    mEndings = -1;
    mHeight = -1;
    mEnd    = false;
    mParent = nullptr;
}

Node::Node(const Node &r)
{
    *this = r;
}

Node::~Node()
{

}

Node &Node::operator = (const Node & r)
{
    mChild   = r.mChild;
    mParent  = r.mParent;
    mEndings = r.mEndings;
    mHeight  = r.mHeight;
    mCheck   = r.mCheck;
    mEnd     = r.mEnd;
    return *this;
}

/**********************************************************************************
 * Generate a checksum for the current node. Value also depends of the
 * checksum of any child nodes
 */
TrieCheck::Check_t Node::CalcCheck()
{
    if (!mCheck)
    {
        // Not done this node before
        char c;
        mCheck.Init();
        // Include number of children
        c = mChild.size();
        mCheck(&c, sizeof c);
        // For each child include its character and node checksum
        for(auto& [ch, node] : mChild)
        {
            Check_t n = node->CalcCheck();
            c = ch;
            mCheck(&c, sizeof c);
            mCheck(&n, sizeof n);
        }
        // Finally include whether this node is an ending in the checksum
        c = mEnd;
        mCheck(&c, sizeof c);
    }
    return mCheck;
}

/**********************************************************************************
 * Get number of nodes for this which end/finish a word
 */
int Node::CalcEndings()
{
    if (mEndings < 0)
    {
        // Not already done this node, so calculate the ends
        int n = 0;
        // Number of endings is sum of the endings of the child nodes plus this node if it ends a word
        for(auto& [ch, node] : mChild)
            n += node->CalcEndings();
        n += static_cast<int>(mEnd);
        mEndings = n;
    }
    return mEndings;
}

/**********************************************************************************
 * Calculate the height of the trie starting at current node
 */
int Node::CalcHeight()
{
    if (mHeight < 0)
    {
        // Not already done this node, so calculate the height
        int hi = 0;
        // Get height of all child nodes, remember the highest
        for(auto& [ch, node] : mChild)
        {
            int i = node->CalcHeight();
            if (i >= hi)
                hi = i + 1;
        }
        mHeight = hi;
    }
    return mHeight;
}

/**********************************************************************************
 * Clear indication that node has been counted
 */
void Node::ClearCounted()
{
    mCounted = false;
    for(auto& [ch, node] : mChild)
        node->ClearCounted();
}

/**********************************************************************************
 * Count this plus the number of child nodes. As part of the tree node count
 * scan, make sure not to double count nodes
 */
int Node::CountNodes()
{
    // Count is 0 if already done
    if (mCounted)
        return 0;
    mCounted = true;
    int i = 1; // 1 for this node

    // Add the child nodes
    for(auto& [ch, node] : mChild)
        i += node->CountNodes();
    return i;
}

/**********************************************************************************
 * Calculate the final node address
 */
int Node::CalcAddr(int start, bool manyEnds)
{
    if (!(mCounted || (manyEnds && (mEndings < 256))))
    {
        mCounted = true;
        mAddr = start++;
    }
    for(auto& [ch, node] : mChild)
        start = node->CalcAddr(start, manyEnds);

    return start;
}

/**********************************************************************************
 * Add the given character to the current node, return the next lower node
 */
NodeSPtr Node::AddChild(char c)
{
    // Find character in map of child nodes
    auto it = mChild.find(c);
    if (it == mChild.end())
    {
        // New character, create new child node
        NodeSPtr a = make_shared<Node>();
        a->mParent = this;
        auto result = mChild.insert({c, a});
        it = result.first;
    }
    return it->second;
}

/**********************************************************************************
 * Find the child node which corresponds to the given character.
 */
NodeSPtr Node::FindChild(char ch)
{
    auto it = mChild.find(ch);
    if (it == mChild.end())
        return NodeSPtr();
    return it->second;
}

/**********************************************************************************
 * Replace the current child node (old param) with a new child (Replace param),
 * and update the new child parent.
 */
void Node::ChangeChild(NodeSPtr & replace, NodeSPtr & oldNode)
{
    for(auto& [ch, node] : mChild)
    {
        if (node == oldNode)
        {
            node = replace;
            replace->mParent = this;
            break;
        }
    }
}

/**********************************************************************************
 * Find all the characters corresponding to the children of this node.
 */
std::string Node::GetChildChars()
{
    std::string result;
    for(auto& [ch, node] : mChild)
    {
        result += ch;
    }
    return result;
}

/**********************************************************************************
 * struct to hold data read from input file (except for the word string)
 */
struct Entry
{
    Entry() : mRank(0), mDict(0), mOrder(0), mOccurs(0) {}
    int mRank;
    int mDict;
    int mOrder;
    int mOccurs;
};

/**********************************************************************************
 * Struct to hold a string and an int. Also provide the compare operators for std::set class
 */
struct StringInt
{
    string       s;
    unsigned int i;
    StringInt() { i = 0; }
    StringInt(const StringInt & r) : s(r.s), i(r.i) {}
    StringInt & operator = (const StringInt & r) { i = r.i; s = r.s; return *this; }
    bool operator < (const StringInt & r)  const { return s < r.s; }
    bool operator > (const StringInt & r)  const { return s > r.s; }
    bool operator == (const StringInt & r) const { return s == r.s; }
    StringInt * Self() const { return const_cast<StringInt *>(this); }
};

typedef map<string, Entry> EntryMap_t;
typedef list<string> StringList_t;
typedef list<NodeSPtr> NodeList_t;
typedef set<StringInt> StringIntSet_t;
typedef vector<int> StringOfInts;
typedef vector<unsigned int> UintVect;
typedef vector<uint64_t> Uint64Vect;
typedef vector<StringInt *> StrIntPtrVect_t;
typedef vector<StringInt> StringIntVect_t;

// Variables holding 'interesting' information on the data
unsigned int MaxLength = 0, MinLength = 999, NumChars = 0, NumInWords = 0, NumDuplicate = 0;
static string PassWithMaxChilds, MaxChildChars;
static unsigned int MaxNumChilds = 0, MaxChildsPosn = 0;

struct FileInfo
{
    FileInfo() : Words(0), BruteIgnore(0), Accented(0), Dups(0), Used(0), Rank(0) { }
    string Name;
    StringList_t Pwds;
    int Words;
    int BruteIgnore;
    int Accented;
    int Dups;
    int Used;
    int Rank;
};

/**********************************************************************************
 * Read the file of words and add them to the file information.
 */
static bool ReadInputFile(const string & fileName, FileInfo &info, int maxRank)
{
    ifstream f(fileName);
    if (!f.is_open())
    {
        cerr << "Error opening " << fileName << endl;
        return false;
    }
    info.Name = fileName;

    // Rank is the position of the word in the dictionary file. Rank==1 is lowest for a word (and
    // indicates a very popular or bad password).
    int rank = 0;
    string line;
    while(getline(f, line) && (rank < maxRank))
    {
        // Truncate at first space or tab to leave just the word in case additional info on line
        auto y = line.find_first_of("\t ");
        if (y != string::npos)
            line.erase(y);

        y = line.length();
        if (!y)
            continue;

        ++info.Words;
        // Only use words where all chars are ascii (no accents etc.)
        size_t x;
        double bruteForce = 1.0;
        for(x = 0; x < y; ++x)
        {
            unsigned char c = line[x];
            if (c >= 128)
                break;
            c = tolower(c);
            line[x] = c;
            bruteForce *= 26.0;
        }
        if (x < y)
        {
            ++info.Accented;
            continue;
        }

        // Don't use words where the brute force strength is less than the word's rank
        if (bruteForce < (rank + 1))
        {
            ++info.BruteIgnore;
            continue;
        }
        // Remember some interesting info
        if (y > MaxLength)
            MaxLength = y;
        if (y < MinLength)
            MinLength = y;
        NumChars += y;

        info.Pwds.push_back(line);
        ++rank;
    }
    f.close();
    return true;
}

static void CombineWordLists(EntryMap_t & entries, FileInfo *infos, int numInfo)
{
    bool done = false;
    int rank = 0;
    while(!done)
    {
        ++rank;
        done = true;
        for(int i = 0; i < numInfo; ++i)
        {
            FileInfo *p = infos + i;
            while(!p->Pwds.empty())
            {
                done = false;
                string word = p->Pwds.front();
                p->Pwds.pop_front();
                auto it = entries.find(word);
                if (it != entries.end())
                {
                    // Word is repeat of one from another file
                    p->Dups += 1;
                    ++NumDuplicate;
                }
                else
                {
                    // New word, add it
                    Entry e;
                    e.mDict = i;
                    e.mRank = rank;
                    entries.insert({word, e});
                    p->Used += 1;
                    break;
                }
            }
        }
    }
}

/**********************************************************************************
 * Use all words previously read from file(s) and add them to a Trie, which starts
 * at Root. Also update a bool array indicating the chars used in the words.
 */
static void ProcessEntries(NodeSPtr root, EntryMap_t & entries, bool *inputCharSet)
{
    for(auto& [text, entry] : entries)
    {
        // Add latest word to tree
        NodeSPtr pNode = root;
        for(char c : text)
        {
            pNode = pNode->AddChild(c);
            // Add char to set of used character codes
            inputCharSet[c & 0xFF] = true;
        }
        pNode->SetEnd();
    }
}

/**********************************************************************************
 * Add the passed node to the list if it has same height as value in Hi (= number
 * of steps to get to a terminal node). If current node has height greater than Hi,
 * recursively call with each child node as one of these may be at the required height.
 */
static void AddToListAtHeight(NodeList_t & lst, NodeSPtr node, int hi)
{
    if (hi == node->Height())
    {
        lst.push_back(node);
        return;
    }
    if (hi < node->Height())
    {
        for(auto it = node->ChildBegin(); it != node->ChildEnd(); ++it)
        {
            AddToListAtHeight(lst, it->second, hi);
        }
    }
}

/**********************************************************************************
 * Scan the trie and update the original word list with the alphabetical order
 * (or 'index location') of the words
 */
static void ScanTrieForOrder(EntryMap_t & entries, int & ord, NodeSPtr root, const string & str)
{
    if (root->IsEnd())
    {
        // Root is a word ending node, so store its index in the input word store
        auto ite = entries.find(str);
        if (ite == entries.end())
            throw "Trie string not in entries";

        ite->second.mOrder = ++ord;
    }
    // For each child, append its character to the current word string and do a recursive
    // call to update their word indexes.
    for(auto it = root->ChildBegin(); it != root->ChildEnd(); ++it)
    {
        string tmp = str + it->first;
        ScanTrieForOrder(entries, ord, it->second, tmp);
    }
}

/**********************************************************************************
 * Reduce the trie by merging tails where possible. Starting at greatest height,
 * get a list of all nodes with given height, then test for identical nodes. If
 * found, change the parent of the second identical node to use the first node,
 * and delete second node and its children. Reduce height by one and repeat
 * until height is zero.
 */
static void ReduceTrie(NodeSPtr root)
{
    root->CalcCheck();

    for(int height = root->CalcHeight(); height >= 0; --height)
    {
        // Get a list of all nodes at given height
        NodeList_t lst;
        AddToListAtHeight(lst, root, height);

        for(auto ita = lst.begin(); ita != lst.end(); ++ita)
        {
            // Going to use a CRC to decide if two nodes are identical
            TrieCheck::Check_t chka = (*ita)->CalcCheck();
            auto itb = ita;
            for(++itb; itb != lst.end(); )
            {
                if (chka == (*itb)->CalcCheck())
                {
                    // Found two identical nodes (with identical children)
                    Node * parentb = (*itb)->GetParent();
                    if (parentb)
                    {
                        // Change the 2nd parent to use the current node as child
                        // Remove the 2nd node from the scanning list as it will
                        // get deleted by the sharing (as using std::shared_ptr)
                        parentb->ChangeChild(*ita, *itb);
                        itb = lst.erase(itb);
                    }
                    else
                    {
                        cout << " orphan ";
                        ++itb;
                    }
                }
                else
                {
                    ++itb;
                }
            }
        }
    }
}

/**********************************************************************************
 * Scan the trie to match with the supplied word. Return the order of the
 * word, or -1 if it is not in the trie.
 */
static int CheckWord(NodeSPtr root, const string & str)
{
    int i = 1;
    bool e = false;
    NodeSPtr p = root;

    for(size_t x = 0; x < str.length(); ++x)
    {
        // Scan children to find one that matches current character
        char c = str[x];
        auto it = p->ChildBegin();
        for(; it != p->ChildEnd(); ++it)
        {
            if (it->first == c)
                break;
            // Add the number of endings at or below child to track the alphabetical index
            int j = it->second->CalcEndings();
            i += j;
        }
        // Fail if no child matches the character
        if (it == p->ChildEnd())
            return -1;
        // Allow for this node being a word ending
        e = p->IsEnd();
        if (e)
            ++i;

        if (p->GetNumChild() > MaxNumChilds)
        {
            MaxNumChilds = p->GetNumChild();
            MaxChildsPosn = x;
            PassWithMaxChilds = str;
            MaxChildChars.clear();
            for(auto itc = p->ChildBegin(); itc != p->ChildEnd(); ++itc)
                MaxChildChars += itc->first;
        }
        p = it->second;
    }

    if (p && p->IsEnd())
    {
        if (str.length() == str.length())
            return i;
    }
    return -1;
}

/**********************************************************************************
 * Try to find every input word in the reduced trie. The order should also
 * match, otherwise the reduction has corrupted the trie.
 */
static int CheckReduction(StringIntVect_t & ranks, NodeSPtr root, EntryMap_t & entries)
{
    int i = 0;
    int n = 0;
    ranks.resize(entries.size() + 1);
    
    for(auto& [text, entry] : entries)
    {
        if (i > 200000)
            break;
            
        int b = CheckWord(root, text);
        if (b < 0)
        {
            ++i;
            cout << entry.mOrder << ": Missing " << text << endl;
        }
        else if (entry.mOrder != b)
        {
            ++i;
            cout << entry.mOrder << ": Bad order " << b << " for  " << text << endl;
        }
        else
        {
            ++n;
        }
        if (b >= static_cast<int>(ranks.size()))
            throw " Using Ranks beyond end";
        if (b >= 0)
        {
            char tmp[20];
            snprintf(tmp, sizeof(tmp), "%d: ", n);
            ranks[b].i = entry.mRank;
            ranks[b].s = string(tmp) + text;
        }
        // Try to find a non-existent word
        string testWord = "a" + text + '#';
        b = CheckWord(root, testWord);
        if (b > 0)
            throw string("Found non-existent word ") + testWord;
     }
     if (i > 0)
         throw "Missing words in reduction check = " + to_string(i);
    return n;
}

struct ChkNum
{
    int Match;
    int Err;
    ChkNum() : Match(0), Err(0) {}
    ChkNum(const ChkNum &r) : Match(r.Match), Err(r.Err) {}
    ChkNum & operator = (const ChkNum & r) { Match = r.Match; Err = r.Err; return *this; }
    ChkNum & operator += (const ChkNum & r) { Match += r.Match; Err += r.Err; return *this; }
};

/**********************************************************************************
 * Find all possible words in the trie and make sure they are input words.
 * Return number of words found. Done as a second trie check.
 */
static ChkNum CheckEntries(NodeSPtr root, string str, const EntryMap_t & entries)
{
    ChkNum ret;
    if (root->IsEnd())
    {
        // This is an end node, find the word in the input words
        auto it = entries.find(str);
        if (it != entries.end())
            ++ret.Match;
        else
            ++ret.Err;
    }
    // Add each child character to the passed string and recursively check
    for(auto it = root->ChildBegin(); it != root->ChildEnd(); ++it)
    {
        string tmp = str + it->first;
        ret += CheckEntries(it->second, tmp, entries);
    }
    return ret;
}

/**********************************************************************************
 * Convert the passed bool array of used chars into a character string
 */
string MakeCharSet(bool *inputCharSet)
{
    string s;
    for(int i = 1; i < 256; ++i)
    {
        if (inputCharSet[i])
            s += char(i);
    }
    return s;
}

/**********************************************************************************
 * Create a set of strings which contain the possible characters matched at
 * a node when checking a word.
 */
void MakeChildBitMap(StringIntSet_t & strSet, NodeSPtr root, int & loc)
{
    // Skip if already done
    if (root->IsCounted())
        return;

    StringInt in;
    NodeSPtr p = root;
    in.s = root->GetChildChars();
    if (strSet.find(in) == strSet.end())
    {
        // Not already in set of possible child chars for a node, so add it
        in.i = loc++; // Address in the final output array
        strSet.insert(in);
    }
    // Recursively do the child nodes
    for(char c : in.s)
    {
        NodeSPtr q = p->FindChild(c);
        if (q)
            MakeChildBitMap(strSet, q, loc);
    }
    root->SetCounted();
}

// Constants defining bit positions of node data
// Number of bits to represent the index of the child char pattern in the final child bitmap array
const int BITS_CHILD_PATT_INDEX = 14;

// Number of bits to represent index of where the child pointers start for this node in
// the Child map array and its bit position
const int BITS_CHILD_MAP_INDEX = 18;
const int SHIFT_CHILD_MAP_INDEX = BITS_CHILD_PATT_INDEX;

// Bit positions of word ending indicator and indicator for number of word endings for this + child nodes is >= 256
const int SHIFT_WORD_ENDING_BIT = SHIFT_CHILD_MAP_INDEX + BITS_CHILD_MAP_INDEX;
const int SHIFT_LARGE_ENDING_BIT = SHIFT_WORD_ENDING_BIT + 1;

/**********************************************************************************
 * Create the arrays of data that will be output
 */
void CreateArrays(NodeSPtr root, StringIntSet_t & strSet, StringOfInts & childAddrs, Uint64Vect & nodeData, UintVect & nodeEnds)
{
    StringInt tmp;
    StringOfInts chld;

    // Find children in the child pattern array
    tmp.s = root->GetChildChars();
    auto its = strSet.find(tmp);

    // Make a 'string' of pointers to the children
    for(auto itc = root->ChildBegin(); itc != root->ChildEnd(); ++itc)
    {
        int i = itc->second->GetAddr();
        chld.push_back(i);
    }
    // Find where in pointer array the child pointer string is
    auto x = search(childAddrs.begin(), childAddrs.end(), chld.begin(), chld.end()) - childAddrs.begin();
    if (x == static_cast<decltype(x)>(childAddrs.size()))
    {
        // Not found, add it
        childAddrs.insert(childAddrs.end(), chld.begin(), chld.end());
    }
    // Val will contain the final node data
    uint64_t val = its->i;
    if (val >= (1u << BITS_CHILD_PATT_INDEX))
    {
        char tmpStr[20];
        snprintf(tmpStr, sizeof tmpStr, "%u", its->i);
        throw string("Not enough bits for child pattern index value of ") + tmpStr + " for " +
                its->s + " (BITS_CHILD_PATT_INDEX too small)";
    }
    if (x >= (1u << BITS_CHILD_MAP_INDEX))
    {
        char tmpStr[24];
        snprintf(tmpStr, sizeof tmpStr, "%zu", x);
        throw string("Not enough bits for child map index value of ") + tmpStr + " for " +
                its->s + " (BITS_CHILD_MAP_INDEX too small)";
    }
    val |= x << SHIFT_CHILD_MAP_INDEX;
    if (root->IsEnd())
        val |= uint64_t(1) << SHIFT_WORD_ENDING_BIT;
    if (root->GetNumEnds() >= 256)
        val |= uint64_t(1) << SHIFT_LARGE_ENDING_BIT;

    // Make sure output arrays are big enough
    if (root->GetAddr() >= nodeData.size())
    {
        nodeData.resize(root->GetAddr() + 1, 4000000000);
        nodeEnds.resize(root->GetAddr() + 1, 4000000000);
    }
    // Save the node data and number of word endings for the node
    nodeData[root->GetAddr()] = val;
    nodeEnds[root->GetAddr()] = root->GetNumEnds();

    // Now do the children
    for(auto itc = root->ChildBegin(); itc != root->ChildEnd(); ++itc)
    {
        CreateArrays(itc->second, strSet, childAddrs, nodeData, nodeEnds);
    }
}

/**********************************************************************************
 * Output the data as a binary file.
 */
static int OutputBinary(ostream *out, const string & chkFile, const string & charSet, StringIntSet_t & strSet,
                        StringOfInts & childAddrs, Uint64Vect & nodeData, UintVect & nodeEnds, StringIntVect_t & ranks)
{
    int outputSize;
    unsigned int fewEndStart = 2000000000;
    unsigned int i;
    unsigned int index;
    unsigned short u;
    TrieCheck h;

    for(index = 0; index < nodeData.size(); ++index)
    {
        uint64_t v = nodeData[index];
        if ((fewEndStart >= 2000000000) && !(v & (uint64_t(1) << SHIFT_LARGE_ENDING_BIT)))
        {
            fewEndStart = index;
            break;
        }
    }
    // Header words
    unsigned int numWordEnd;
    const unsigned int MAGIC = 'z' + ('x' << 8) + ('c' << 16) + ('v' << 24);
    out->write(reinterpret_cast<const char *>(&MAGIC), sizeof MAGIC);
    h(&MAGIC, sizeof MAGIC);
    outputSize = sizeof MAGIC;

    i = nodeData.size();
    out->write(reinterpret_cast<const char *>(&i), sizeof i);
    h(&i, sizeof i);
    outputSize += sizeof i;

    i = childAddrs.size();
    if (nodeData.size() > numeric_limits<unsigned int>::max())
        i |= 1 << 31;
    out->write(reinterpret_cast<const char *>(&i), sizeof i);
    h(&i, sizeof i);
    outputSize += sizeof i;

    i = ranks.size();
    out->write(reinterpret_cast<const char *>(&i), sizeof i);
    h(&i, sizeof i);
    outputSize += sizeof i;

    numWordEnd = (nodeData.size() + 7) / 8;
    out->write(reinterpret_cast<const char *>(&numWordEnd), sizeof numWordEnd);
    h(&numWordEnd, sizeof numWordEnd);
    outputSize += sizeof numWordEnd;

    i = strSet.size();
    out->write(reinterpret_cast<const char *>(&i), sizeof i);
    h(&i, sizeof i);
    outputSize += sizeof i;

    unsigned int bytePerEntry = (charSet.length() + 7) / 8;
    out->write(reinterpret_cast<const char *>(&bytePerEntry), sizeof bytePerEntry);
    h(&bytePerEntry, sizeof bytePerEntry);
    outputSize += sizeof bytePerEntry;

    out->write(reinterpret_cast<const char *>(&fewEndStart), sizeof fewEndStart);
    h(&fewEndStart, sizeof fewEndStart);
    outputSize += sizeof fewEndStart;

    i = nodeData.size();
    out->write(reinterpret_cast<const char *>(&i), sizeof i);
    h(&i, sizeof i);
    outputSize += sizeof i;

    i = charSet.length();
    out->write(reinterpret_cast<const char *>(&i), sizeof i);
    h(&i, sizeof i);
    outputSize += sizeof i;

    // Output array of node data
    vector<unsigned char> wordEnds(numWordEnd, 0);
    unsigned char v = 0;
    unsigned int z = 0;
    int y = 0;
    for(index = 0; index < nodeData.size(); ++index)
    {
        i = nodeData[index];
        out->write(reinterpret_cast<const char *>(&i), sizeof i);
        h(&i, sizeof i);

        if (nodeData[index] & (uint64_t(1) << SHIFT_WORD_ENDING_BIT))
            v |= 1 << y;
        if (++y >= 8)
        {
            wordEnds[z++] = v;
            y = 0;
            v = 0;
        }
    }
    while(z < numWordEnd)
    {
         wordEnds[z++] = v;
         v = 0;
    }
    outputSize += index * sizeof i;

    // Output array of node pointers
    for(index = 0; index < childAddrs.size(); ++index)
    {
        i = childAddrs[index];
        out->write(reinterpret_cast<const char *>(&i), sizeof i);
        h(&i, sizeof i);
    }
    outputSize += index * sizeof i;

    // Output ranks
    for(index = 0; index < ranks.size(); ++index)
    {
        i = ranks[index].i;
        if (i >= (1 << 15))
        {
            i -= 1 << 15;
            i /= 4;
            if (i >= (1 << 15))
                i = (1 << 15) - 1;
            i |= 1 << 15;
        }
        if (i > numeric_limits<unsigned short>::max())
            i = numeric_limits<unsigned short>::max();
        u = i;
        out->write(reinterpret_cast<const char *>(&u), sizeof u);
        h(&u, sizeof u);
    }
    outputSize += index * sizeof u;

    // Output word end bit markers
    out->write(reinterpret_cast<const char *>(wordEnds.data()), numWordEnd);
    h(wordEnds.data(), numWordEnd);
    outputSize += numWordEnd;

    string str;
    unsigned char buf[8];

    // Get the items from strSet ordered by the index
    StrIntPtrVect_t setPtrs(strSet.size());
    for(auto& item : strSet)
    {
        StringInt *p = item.Self();
        if (p->i >= strSet.size())
            throw "Bad index";
        setPtrs[p->i] = p;
    }
    // Output child bitmap
    unsigned int charSetLen = 0;
    for(index = 0; index < setPtrs.size(); ++index)
    {
        unsigned int j;
        memset(buf, 0, sizeof buf);
        StringInt *p = setPtrs[index];
        str = p->s;
        for(char ch : str)
        {
            auto pos = charSet.find(ch);
            if (pos != string::npos)
            {
                buf[pos / 8] |= 1 << (pos & 7);
            }
        }
        // Find max bits set which indicates max number chars used at a node
        for(i = j = 0; i < 8 * sizeof buf; ++i)
        {
            if (buf[i / 8] & (1 << (i & 7)))
                ++j;
        }
        if (j > charSetLen)
            charSetLen = j;

        out->write(reinterpret_cast<const char *>(buf), bytePerEntry);
        h(buf, bytePerEntry);
     }
    outputSize += index * bytePerEntry;

    unsigned char c;
    for(index = 0; index < fewEndStart; ++index)
    {
        i = nodeEnds[index] >> 8;
        c = (i >= 256) ? 0 : i;
        out->write(reinterpret_cast<const char *>(&c), 1);
        h(&c, 1);
    }
    outputSize += index * sizeof c;

    for(index = 0; index < nodeEnds.size(); ++index)
    {
        c = nodeEnds[index];
        out->write(reinterpret_cast<const char *>(&c), 1);
        h(&c, 1);
    }
    outputSize += index * sizeof c;

    out->write(charSet.c_str(), charSet.length());
    h(charSet.c_str(), charSet.length());
    outputSize += charSet.length();

    if (!chkFile.empty())
    {
        // Write the checksum file
        TrieCheck::Check_t x = h.Result();
        ofstream f(chkFile);
        f << "static const unsigned char WordCheck[" << sizeof x << "] =\n{\n    ";
        unsigned char *cp = reinterpret_cast<unsigned char *>(&x);
        for(index = 0; index < sizeof x; ++index, ++cp)
        {
            if (index)
                f << ',';
            f << int(*cp);
        }
        f << "\n};\n";
        f << "#define WORD_FILE_SIZE " << outputSize << endl;
        f << "#define ROOT_NODE_LOC 0\n"
             "#define BITS_CHILD_PATT_INDEX " << BITS_CHILD_PATT_INDEX << "\n"
             "#define BITS_CHILD_MAP_INDEX  " << BITS_CHILD_MAP_INDEX << "\n"
             "#define SHIFT_CHILD_MAP_INDEX BITS_CHILD_PATT_INDEX\n"
             "#define SHIFT_WORD_ENDING_BIT (SHIFT_CHILD_MAP_INDEX + BITS_CHILD_MAP_INDEX)\n"
             "#define CHARSET_SIZE " << (charSetLen + 1) << endl;
        f.close();
    }
    return outputSize;
}

int OutputTester(ostream *out, bool /*cmnts*/, StringIntVect_t & ranks)
{
    unsigned int index;
    string pwd;
    for(index = 1; index < ranks.size(); ++index)
    {
        unsigned int v = ranks[index].i;
        pwd = ranks[index].s;
        auto x = pwd.find(':');
        if (x != string::npos)
            pwd.erase(0, x + 1);

        *out << pwd << "  ";
        for(x = pwd.length(); x < 16; ++x)
            *out << ' ';
        *out << log(v * 1.0) / log(2.0) << "  " << v << '\n';
    }
    return index;
}

const int LINE_OUT_LEN = 160;

/**********************************************************************************
 * Output the data as C source.
 */
int OutputCode(ostream *out, bool cmnts, const string & charSet, StringIntSet_t & strSet, NodeSPtr & root,
               StringOfInts & childAddrs, Uint64Vect & nodeData, UintVect & nodeEnds, StringIntVect_t & ranks)
{
    unsigned int index;
    int outputSize;

    if (cmnts)
        *out << "#define ND(e,c,b) (c<<" << SHIFT_CHILD_MAP_INDEX << ")|b\n";

    // Output array of node data
    *out << "#define ROOT_NODE_LOC 0\n"
            "#define BITS_CHILD_PATT_INDEX " << BITS_CHILD_PATT_INDEX << "\n"
            "#define BITS_CHILD_MAP_INDEX  " << BITS_CHILD_MAP_INDEX << "\n"
            "#define SHIFT_CHILD_MAP_INDEX BITS_CHILD_PATT_INDEX\n"
            "#define SHIFT_WORD_ENDING_BIT (SHIFT_CHILD_MAP_INDEX + BITS_CHILD_MAP_INDEX)\n"
            "static const unsigned int DictNodes[" << nodeData.size() << "] =\n{";
    outputSize = nodeData.size() * sizeof(unsigned int);
    int x = 999;
    unsigned int fewEndStart = 2000000000;
    for(index = 0; index < nodeData.size(); ++index)
    {
        uint64_t v;
        x += 11;
        if (x > LINE_OUT_LEN)
        {
            *out << "\n    ";
            x = 0;
        }
        v = nodeData[index];
        v &= (uint64_t(1) << SHIFT_WORD_ENDING_BIT) - 1;
        if (cmnts)
        {
            uint64_t i = (v >> SHIFT_WORD_ENDING_BIT) & 3;
            *out << "ND(" << i << ',';
            i = (v >> SHIFT_CHILD_MAP_INDEX) & ((1 << BITS_CHILD_MAP_INDEX) - 1);
            *out << i << ',';
            if (i < 10000) *out << ' ';
            if (i < 1000)  *out << ' ';
            if (i < 100)   *out << ' ';
            if (i < 10)    *out << ' ';
            i = v & ((1 << BITS_CHILD_PATT_INDEX) - 1);
            *out << i << ")";
            if (index < (nodeData.size() - 1))
            {
                *out << ',';
                if (i < 1000)  *out << ' ';
                if (i < 100)   *out << ' ';
                if (i < 10)    *out << ' ';
            }
        }
        else
        {
            *out << v;
            if (index < (nodeData.size() - 1))
            {
                *out << ',';
                if (v < 1000000000) *out << ' ';
                if (v < 100000000) *out << ' ';
                if (v < 10000000) *out << ' ';
                if (v < 1000000) *out << ' ';
                if (v < 100000) *out << ' ';
                if (v < 10000) *out << ' ';
                if (v < 1000)  *out << ' ';
                if (v < 100)   *out << ' ';
                if (v < 10)    *out << ' ';
            }
        }
        if ((fewEndStart >= 2000000000) && !(nodeData[index] & (uint64_t(1) << SHIFT_LARGE_ENDING_BIT)))
            fewEndStart = index;
    }
    *out << "\n};\n";
    unsigned int len = ((nodeData.size() + 7) / 8);
    outputSize += len;
    x = 999;
    *out << "static const unsigned char WordEndBits[" << len << "] =\n{";
    index = 0;
    {
        unsigned int v = 0;
        unsigned int y = 0;
        unsigned int z = 0;
        while(z < len)
        {
            if (index < nodeData.size())
            {
                if (nodeData[index] & (uint64_t(1) << SHIFT_WORD_ENDING_BIT))
                    v |= 1 << y;
            }
            if (++y >= 8)
            {
                x += 4;
                if (x > LINE_OUT_LEN)
                {
                    *out << "\n    ";
                    x = 0;
                }
                *out << v;
                if (++z < len)
                {
                    *out << ',';
                    if (v < 100) *out << ' ';
                    if (v < 10) *out << ' ';
                }
                y = 0;
                v = 0;
            }
            ++index;
        }
    }
    *out << "\n};\n";
    // Output array of node pointers
    *out << "static const unsigned ";
    if (nodeData.size() > numeric_limits<unsigned short>::max())
    {
        *out << "int";
        x = sizeof(unsigned int);
    }
    else
    {
        *out << "short";
        x = sizeof(unsigned short);
    }
    *out << " ChildLocs[" << childAddrs.size() << "] =\n{";
    outputSize += x * childAddrs.size();
    x = 999;
    for(index = 0; index < childAddrs.size(); ++index)
    {
        int v;
        x += 6;
        if (x > LINE_OUT_LEN)
        {
            *out << "\n    ";
            x = 0;
        }
        v = childAddrs[index];
        *out << v;
        if (index < (childAddrs.size() - 1))
        {
            *out << ',';
            if (v < 10000) *out << ' ';
            if (v < 1000)  *out << ' ';
            if (v < 100)   *out << ' ';
            if (v < 10)    *out << ' ';
        }
    }
    *out << "\n};\n";

    // Output the rank of the words
    *out << "static const unsigned short Ranks[" << ranks.size() << "] =\n{";
    outputSize += ranks.size() * sizeof(unsigned short);
    x = 999;
    bool tooBig = false;
    if (cmnts)
    {
        *out << "\n";
        for(index = 0; index < ranks.size(); ++index)
        {
            unsigned int v = ranks[index].i;
            *out << "    ";
            if (v >= (1 << 15))
            {
                v -= 1 << 15;
                v /= 4;
                if (v >= (1 << 15))
                {
                    tooBig = true;
                    v = (1 << 15) - 1;
                }
                v |= 1 << 15;
            }
            if (v > numeric_limits<unsigned short>::max())
                v = numeric_limits<unsigned short>::max();
            *out << v;
            if (index < (ranks.size() - 1))
            {
                *out << ',';
                if (v < 10000) *out << ' ';
                if (v < 1000)  *out << ' ';
                if (v < 100)   *out << ' ';
                if (v < 10)    *out << ' ';
            }
            *out << " // " << ranks[index].s << '\n';
        }
    }
    else
    {
        for(index = 0; index < ranks.size(); ++index)
        {
            unsigned int v = ranks[index].i;
            x += 6;
            if (x > LINE_OUT_LEN)
            {
                *out << "\n    ";
                x = 0;
            }
            if (v >= (1 << 15))
            {
                v -= 1 << 15;
                v /= 4;
                if (v >= (1 << 15))
                {
                    tooBig = true;
                    v = (1 << 15) - 1;
                }
                v |= 1 << 15;
            }
            if (v > numeric_limits<unsigned short>::max())
                v = numeric_limits<unsigned short>::max();
            *out << v;
            if (index < (ranks.size() - 1))
            {
                *out << ',';
                if (v < 10000) *out << ' ';
                if (v < 1000)  *out << ' ';
                if (v < 100)   *out << ' ';
                if (v < 10)    *out << ' ';
            }
        }
    }
    *out << "\n};\n";
    if (tooBig)
    {
        unsigned int v  = ((1 << 15) - 1) * 4 + (1 << 15);
        cout << "// Word ranks too large, value restricted to " << v << endl;
    }
    unsigned int bytePerEntry = (charSet.length() + 7) / 8;
    *out << "#define SizeChildMapEntry " << bytePerEntry << '\n';
    *out << "static const unsigned char ChildMap[" << strSet.size() << '*' << bytePerEntry << "] =\n{";
    outputSize += strSet.size() * bytePerEntry * sizeof(unsigned char);

    string str;
    unsigned char buf[8];

    // Get the items from strSet ordered by the index
    StrIntPtrVect_t setPtrs(strSet.size());
    for(auto& item : strSet)
    {
        StringInt *p = item.Self();
        if (p->i >= strSet.size())
        {
            cout << "p->i=" << p->i << "  " << p->s << endl;
            throw "Bad index";
        }
        setPtrs[p->i] = p;
    }
    unsigned int charSetLen = 0;
    x = 999;
    len = 0;
    for(index = 0; index < setPtrs.size(); ++index)
    {
        unsigned int i, j;
        size_t z, y;
        memset(buf, 0, sizeof buf);
        if (x > LINE_OUT_LEN)
        {
            *out << "\n    ";
            x = 4 * bytePerEntry;
        }
        StringInt *p = setPtrs[index];
        str = p->s;
        for(char ch : str)
        {
            y = charSet.find(ch);
            if (y != string::npos)
            {
                buf[y / 8] |= 1 << (y & 7);
            }
        }
        // Find max bits set which indicates max number chars used at a node
        for(i = j = 0; i < 8 * sizeof buf; ++i)
        {
            if (buf[i / 8] & (1 << (i & 7)))
                ++j;
        }
        if (j > charSetLen)
            charSetLen = j;
        for(z = 0; z < bytePerEntry; ++z)
        {
            y = buf[z] & 0xFF;
            *out << y;
            if (z < (bytePerEntry - 1))
                *out << ',';
            else
            {
                if (index < (setPtrs.size() - 1))
                    *out << ", ";
            }
            if (y < 100)
                *out << ' ';
            if (y < 10)
                *out << ' ';
            x += 4;
        }
        if (cmnts)
        {
            *out << " // " << p->i << ": " << str;
            x = 999;
        }
    }
    *out << "\n};\n#define CHARSET_SIZE " << (charSetLen + 1) << endl;

    // Output the top 8 bits of the node word endings count
    *out << "#define NumLargeCounts " << fewEndStart << "\n";
    *out << "static const unsigned char EndCountLge[" << fewEndStart << "] =\n{";
    outputSize += fewEndStart * sizeof(unsigned char);
    x = 999;
    for(index = 0; index < fewEndStart; ++index)
    {
        unsigned int v;
        x += 4;
        if (x > LINE_OUT_LEN)
        {
            *out << "\n    ";
            x = 0;
        }
        v = nodeEnds[index] >> 8;
        if (v >= 256)
            v = 0;
        *out << v;
        if (index < (fewEndStart - 1))
        {
            *out << ',';
            if (v < 100)   *out << ' ';
            if (v < 10)    *out << ' ';
        }
    }
    *out << "\n};\n";

    // Output all the word ending counts
    *out << "static const unsigned char EndCountSml[" << nodeEnds.size() << "] =\n{";
    outputSize += nodeEnds.size() * sizeof(unsigned char);
    x = 999;
    for(index = 0; index < nodeEnds.size(); ++index)
    {
        unsigned int v;
        x += 4;
        if (x > LINE_OUT_LEN)
        {
            *out << "\n    ";
            x = 0;
        }
        v = nodeEnds[index] & 255;
        *out << v;
        if (index < (nodeEnds.size() - 1))
        {
            *out << ',';
            if (v < 100)   *out << ' ';
            if (v < 10)    *out << ' ';
        }
    }
    *out << "\n};\n";

    // Finally output the used characters
    *out << "static const char CharSet[" << charSet.length() + 1 << "] = \"";
    outputSize += charSet.length() * sizeof(char);
    for(char c : charSet)
    {
        if ((c == '\\') || (c == '"'))
            *out << '\\';
        *out << c;
    }
    *out << "\";" << endl;
    *out << "#define ROOT_NODE_LOC " << root->GetAddr() << "\n";
    return outputSize + sizeof(unsigned int);
}

enum { OUT_C_CODE, OUT_BINARY, OUT_TESTER };

/**********************************************************************************
 */
int main(int argc, char *argv[])
{
    int maxRank = 999999999;
    int outType = OUT_C_CODE;
    bool verbose = false;
    bool comments = false;
    string fileName, hashFile;
    char *outFile = nullptr;
    EntryMap_t entries;
    FileInfo inInfo[10];
    int numFiles = 0;

    try
    {
        for(int i = 1; i < argc; ++i)
        {
            fileName = argv[i];
            if (fileName == "-b")
            {
                // Output a binary file to stdout or file
                outType = OUT_BINARY;
                continue;
            }
            if (fileName == "-t")
            {
                // Output a tester file to stdout or file
                outType = OUT_TESTER;
                continue;
            }
            if (fileName == "-c")
            {
                // Add comments to the output (if text)
                comments = true;
                continue;
            }
            if (fileName == "-o")
            {
                // Give output file
                if (++i < argc)
                    outFile = argv[i];
                continue;
            }
            if (fileName == "-h")
            {
                // Give crc header output file
                if (++i < argc)
                    hashFile = argv[i];
                continue;
            }
            if (fileName == "-r")
            {
                // Ignore words with too high rank
                if (++i < argc)
                {
                    char *p = nullptr;
                    maxRank = strtol(argv[i], &p, 0);
                    if ((maxRank < 1000) || *p)
                        maxRank = 999999999;
                    continue;
                }
            }
            if (fileName == "-v")
            {
                verbose = true;
                continue;
            }
            if (fileName[0] == '-')
            {
                cerr << "Usage: " << argv[0] << " [ -c ] [ -b | -t ] [ -o Ofile ] [ -h Hfile ] Files...\n"
                        "Where:\n"
                        "     -b        Generate a binary output file\n"
                        "     -t        Generate a test file for testing zxcvbn\n"
                        "     -c        Add comments to output file if C code mode\n"
                        "     -r number Ignore words with rank greater than number (must be >=1000)\n"
                        "     -v        Additional information output\n"
                        "     -h Hfile  Write file checksum to file Hfile as C code (for -b mode)\n"
                        "     -o Ofile  Write output to file Ofile\n"
                        "     Files     The dictionary input files to read\n"
                        "  If the -o option is not used, output is written to stdout\n"
                        "  if the -b option is not used, output is in the form of C source code\n"
                        << endl;
                return 1;
            }
            ReadInputFile(fileName, inInfo[numFiles], maxRank);
            if (numFiles < static_cast<int>(sizeof inInfo / sizeof inInfo[0] - 1))
                ++numFiles;
        }
        CombineWordLists(entries, inInfo, numFiles);
        if (verbose)
        {
            if (!outFile && (outType == OUT_C_CODE))
                cout << "/*\n";
            for(int i = 0; i < numFiles; ++i)
            {
                FileInfo *fi = inInfo + i;
                cout << "Read input file " << fi->Name << endl;
                cout << "   Input words  " << fi->Words << endl;
                cout << "   Used words   " << fi->Used << endl;
                cout << "        Unused  " << fi->BruteIgnore <<
                        " Bruteforce compare, " << fi->Accented <<
                        " Accented char, " << fi->Dups << " Duplicates" << endl;
            }
        }
        bool inputCharSet[256];
        NodeSPtr root = make_shared<Node>();
        // Initially charset of used characters is empty
        memset(inputCharSet, 0, sizeof inputCharSet);

        // Add words to the trie with root in Root
        ProcessEntries(root, entries, inputCharSet);

        // Get some interesting info
        int numEnds = root->CalcEndings();
        int hi = root->CalcHeight();
        int numNodes = root->NodeCount();
        if (verbose)
        {
            cout << "Max word length = " << MaxLength << endl;
            cout << "Min word length = " << MinLength << endl;
            cout << "Num input chars = " << NumChars << endl;
            cout << "Num input words = " << NumInWords << endl;
            cout << "Duplicate words = " << NumDuplicate << endl;
            cout << "Number of Ends  = " << numEnds << endl;
            cout << "Number of Nodes = " << numNodes << endl;
            cout << "Trie height = " << hi << endl;
        }
        // Store the alphabetical ordering of the input words
        int i = 0;
        ScanTrieForOrder(entries, i, root, string());
        if (verbose)
            cout << "Trie Order = " << i << endl;
        int inputOrder = i;
        // Reduce the Trie
        ReduceTrie(root);

        // Output some interesting information
        numNodes = root->NodeCount();
        int reduceEnds = root->CalcEndings();
        if (verbose)
        {
            cout << "After reduce:\n";
            cout << "Number of Ends  = " << reduceEnds << endl;
            cout << "Number of Nodes = " << numNodes << endl;
        }
        // Check reduction was OK
        StringIntVect_t ranks;
        int checkEnds = CheckReduction(ranks, root, entries);
        if (verbose)
            cout << "Number of Words = " << checkEnds << endl;

        ChkNum tst = CheckEntries(root, string(), entries);
        if (verbose)
        {
            cout << "2nd check - Number of valid words = " << tst.Match << endl;
            cout << "          Number of invalid words = " << tst.Err << endl;
        }

        // Give up if there was an error
        if (tst.Err)
            throw "Checks show invalid words after reduction";
        if ((tst.Match != inputOrder) || (reduceEnds != inputOrder))
            throw "Word count changed after reduce";

        // Output more info
        StringIntSet_t childBits;
        string charSet = MakeCharSet(inputCharSet);
        if (verbose)
            cout << "Used characters (" << charSet.length() << "): " << charSet << endl;

        // Make a set of all unique child character patterns for the nodes
        i = 0;
        root->ClearCounted();
        MakeChildBitMap(childBits, root, i);
        if (verbose)
            cout << "Number of child bitmaps = " << childBits.size() << endl;

        // Get final node address
        root->CalcAddress();

        Uint64Vect nodeData;
        UintVect nodeEnds;
        StringOfInts childAddrs;

        // Resize to save library adjusting allocation during data creation
        nodeData.resize(numNodes, 4000000000);
        nodeEnds.resize(numNodes, 4000000000);
        CreateArrays(root, childBits, childAddrs, nodeData, nodeEnds);
        if (verbose)
        {
            cout << "Node data array size " << nodeData.size() << endl;
            cout << "Child pointer array size " << childAddrs.size() << endl;
            cout << "Max node childs " << MaxNumChilds <<  " (chars " << MaxChildChars << " ) at character index "
                 << MaxChildsPosn << " using password " << PassWithMaxChilds << endl;
        }
        shared_ptr<ofstream> fout;
        ostream *out = &cout;
        if (outFile)
        {
            fout = make_shared<ofstream>();
            if (outType == OUT_BINARY)
                fout->open(outFile, ios_base::trunc | ios_base::binary);
            else
                fout->open(outFile, ios_base::trunc);
            out = fout.get();
        }
        if (!outFile && (outType == OUT_C_CODE))
            cout << "*/\n";

        if (outType == OUT_BINARY)
            i = OutputBinary(out, hashFile, charSet, childBits, childAddrs, nodeData, nodeEnds, ranks);
        else if (outType == OUT_TESTER)
            i = OutputTester(out, comments, ranks);
        else
            i = OutputCode(out, comments, charSet, childBits, root, childAddrs, nodeData, nodeEnds, ranks);

        if (fout)
        {
            fout->close();
        }
    }
    catch(const char *m)
    {
        cerr << m << endl;
        return 1;
    }
    catch(string m)
    {
        cerr << m << endl;
        return 1;
    }
    catch(...)
    {
        cerr << "Unhandled exception" << endl;
        return 1;
    }
    return 0;
}

/**********************************************************************************/
