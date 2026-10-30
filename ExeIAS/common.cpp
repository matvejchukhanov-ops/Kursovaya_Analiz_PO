#include "common.h"

#include <iomanip>
#include <sstream>

string toLower(string s)
{
    for (size_t i = 0; i < s.length(); i++)
        if (s[i] >= 'A' && s[i] <= 'Z')
            s[i] = s[i] - 'A' + 'a';
    return s;
}

bool containsNoCase(const string& text, const string& lowerPattern)
{
    return toLower(text).find(lowerPattern) != NPOS;
}

void addUnique(vector<string>& list, const string& value)
{
    if (find(list.begin(), list.end(), value) == list.end())
        list.push_back(value);
}

string hexVa(uint64_t v)
{
    ostringstream ss;
    ss << "0x" << uppercase << hex << setw(8) << setfill('0') << v;
    return ss.str();
}

// Число как в листингах: маленькие — десятичные, остальные — 0x...
string hexNum(uint64_t v)
{
    if (v < 10)
        return to_string(v);
    ostringstream ss;
    ss << "0x" << uppercase << hex << v;
    return ss.str();
}

// Без префикса, как в именах IDA: var_434, sub_401000
string hexPlain(uint64_t v)
{
    ostringstream ss;
    ss << uppercase << hex << v;
    return ss.str();
}

string severityName(Severity s)
{
    switch (s)
    {
    case CRITICAL: return "CRITICAL";
    case HIGH:     return "HIGH";
    case MEDIUM:   return "MEDIUM";
    case LOW:      return "LOW";
    default:       return "-";
    }
}
