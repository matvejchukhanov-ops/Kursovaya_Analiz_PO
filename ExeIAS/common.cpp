// windows.h — до common.h: там using namespace std, а в SDK есть свой тип byte
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

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

string toUtf8(const wstring& w)
{
#ifdef _WIN32
    if (w.empty())
        return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
#else
    return string(w.begin(), w.end());
#endif
}

wstring fromUtf8(const string& s)
{
#ifdef _WIN32
    if (s.empty())
        return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
#else
    return wstring(s.begin(), s.end());
#endif
}

fs::path pathFromUtf8(const string& s)
{
    return fs::path(fromUtf8(s));
}

string pathToUtf8(const fs::path& p)
{
    return toUtf8(p.wstring());
}
