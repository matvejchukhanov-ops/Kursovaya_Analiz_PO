// windows.h — до common.h: там using namespace std, а в SDK есть свой тип byte
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <fcntl.h>
#include <io.h>
#pragma comment(lib, "bcrypt.lib")
#endif

#include "input.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>

namespace fs = std::filesystem;

bool readInput(const string& path, vector<unsigned char>& bytes, string& error)
{
    if (path == "-")
    {
#ifdef _WIN32
        _setmode(_fileno(stdin), _O_BINARY);
#endif
        bytes.assign(istreambuf_iterator<char>(cin), istreambuf_iterator<char>());
    }
    else
    {
        error_code ec;
        if (!fs::exists(path, ec) || fs::is_directory(path, ec))
        {
            error = "файл не существует: " + path;
            return false;
        }
#ifdef _WIN32
        // 32-битная сборка иначе вместо System32 молча прочитает файл из SysWOW64
        PVOID redirection = nullptr;
        BOOL redirected = Wow64DisableWow64FsRedirection(&redirection);
#endif
        ifstream in(path, ios::binary);
        if (in.is_open())
            bytes.assign(istreambuf_iterator<char>(in), istreambuf_iterator<char>());
#ifdef _WIN32
        if (redirected)
            Wow64RevertWow64FsRedirection(redirection);
#endif
        if (!in.is_open())
        {
            error = "не удалось прочитать " + path + " (нет доступа или файл заблокирован антивирусом; используйте режим «-»)";
            return false;
        }
    }
    if (bytes.empty())
    {
        error = "файл пуст";
        return false;
    }
    return true;
}

string hashOf(const vector<unsigned char>& data, const wchar_t* algorithm)
{
#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD length = 0, written = 0;
    if (BCryptOpenAlgorithmProvider(&alg, algorithm, nullptr, 0) != 0)
        return "-";
    BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&length, sizeof(length), &written, 0);
    vector<unsigned char> digest(length);
    bool ok = BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0
           && BCryptHashData(hash, (PUCHAR)data.data(), (ULONG)data.size(), 0) == 0
           && BCryptFinishHash(hash, digest.data(), length, 0) == 0;
    if (hash)
        BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!ok)
        return "-";
    ostringstream ss;
    for (size_t i = 0; i < digest.size(); i++)
        ss << hex << setw(2) << setfill('0') << (int)digest[i];
    return ss.str();
#else
    return "-";
#endif
}

bool isPrintable(unsigned char c)
{
    return (c >= 32 && c < 127) || c == '\t';
}

bool isPeFile(const vector<unsigned char>& bytes)
{
    return bytes.size() > 2 && bytes[0] == 'M' && bytes[1] == 'Z';
}

vector<FoundString> extractStrings(const vector<unsigned char>& bytes, size_t minLength)
{
    vector<FoundString> found;

    string current;
    size_t start = 0;
    for (size_t i = 0; i <= bytes.size(); i++)
    {
        if (i < bytes.size() && isPrintable(bytes[i]))
        {
            if (current.empty())
                start = i;
            current += (char)bytes[i];
        }
        else
        {
            if (current.length() >= minLength)
                found.push_back({ start, current, false });
            current.clear();
        }
    }

    for (size_t parity = 0; parity < 2; parity++)
    {
        current.clear();
        for (size_t i = parity; i < bytes.size() + 2; i += 2)
        {
            bool ok = (i + 1 < bytes.size()) && isPrintable(bytes[i]) && bytes[i + 1] == 0;
            if (ok)
            {
                if (current.empty())
                    start = i;
                current += (char)bytes[i];
            }
            else
            {
                // UTF-16 короче 2 символов неотличима от ASCII-байта с нулём
                if (current.length() >= max<size_t>(minLength, 2))
                    found.push_back({ start, current, true });
                current.clear();
            }
        }
    }

    sort(found.begin(), found.end(), [](const FoundString& a, const FoundString& b) { return a.offset < b.offset; });
    return found;
}

string findStringsUtility(const string& selfPath)
{
#ifdef _WIN32
    fs::path dir = fs::path(selfPath).parent_path();
    const char* names[] = { "strings64.exe", "strings.exe" };
    for (const char* n : names)
    {
        error_code ec;
        fs::path local = dir / n;
        if (!dir.empty() && fs::exists(local, ec))
            return local.string();
        char buf[MAX_PATH];
        if (SearchPathA(nullptr, n, nullptr, MAX_PATH, buf, nullptr) > 0)
            return buf;
    }
#endif
    return "";
}

vector<string> runStringsUtility(const string& utility, const string& target)
{
    vector<string> lines;
#ifdef _WIN32
    // cmd /c снимает внешние кавычки, поэтому вся команда берётся в ещё одни
    string command = "\"\"" + utility + "\" -accepteula -nobanner -n 4 \"" + target + "\" 2>nul\"";
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe)
        return lines;
    char buf[4096];
    while (fgets(buf, sizeof(buf), pipe))
    {
        string line = buf;
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
            line.pop_back();
        lines.push_back(line);
    }
    _pclose(pipe);
#endif
    return lines;
}

string cleanLine(const string& line)
{
    string result;
    for (size_t i = 0; i < line.length(); i++)
    {
        unsigned char c = line[i];
        if (c >= 32 && c < 127)
            result += line[i];
    }

    size_t first = result.find_first_not_of(" \t");
    if (first == NPOS)
        return "";
    size_t last = result.find_last_not_of(" \t");
    return result.substr(first, last - first + 1);
}

// Отсев «мусора»: строка достаточно длинная и содержит хотя бы 3 буквы подряд
bool isMeaningful(const string& line)
{
    if (line.length() < MIN_LENGTH)
        return false;

    int run = 0;
    for (size_t i = 0; i < line.length(); i++)
    {
        char c = line[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
        {
            if (++run >= 3)
                return true;
        }
        else
            run = 0;
    }
    return false;
}

vector<string> normalizeStrings(const vector<string>& raw, size_t& meaningful)
{
    vector<string> data;
    set<string> seen;
    meaningful = 0;
    for (const string& line : raw)
    {
        string cleaned = cleanLine(line);
        if (!isMeaningful(cleaned))
            continue;
        meaningful++;
        if (seen.insert(cleaned).second)
            data.push_back(cleaned);
    }
    return data;
}
