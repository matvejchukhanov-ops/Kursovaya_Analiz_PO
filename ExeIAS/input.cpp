// windows.h — до common.h: там using namespace std, а в SDK есть свой тип byte
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <fcntl.h>
#include <io.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "user32.lib")
#endif

#include "input.h"

#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>

const size_t MAX_INPUT = 256u * 1024 * 1024;   // больше не читаем: защита от «архивной бомбы»

bool readFile(const fs::path& path, vector<unsigned char>& bytes, string& error)
{
    error_code ec;
    if (!fs::exists(path, ec) || fs::is_directory(path, ec))
    {
        error = "файл не существует: " + pathToUtf8(path);
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
        error = "не удалось прочитать " + pathToUtf8(path)
              + " (нет доступа или файл заблокирован антивирусом; образец ВПО проверяйте из архива)";
        return false;
    }
    if (bytes.empty())
    {
        error = "файл пуст";
        return false;
    }
    return true;
}

bool readStdin(vector<unsigned char>& bytes, string& error)
{
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
#endif
    bytes.assign(istreambuf_iterator<char>(cin), istreambuf_iterator<char>());
    if (bytes.empty())
    {
        error = "стандартный ввод пуст";
        return false;
    }
    return true;
}

#ifdef _WIN32
// Аргумент командной строки по правилам CommandLineToArgvW: кавычки и обратные косые перед ними
wstring quoteArg(const wstring& arg)
{
    wstring out = L"\"";
    size_t slashes = 0;
    for (wchar_t c : arg)
    {
        if (c == L'\\')
            slashes++;
        else
        {
            if (c == L'"')
                out.append(slashes + 1, L'\\');
            slashes = 0;
        }
        out += c;
    }
    out.append(slashes, L'\\');
    return out + L"\"";
}

// Запуск программы напрямую (без cmd.exe) с чтением её вывода.
// Имя файла из архива не может превратиться в команду оболочки
bool runProcess(const fs::path& exe, const vector<wstring>& args, vector<unsigned char>& output, DWORD& exitCode)
{
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE readPipe = nullptr, writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0))
        return false;
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);
    HANDLE nul = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                             OPEN_EXISTING, 0, nullptr);

    wstring cmd = quoteArg(exe.wstring());
    for (const wstring& a : args)
        cmd += L" " + quoteArg(a);

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = nul;
    si.hStdOutput = writePipe;
    si.hStdError = nul;
    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessW(exe.c_str(), cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(writePipe);
    if (nul != INVALID_HANDLE_VALUE)
        CloseHandle(nul);
    if (!ok)
    {
        CloseHandle(readPipe);
        return false;
    }

    char buf[65536];
    DWORD n = 0;
    while (ReadFile(readPipe, buf, sizeof(buf), &n, nullptr) && n > 0)
    {
        output.insert(output.end(), buf, buf + n);
        if (output.size() > MAX_INPUT)
        {
            TerminateProcess(pi.hProcess, 1);
            break;
        }
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(readPipe);
    return true;
}

// Системный tar.exe (bsdtar, есть в Windows 10 1803+), строго из System32
fs::path systemTar()
{
    wchar_t dir[MAX_PATH];
    UINT n = GetSystemDirectoryW(dir, MAX_PATH);
    return n ? fs::path(wstring(dir, n)) / L"tar.exe" : fs::path();
}

string ansiToUtf8(const string& s)
{
    int n = MultiByteToWideChar(CP_ACP, 0, s.data(), (int)s.size(), nullptr, 0);
    wstring w(n, L'\0');
    MultiByteToWideChar(CP_ACP, 0, s.data(), (int)s.size(), w.data(), n);
    return toUtf8(w);
}
#endif

bool isArchive(const fs::path& path)
{
    string ext = toLower(pathToUtf8(path.extension()));
    return ext == ".rar" || ext == ".zip" || ext == ".7z" || ext == ".tar" || ext == ".gz";
}

vector<string> listArchive(const fs::path& archive, string& error)
{
    vector<string> names;
#ifdef _WIN32
    fs::path tar = systemTar();
    error_code ec;
    if (tar.empty() || !fs::exists(tar, ec))
    {
        error = "не найден системный tar.exe (нужна Windows 10 1803 или новее)";
        return names;
    }
    vector<unsigned char> out;
    DWORD code = 1;
    if (!runProcess(tar, { L"-tf", archive.wstring() }, out, code) || code != 0)
    {
        error = "не удалось прочитать архив (возможно, он защищён паролем или повреждён)";
        return names;
    }
    string line;
    for (unsigned char c : out)
    {
        if (c == '\n')
        {
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            if (!line.empty() && line.back() != '/')     // каталоги пропускаем
                names.push_back(ansiToUtf8(line));
            line.clear();
        }
        else
            line += (char)c;
    }
    if (!line.empty() && line.back() != '/')
        names.push_back(ansiToUtf8(line));
    if (names.empty())
        error = "архив пуст";
#else
    error = "чтение архивов поддерживается только в Windows";
#endif
    return names;
}

#ifdef _WIN32
// Снимок архива во временной папке: список и извлечение делаются по одной и той же копии,
// архив нельзя подменить между ними. Копируется сам архив, образец из него не распаковывается
struct ArchiveSnapshot
{
    fs::path path;
    ~ArchiveSnapshot()
    {
        error_code ec;
        if (!path.empty())
            fs::remove(path, ec);
    }
};

bool makeSnapshot(const fs::path& archive, ArchiveSnapshot& snap)
{
    wchar_t dir[MAX_PATH], file[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, dir) || !GetTempFileNameW(dir, L"ias", 0, file))
        return false;
    snap.path = fs::path(file).replace_extension(archive.extension());
    error_code ec;
    fs::remove(fs::path(file), ec);
    return fs::copy_file(archive, snap.path, fs::copy_options::overwrite_existing, ec);
}
#endif

bool readFromArchive(const fs::path& archive, const string& member, vector<unsigned char>& bytes, string& error)
{
#ifdef _WIN32
    // имя, начинающееся с «-», tar принял бы за ключ, а * ? [ ] \ — за шаблон: тогда в поток
    // попало бы содержимое нескольких файлов, и анализировался бы не тот файл, что указан в отчёте
    if (member.empty() || member[0] == '-' || member.find_first_of("*?[]\\") != NPOS)
    {
        error = "недопустимое имя файла в архиве «" + member + "» (символы шаблона); перепакуйте архив";
        return false;
    }
    ArchiveSnapshot snap;
    if (!makeSnapshot(archive, snap))
    {
        error = "не удалось скопировать архив во временную папку";
        return false;
    }
    // по той же причине имя должно встречаться ровно один раз, и под ним не должно быть
    // «подкаталога»: по имени каталога tar отдаёт и всё его содержимое
    vector<string> names = listArchive(snap.path, error);
    bool nested = false;
    for (const string& n : names)
        if (n.size() > member.size() && n.compare(0, member.size(), member) == 0
            && (n[member.size()] == '/' || n[member.size()] == '\\'))
            nested = true;
    if (count(names.begin(), names.end(), member) != 1 || nested)
    {
        if (error.empty())
            error = "файл «" + member + "» не найден в архиве, встречается в нём несколько раз или совпадает с именем каталога";
        return false;
    }
    fs::path tar = systemTar();
    DWORD code = 1;
    if (!runProcess(tar, { L"-xOf", snap.path.wstring(), fromUtf8(member) }, bytes, code) || code != 0 || bytes.empty())
    {
        error = "не удалось извлечь «" + member + "» из архива";
        return false;
    }
    if (bytes.size() > MAX_INPUT)
    {
        error = "файл в архиве больше 256 МБ";
        return false;
    }
    return true;
#else
    error = "чтение архивов поддерживается только в Windows";
    return false;
#endif
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

// strings.exe ищется рядом с ExeIAS.exe и в абсолютных каталогах PATH. Текущая папка и папка
// с образцом исключены: иначе подложенный рядом с образцом strings.exe был бы запущен
#ifdef _WIN32
// Каталог для сравнения: полный путь в нижнем регистре (в Windows «C:\Users» и «c:\users» — одно и то же)
wstring dirKey(const fs::path& p)
{
    error_code ec;
    wstring s = fs::weakly_canonical(fs::absolute(p, ec), ec).wstring();
    while (s.size() > 3 && (s.back() == L'\\' || s.back() == L'/'))
        s.pop_back();
    if (!s.empty())
        CharLowerBuffW(s.data(), (DWORD)s.size());
    return s;
}
#endif

fs::path findStringsUtility(const fs::path& selfPath, const fs::path& samplePath)
{
#ifdef _WIN32
    vector<fs::path> dirs;
    if (!selfPath.empty())
        dirs.push_back(selfPath.parent_path());
    // исключаются папка образца и текущая папка — кроме случая, когда текущая папка и есть папка ИАС
    // (запуск двойным щелчком); папка ИАС, совпавшая с папкой образца, тоже исключается
    error_code ec;
    set<wstring> excluded;
    wstring current = dirKey(fs::current_path(ec));
    if (selfPath.empty() || current != dirKey(selfPath.parent_path()))
        excluded.insert(current);
    if (!samplePath.empty())
        excluded.insert(dirKey(fs::absolute(samplePath, ec).parent_path()));
    DWORD length = GetEnvironmentVariableW(L"PATH", nullptr, 0);
    if (length > 0)
    {
        wstring list(length, L'\0');
        list.resize(GetEnvironmentVariableW(L"PATH", list.data(), length));
        size_t start = 0;
        while (start <= list.size())
        {
            size_t end = list.find(L';', start);
            wstring item = list.substr(start, end == wstring::npos ? wstring::npos : end - start);
            start = end == wstring::npos ? list.size() + 1 : end + 1;
            fs::path dir(item);
            if (!item.empty() && dir.is_absolute())
                dirs.push_back(dir);
        }
    }
    const wchar_t* names[] = { L"strings64.exe", L"strings.exe" };
    for (const fs::path& dir : dirs)
    {
        // и папка самой ИАС исключается, если ExeIAS.exe лежит рядом с образцом или запущен из неё
        if (excluded.count(dirKey(dir)))
            continue;
        for (const wchar_t* n : names)
        {
            fs::path candidate = dir / n;
            if (fs::is_regular_file(candidate, ec))
                return candidate;
        }
    }
#endif
    return fs::path();
}

vector<string> runStringsUtility(const fs::path& utility, const fs::path& target)
{
    vector<string> lines;
#ifdef _WIN32
    vector<unsigned char> out;
    DWORD code = 1;
    if (!runProcess(utility, { L"-accepteula", L"-nobanner", L"-n", L"4", target.wstring() }, out, code) || code != 0)
        return lines;
    string line;
    for (unsigned char c : out)
    {
        if (c == '\n')
        {
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            lines.push_back(line);
            line.clear();
        }
        else
            line += (char)c;
    }
    if (!line.empty())
        lines.push_back(line);
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
        if (cleaned.length() > MAX_LINE)
            cleaned.resize(MAX_LINE);
        meaningful++;
        if (seen.insert(cleaned).second)
            data.push_back(cleaned);
    }
    return data;
}
