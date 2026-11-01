// Фаззинг конвейера анализа: runAnalysis() на испорченных и специально собранных PE.
//
// Безопасность: входные данные НИКОГДА не запускаются и не пишутся на диск. Whiter.a.exe читается
// из архива в память (readFromArchive), мутации живут только в памяти; воспроизведение — по значению
// seed, а не по файлу. На диск runAnalysis пишет только текстовые отчёты во временную папку.
//
// Режимы:
//   fuzz_analysis --supervise --iters N [--base B] [--log файл]   перезапускает рабочий процесс после сбоя
//   fuzz_analysis --worker --start K --end N [--base B]           одна серия итераций
//   fuzz_analysis --seed 0x...                                    одна итерация для воспроизведения
//   fuzz_analysis --seed 0x... --describe                         только показать, что будет подано на вход
//   fuzz_analysis --file путь                                     замер на одном файле (файл не запускается)
//   fuzz_analysis --selftest oob|crash|stack|throw|hang|mem       намеренный сбой: стенд должен его заметить
//   fuzz_analysis --seed 1 --scenario importnames                 отдельный сценарий вне общего потока
// Общие ключи: --hang-sec S (20), --mem-mb M, --stack-kb K, --rar путь
//
// Коды выхода рабочего процесса: 0 норма, 2 аппаратное исключение, 3 зависание, 4 исключение C++,
// 5 превышение памяти, 6 abort, 7 проверка отладочной CRT, 8 недопустимый параметр CRT, 9 нет образцов.
// Отчёт AddressSanitizer идёт в stderr, рабочий процесс при этом завершается с ненулевым кодом.

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <crtdbg.h>

#include "common.h"
#include "input.h"
#include "pipeline.h"

#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <exception>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

typedef vector<unsigned char> Bytes;

// ================================================================ ГПСЧ (свой — результат не зависит от версии STL)

struct Rng
{
    uint64_t s;
    uint64_t next()
    {
        uint64_t z = (s += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }
    uint64_t below(uint64_t n) { return n ? next() % n : 0; }
    bool pct(int p) { return below(100) < (uint64_t)p; }
    uint32_t u32() { return (uint32_t)next(); }
    template <class T, size_t N> T pick(const T (&a)[N]) { return a[below(N)]; }
};

static string hex32(uint64_t v)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)v);
    return buf;
}

// ================================================================ чтение и запись с проверкой границ

static void put8(Bytes& b, size_t o, uint8_t v) { if (o < b.size()) b[o] = v; }
static void put16(Bytes& b, size_t o, uint16_t v) { put8(b, o, (uint8_t)v); put8(b, o + 1, (uint8_t)(v >> 8)); }
static void put32(Bytes& b, size_t o, uint32_t v) { put16(b, o, (uint16_t)v); put16(b, o + 2, (uint16_t)(v >> 16)); }
static void put64(Bytes& b, size_t o, uint64_t v) { put32(b, o, (uint32_t)v); put32(b, o + 4, (uint32_t)(v >> 32)); }
static uint32_t get8(const Bytes& b, size_t o) { return o < b.size() ? b[o] : 0; }
static uint32_t get16(const Bytes& b, size_t o) { return get8(b, o) | (get8(b, o + 1) << 8); }
static uint32_t get32(const Bytes& b, size_t o) { return get16(b, o) | (get16(b, o + 2) << 16); }
static uint64_t get64(const Bytes& b, size_t o) { return get32(b, o) | ((uint64_t)get32(b, o + 4) << 32); }

// Опасные значения для смещений и размеров
static uint32_t nasty(Rng& r, size_t fileSize)
{
    switch (r.below(16))
    {
    case 0:  return 0;
    case 1:  return 1;
    case 2:  return 0x7FFFFFFF;
    case 3:  return 0x80000000;
    case 4:  return 0xFFFFFFFF;
    case 5:  return 0xFFFFFFFC;
    case 6:  return 0xFFFFF000;
    case 7:  return 0xFFFFFFFF - (uint32_t)fileSize;
    case 8:  return (uint32_t)fileSize;
    case 9:  return (uint32_t)fileSize - 1;
    case 10: return (uint32_t)fileSize - 4;
    case 11: return (uint32_t)fileSize + 1;
    case 12: return 0x10000000;
    case 13: return 0x1000;
    case 14: return (uint32_t)r.below(fileSize + 1);
    default: return r.u32();
    }
}

// ================================================================ заголовки текущего образа

struct View
{
    bool ok = false, is64 = false;
    size_t nt = 0, fh = 0, oh = 0, dd = 0, sh = 0;
    uint32_t nsec = 0;
    uint64_t imageBase = 0;
};

static View viewOf(const Bytes& b)
{
    View v;
    if (b.size() < 0x40)
        return v;
    v.nt = get32(b, 0x3C);
    if (v.nt > b.size() || v.nt + 0x18 > b.size() || get32(b, v.nt) != 0x4550)
        return v;
    v.fh = v.nt + 4;
    v.oh = v.fh + 20;
    uint32_t magic = get16(b, v.oh);
    if (magic != 0x10B && magic != 0x20B)
        return v;
    v.is64 = magic == 0x20B;
    v.dd = v.oh + (v.is64 ? 112 : 96);
    v.sh = v.oh + get16(b, v.fh + 16);
    v.nsec = get16(b, v.fh + 2);
    v.imageBase = v.is64 ? get64(b, v.oh + 24) : get32(b, v.oh + 28);
    v.ok = true;
    return v;
}

struct SecView { size_t hdr; uint32_t vsize, va, rawSize, rawPtr, chars; };

static vector<SecView> sectionsOf(const Bytes& b, const View& v)
{
    vector<SecView> list;
    for (uint32_t i = 0; i < v.nsec && i < 96; i++)
    {
        size_t h = v.sh + i * 40;
        if (h + 40 > b.size())
            break;
        list.push_back({ h, get32(b, h + 8), get32(b, h + 12), get32(b, h + 16), get32(b, h + 20), get32(b, h + 36) });
    }
    return list;
}

static size_t rvaOff(const vector<SecView>& secs, size_t fileSize, uint32_t rva)
{
    for (const SecView& s : secs)
        if (rva >= s.va && (uint64_t)rva < (uint64_t)s.va + s.rawSize)
        {
            uint64_t o = (uint64_t)s.rawPtr + (rva - s.va);
            return o < fileSize ? (size_t)o : NPOS;
        }
    return NPOS;
}

// Диапазон файла, занятый кодом: первая выполняемая секция, иначе любая непустая
static bool codeRange(const Bytes& b, const View& v, size_t& begin, size_t& len, uint64_t& va)
{
    vector<SecView> secs = sectionsOf(b, v);
    const SecView* found = nullptr;
    for (const SecView& s : secs)
        if ((s.chars & 0x20000020) && s.rawPtr < b.size() && s.rawSize)
        {
            found = &s;
            break;
        }
    if (!found)
        for (const SecView& s : secs)
            if (s.rawPtr < b.size() && s.rawSize)
            {
                found = &s;
                break;
            }
    if (!found)
        return false;
    begin = found->rawPtr;
    len = min<uint64_t>(found->rawSize, b.size() - begin);
    va = v.imageBase + found->va;
    return len > 0;
}

// ================================================================ потоки машинного кода

struct StormCtx
{
    uint64_t textVa = 0;
    size_t textLen = 0;
    vector<uint64_t> iat;       // адреса настоящих ячеек IAT
    vector<uint64_t> strings;   // адреса строк
};

static const char* const STORM_NAMES[] = {
    "jmpself2", "jmpself5", "callself", "e8rand", "e8intext", "ff15bad", "ff25bad", "ff15iat", "repruns", "strcatblk",
    "tinyfuncs", "prologues", "pushimm", "calladdesp", "pusha", "retn", "rand", "insnlike", "strrefs", "popa",
};
const int STORM_COUNT = sizeof(STORM_NAMES) / sizeof(STORM_NAMES[0]);

static void storm(Rng& r, Bytes& b, size_t pos, size_t len, uint64_t va, bool is64, const StormCtx& c, int kind)
{
    const size_t end = min(b.size(), pos + len);
    size_t p = pos;
    auto w8 = [&](uint32_t x) { if (p < end) b[p] = (uint8_t)x; p++; };
    auto w32 = [&](uint32_t x) { for (int i = 0; i < 4; i++) w8((x >> (8 * i)) & 0xFF); };
    auto curVa = [&]() { return va + (p - pos); };
    auto textTarget = [&]() { return c.textLen ? c.textVa + r.below(c.textLen) : va + r.below(len + 1); };
    auto someString = [&]() { return c.strings.empty() ? textTarget() : c.strings[r.below(c.strings.size())]; };

    while (p < end)
    {
        switch (kind)
        {
        case 0: w8(0xEB); w8(0xFE); break;
        case 1: w8(0xE9); w32(0xFFFFFFFB); break;
        case 2: w8(0xE8); w32(0xFFFFFFFB); break;
        case 3: w8(0xE8); w32(r.u32()); break;
        case 4: { uint64_t t = textTarget(); uint64_t from = curVa(); w8(0xE8); w32((uint32_t)(t - (from + 5))); break; }
        case 5: w8(0xFF); w8(0x15); w32(nasty(r, b.size())); break;
        case 6: w8(0xFF); w8(0x25); w32(nasty(r, b.size())); break;
        case 7:
            if (c.iat.empty())
            {
                w8(0xFF); w8(0x15); w32(r.u32());
            }
            else
            {
                uint64_t t = c.iat[r.below(c.iat.size())];
                uint64_t from = curVa();
                w8(0xFF); w8(0x15); w32(is64 ? (uint32_t)(t - (from + 6)) : (uint32_t)t);
            }
            break;
        case 8:
        {
            uint64_t k = 1 + r.below(20);
            for (uint64_t i = 0; i < k; i++)
                w8(r.pct(50) ? 0xF3 : 0xF2);
            static const uint8_t ops[] = { 0xA4, 0xA5, 0xAA, 0xAB, 0xAE, 0xAF, 0xA6, 0xA7 };
            w8(r.pick(ops));
            break;
        }
        case 9:     // lea edi,[ebp-100h]; lea esi,[ebp-100h]; repne scasb; rep movsb
            w8(0x8D); w8(0xBD); w32(0xFFFFFF00);
            w8(0x8D); w8(0xB5); w32(0xFFFFFF00);
            w8(0xF2); w8(0xAE); w8(0xF3); w8(0xA4);
            break;
        case 10:    // ret; call <следующая функция>: граница функции распознаётся по ret перед целью call
            w8(0xC3); w8(0xE8); w32(1);
            break;
        case 11:
            w8(0x55); w8(0x8B); w8(0xEC); w8(0x5D); w8(0xC3); w8(0xCC);
            break;
        case 12: w8(0x68); w32((uint32_t)someString()); break;
        case 13:    // call x; add esp, imm32 — число аргументов берётся из непосредственного операнда
        {
            uint64_t t = textTarget(), from = curVa();
            w8(0xE8); w32((uint32_t)(t - (from + 5)));
            static const uint32_t imms[] = { 4, 0x10, 0x1000, 0x100000, 0x1000000, 0x7FFFFFFF, 0x7FFFFFFC, 0x40000000, 0xFFFFFFFC };
            w8(0x81); w8(0xC4); w32(r.pick(imms));
            break;
        }
        case 14: w8(0x60); break;
        case 15:    // ret; ret N; call <ret N> — у цели call самый большой ret N
        {
            uint64_t target = curVa() + 1;
            w8(0xC3); w8(0xC2); w8(0xFC); w8(0xFF);
            uint64_t from = curVa();
            w8(0xE8); w32((uint32_t)(target - (from + 5)));
            break;
        }
        case 16: w8(r.u32() & 0xFF); break;
        case 17:
        {
            static const uint8_t ops[] = { 0x50, 0x51, 0x53, 0x55, 0x56, 0x57, 0x58, 0x5B, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x90, 0xC3, 0xC9, 0xCC, 0x99,
                                           0x9C, 0x9D, 0x91, 0x97, 0xA4, 0xA5, 0xAE };
            static const uint8_t mods[] = { 0x89, 0x8B, 0x8D, 0x87, 0x86, 0x88, 0x8A, 0x33, 0x2B, 0x31, 0x29, 0x3B, 0x85, 0x8F, 0xFF, 0xFE, 0xF7, 0xF6,
                                            0xC7, 0xC6, 0x81, 0x83, 0x80, 0x69, 0x6B, 0xC1, 0xD1, 0xD3, 0x63 };
            switch (r.below(4))
            {
            case 0: w8(r.pick(ops)); break;
            case 1: w8(r.pick(mods)); w8(r.u32() & 0xFF); break;
            case 2: w8(r.pick(mods)); w8(0x45 + 8 * r.below(8)); w8(r.u32() & 0xFF); break;   // [ebp+disp8]
            default:
                if (is64)
                    w8(0x40 + r.below(16));
                w8(r.pick(mods)); w8(0xC0 + r.below(64));
                break;
            }
            break;
        }
        case 18:
            switch (r.below(4))
            {
            case 0: w8(0xB8 + r.below(8)); w32((uint32_t)someString()); break;
            case 1: w8(0xA1); w32((uint32_t)someString()); break;
            case 2: w8(0x8B); w8(0x05); w32((uint32_t)someString()); break;
            default:
            {
                uint64_t from = curVa();
                w8(0x48); w8(0x8D); w8(0x05); w32((uint32_t)(someString() - (from + 7)));
                break;
            }
            }
            break;
        default: w8(0x61); break;
        }
    }
}

// Обрыв инструкции на самой границе диапазона
static void truncatedTail(Rng& r, Bytes& b, size_t pos, size_t len)
{
    static const uint8_t patterns[][4] = {
        { 0xE8, 0, 0, 0 }, { 0xE9, 0, 0, 0 }, { 0xFF, 0x15, 0, 0 }, { 0xFF, 0x25, 0, 0 }, { 0x0F, 0x38, 0, 0 }, { 0x0F, 0x3A, 0, 0 },
        { 0x0F, 0x80, 0, 0 }, { 0x66, 0x66, 0x66, 0x66 }, { 0x68, 0, 0, 0 }, { 0x81, 0xC4, 0, 0 }, { 0xC7, 0x05, 0, 0 }, { 0xA1, 0, 0, 0 },
        { 0xF3, 0xF3, 0xF3, 0xF3 }, { 0x48, 0x8D, 0x05, 0 }, { 0x8B, 0x84, 0, 0 }, { 0xEA, 0, 0, 0 },
    };
    const uint8_t* p = patterns[r.below(sizeof(patterns) / 4)];
    size_t n = 1 + r.below(4);
    if (len < n)
        return;
    for (size_t i = 0; i < n; i++)
        put8(b, pos + len - n + i, p[i]);
}

// ================================================================ сборка PE с нуля

struct PeSec
{
    string name;
    uint32_t rva = 0, chars = 0;
    Bytes data;
};

struct PeBuild
{
    bool is64 = false;
    uint64_t imageBase = 0x400000;
    uint32_t entryRva = 0x1000;
    uint32_t importRva = 0, importSize = 0;
    bool rich = false;
    vector<PeSec> secs;
};

const uint32_t CHARS_CODE = 0x60000020, CHARS_RDATA = 0x40000040;

static uint32_t alignUp(uint64_t v, uint32_t a) { return (uint32_t)((v + a - 1) / a * a); }

static Bytes buildPe(const PeBuild& p, Rng& r)
{
    const uint32_t lfanew = 0x100;
    const uint32_t optSize = p.is64 ? 240 : 224;
    const uint32_t headers = alignUp((uint64_t)lfanew + 24 + optSize + 40ull * p.secs.size(), 0x200);
    uint64_t total = headers;
    for (const PeSec& s : p.secs)
        total += alignUp(s.data.size(), 0x200);
    Bytes b((size_t)total, 0);

    put16(b, 0, 0x5A4D);
    put32(b, 0x3C, lfanew);
    if (p.rich)
    {
        uint32_t key = r.u32();
        size_t o = 0x80;
        put32(b, o, 0x536E6144 ^ key);
        for (int i = 1; i < 4; i++)
            put32(b, o + i * 4, key);
        o += 16;
        for (int i = 0; i < 4; i++, o += 8)
        {
            put32(b, o, r.u32() ^ key);
            put32(b, o + 4, r.u32() ^ key);
        }
        put32(b, o, 0x68636952);
        put32(b, o + 4, key);
    }

    size_t fh = lfanew + 4, oh = fh + 20;
    put32(b, lfanew, 0x4550);
    put16(b, fh, p.is64 ? 0x8664 : 0x14C);
    put16(b, fh + 2, (uint16_t)p.secs.size());
    put32(b, fh + 4, r.u32());
    put16(b, fh + 16, (uint16_t)optSize);
    put16(b, fh + 18, 0x0102);
    put16(b, oh, p.is64 ? 0x20B : 0x10B);
    put8(b, oh + 2, 14);
    put32(b, oh + 16, p.entryRva);
    if (p.is64)
        put64(b, oh + 24, p.imageBase);
    else
        put32(b, oh + 28, (uint32_t)p.imageBase);
    put32(b, oh + 32, 0x1000);
    put32(b, oh + 36, 0x200);
    put32(b, oh + 60, headers);
    put16(b, oh + 68, 3);
    put32(b, oh + (p.is64 ? 108 : 92), 16);
    size_t dd = oh + (p.is64 ? 112 : 96);
    put32(b, dd + 8, p.importRva);
    put32(b, dd + 12, p.importSize);

    size_t sh = oh + optSize;
    uint32_t raw = headers;
    uint64_t lastEnd = 0x1000;
    for (const PeSec& s : p.secs)
    {
        for (size_t i = 0; i < 8 && i < s.name.size(); i++)
            put8(b, sh + i, s.name[i]);
        put32(b, sh + 8, (uint32_t)s.data.size());
        put32(b, sh + 12, s.rva);
        put32(b, sh + 16, alignUp(s.data.size(), 0x200));
        put32(b, sh + 20, raw);
        put32(b, sh + 36, s.chars);
        if (!s.data.empty())
            memcpy(b.data() + raw, s.data.data(), s.data.size());
        raw += alignUp(s.data.size(), 0x200);
        sh += 40;
        lastEnd = max<uint64_t>(lastEnd, (uint64_t)s.rva + s.data.size());
    }
    put32(b, oh + 56, alignUp(lastEnd, 0x1000));
    return b;
}

// Таблица импорта; возвращает адреса (RVA) ячеек IAT по именам функций
struct ImportSpec { string dll; vector<string> funcs; };

static Bytes makeImports(uint32_t rva, const vector<ImportSpec>& dlls, bool is64, map<string, uint32_t>& iatRva)
{
    const uint32_t ptr = is64 ? 8 : 4;
    uint32_t cur = (uint32_t)(dlls.size() + 1) * 20;
    struct Layout { uint32_t ilt, iat, name; vector<uint32_t> hints; };
    vector<Layout> layout;
    for (const ImportSpec& d : dlls)
    {
        Layout l;
        l.ilt = cur;
        cur += (uint32_t)(d.funcs.size() + 1) * ptr;
        l.iat = cur;
        cur += (uint32_t)(d.funcs.size() + 1) * ptr;
        l.name = cur;
        cur += (uint32_t)d.dll.size() + 1;
        for (const string& f : d.funcs)
        {
            l.hints.push_back(cur);
            cur += 2 + (uint32_t)f.size() + 1;
        }
        layout.push_back(l);
    }
    Bytes b(cur, 0);
    for (size_t i = 0; i < dlls.size(); i++)
    {
        const Layout& l = layout[i];
        put32(b, i * 20, rva + l.ilt);
        put32(b, i * 20 + 12, rva + l.name);
        put32(b, i * 20 + 16, rva + l.iat);
        memcpy(b.data() + l.name, dlls[i].dll.data(), dlls[i].dll.size());
        for (size_t k = 0; k < dlls[i].funcs.size(); k++)
        {
            const string& f = dlls[i].funcs[k];
            memcpy(b.data() + l.hints[k] + 2, f.data(), f.size());
            if (is64)
            {
                put64(b, l.ilt + k * 8, rva + l.hints[k]);
                put64(b, l.iat + k * 8, rva + l.hints[k]);
            }
            else
            {
                put32(b, l.ilt + k * 4, rva + l.hints[k]);
                put32(b, l.iat + k * 4, rva + l.hints[k]);
            }
            iatRva[f] = rva + l.iat + (uint32_t)k * ptr;
        }
    }
    return b;
}

static const char* const API_NAMES[] = {
    "CreateFileA", "CreateFileW", "WriteFile", "ReadFile", "DeleteFileA", "DeleteFileW", "CopyFileA", "MoveFileExA", "FindFirstFileA", "FindNextFileA",
    "GetSystemDirectoryA", "GetWindowsDirectoryA", "GetTempPathA", "GetTempFileNameA", "GetModuleFileNameA", "GetCommandLineA", "CreateProcessA", "WinExec",
    "SetFileAttributesA", "RegCreateKeyA", "RegOpenKeyExA", "RegSetValueExA", "RegQueryValueExA", "CreateMutexA", "GetLogicalDriveStringsA", "VirtualAlloc",
    "LoadLibraryA", "GetProcAddress", "ExitProcess", "lstrcpyA", "lstrcatA", "wsprintfA", "MessageBoxA", "RemoveDirectoryA", "GetLogicalDrives", "GetDriveTypeA",
};

static size_t sizePick(Rng& r)
{
    uint64_t c = r.below(100);
    if (c < 70) return 256 + (size_t)r.below(16 * 1024);
    if (c < 90) return 64 * 1024 + (size_t)r.below(192 * 1024);
    if (c < 98) return 512 * 1024 + (size_t)r.below(1536 * 1024);
    return 4 * 1024 * 1024 + (size_t)r.below(4 * 1024 * 1024);
}

// Скелет: .text, .rdata со строками, .idata с настоящими импортами
struct Skeleton
{
    PeBuild p;
    StormCtx ctx;
    map<string, uint32_t> iat;
    uint32_t rdataRva = 0;
};

static Skeleton skeleton(Rng& r, bool is64, size_t textSize, const Bytes& rdata, const vector<uint32_t>& stringOffsets)
{
    Skeleton s;
    s.p.is64 = is64;
    s.p.imageBase = is64 ? 0x140000000ull : 0x400000ull;
    if (r.pct(5))
    {
        const uint64_t bases[] = { 0, 0x10000, 0xFFFF0000ull, 0xFFFFFFFFFFFF0000ull, 0x7FFFFFFFFFFF0000ull };
        s.p.imageBase = r.pick(bases);
    }
    s.p.rich = r.pct(30);

    PeSec text;
    text.name = ".text";
    text.rva = 0x1000;
    text.chars = CHARS_CODE;
    text.data.assign(textSize, 0x90);

    PeSec rd;
    rd.name = ".rdata";
    rd.rva = alignUp((uint64_t)text.rva + textSize, 0x1000);
    rd.chars = CHARS_RDATA;
    rd.data = rdata;
    s.rdataRva = rd.rva;

    uint32_t idataRva = alignUp((uint64_t)rd.rva + max<size_t>(rdata.size(), 1), 0x1000);
    vector<ImportSpec> dlls(1);
    dlls[0].dll = "KERNEL32.dll";
    for (const char* n : API_NAMES)
        dlls[0].funcs.push_back(n);
    ImportSpec crt;
    crt.dll = "MSVCRT.dll";
    crt.funcs = { "fopen", "strcpy", "strcat", "sprintf", "malloc" };
    dlls.push_back(crt);
    PeSec idata;
    idata.name = ".idata";
    idata.rva = idataRva;
    idata.chars = 0xC0000040;
    idata.data = makeImports(idataRva, dlls, is64, s.iat);
    s.p.importRva = idataRva;
    s.p.importSize = (uint32_t)(dlls.size() + 1) * 20;

    s.p.secs.push_back(text);
    s.p.secs.push_back(rd);
    s.p.secs.push_back(idata);

    s.ctx.textVa = s.p.imageBase + text.rva;
    s.ctx.textLen = textSize;
    for (const auto& item : s.iat)
        s.ctx.iat.push_back(s.p.imageBase + item.second);
    for (uint32_t o : stringOffsets)
        s.ctx.strings.push_back(s.p.imageBase + rd.rva + o);
    return s;
}

static void addCStr(Bytes& b, vector<uint32_t>& offs, const string& s)
{
    offs.push_back((uint32_t)b.size());
    b.insert(b.end(), s.begin(), s.end());
    b.push_back(0);
}

static Bytes defaultRdata(vector<uint32_t>& offs)
{
    Bytes b;
    static const char* const strs[] = {
        "%s%s", "%s\\%s", "%s%s%s%s", "%s\\*.*", "w", "wb", "c:\\windows\\system32\\evil.exe", "*.*", "\\autoexec.bat", "%d %x %s",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "cmd.exe /c del", "http://example.invalid/a.exe", "kernel32.dll", "c:\\", "%", "%%", "%l", "%.",
    };
    for (const char* s : strs)
        addCStr(b, offs, s);
    return b;
}

// Байты в буфере .text с контролем размера
struct Emit
{
    Bytes& b;
    size_t p = 0;
    bool full() const { return p + 64 >= b.size(); }
    void u8(uint32_t x) { if (p < b.size()) b[p] = (uint8_t)x; p++; }
    void u32(uint32_t x) { for (int i = 0; i < 4; i++) u8((x >> (8 * i)) & 0xFF); }
};

// ---------------------------------------------------------------- сценарии

static Bytes scratchGarbage(Rng& r, string& d)
{
    PeBuild p;
    p.is64 = r.pct(50);
    p.imageBase = p.is64 ? 0x140000000ull : 0x400000ull;
    p.rich = r.pct(30);
    uint32_t rva = 0x1000;
    size_t count = r.below(9);
    for (size_t i = 0; i < count; i++)
    {
        PeSec s;
        s.name = string(".g") + to_string(i);
        s.rva = rva;
        s.chars = r.pct(50) ? CHARS_CODE : r.u32();
        s.data.resize(r.pct(20) ? 0 : 1 + (size_t)r.below(32 * 1024));
        for (auto& c : s.data)
            c = (unsigned char)r.u32();
        rva = alignUp((uint64_t)rva + s.data.size() + 1, 0x1000);
        p.secs.push_back(s);
    }
    p.entryRva = count ? 0x1000 + (uint32_t)r.below(rva) : r.u32();
    d += "scratch.garbage(" + string(p.is64 ? "pe32+" : "pe32") + ",secs=" + to_string(count) + ")";
    return buildPe(p, r);
}

static Bytes scratchStorm(Rng& r, string& d)
{
    bool is64 = r.pct(50);
    size_t textSize = sizePick(r);
    vector<uint32_t> offs;
    Bytes rdata = defaultRdata(offs);
    Skeleton s = skeleton(r, is64, textSize, rdata, offs);
    Bytes& text = s.p.secs[0].data;
    d += "scratch.storm(" + string(is64 ? "pe32+" : "pe32") + ",text=" + to_string(textSize);
    int parts = 1 + (int)r.below(3);
    for (int i = 0; i < parts; i++)
    {
        size_t from = i == 0 ? 0 : (size_t)r.below(textSize);
        size_t len = i == 0 ? textSize : (size_t)r.below(textSize - from + 1);
        int kind = (int)r.below(STORM_COUNT);
        d += string(",") + STORM_NAMES[kind];
        storm(r, text, from, len, s.ctx.textVa + from, is64, s.ctx, kind);
    }
    if (r.pct(40))
    {
        truncatedTail(r, text, 0, textSize);
        d += ",tail";
    }
    s.p.entryRva = 0x1000;
    d += ")";
    return buildPe(s.p, r);
}

// Цикл в импорте: дескрипторы и таблицы имён указывают на себя, имена без завершающего нуля
static Bytes scratchImportLoop(Rng& r, string& d)
{
    bool is64 = r.pct(50);
    PeBuild p;
    p.is64 = is64;
    p.imageBase = is64 ? 0x140000000ull : 0x400000ull;
    const uint32_t ptr = is64 ? 8 : 4;
    uint32_t rva = 0x2000;
    int variant = (int)r.below(5);
    uint32_t descriptors = r.pct(50) ? 512 + (uint32_t)r.below(16) : 1 + (uint32_t)r.below(64);
    uint32_t thunks = r.pct(50) ? 4096 + (uint32_t)r.below(16) : 1 + (uint32_t)r.below(256);
    uint32_t nameTail = 300;
    uint32_t dsz = (descriptors + 1) * 20;
    Bytes b(dsz + (thunks + 1) * ptr + nameTail, 'A');
    uint32_t ilt = rva + dsz, nameRva = rva + dsz + (thunks + 1) * ptr;
    for (uint32_t i = 0; i < descriptors; i++)
    {
        size_t o = i * 20;
        switch (variant)
        {
        case 0:     // все дескрипторы — одна и та же таблица
            put32(b, o, ilt); put32(b, o + 12, nameRva); put32(b, o + 16, ilt);
            break;
        case 1:     // OriginalFirstThunk указывает на сам дескриптор
            put32(b, o, rva + (uint32_t)o); put32(b, o + 12, rva + (uint32_t)o); put32(b, o + 16, rva + (uint32_t)o);
            break;
        case 2:     // FirstThunk у каждого свой: таблица IAT на миллионы адресов
            put32(b, o, ilt); put32(b, o + 12, nameRva); put32(b, o + 16, ilt + i * thunks * ptr);
            break;
        case 3:     // значения за границей образа
            put32(b, o, nasty(r, b.size())); put32(b, o + 12, nasty(r, b.size())); put32(b, o + 16, nasty(r, b.size()));
            break;
        default:    // таблица начинается внутри самой себя со случайным сдвигом
            put32(b, o, ilt + (uint32_t)r.below(thunks) * ptr); put32(b, o + 12, ilt); put32(b, o + 16, ilt);
            break;
        }
    }
    if (variant != 3)
        memset(b.data() + dsz - 20, 0, 20);
    // ячейки: имя — длинный хвост без нуля, или сама таблица
    for (uint32_t k = 0; k < thunks; k++)
    {
        size_t o = dsz + (size_t)k * ptr;
        uint32_t v = r.pct(20) ? ilt + k * ptr - 2 : nameRva - 2;
        if (is64)
            put64(b, o, v);
        else
            put32(b, o, v);
    }
    PeSec s;
    s.name = ".idata";
    s.rva = rva;
    s.chars = r.pct(50) ? 0xC0000040 : 0xE0000060;
    s.data = b;
    p.secs.push_back(s);
    p.importRva = rva;
    p.importSize = dsz;
    p.entryRva = rva;
    d += "scratch.importloop(" + string(is64 ? "pe32+" : "pe32") + ",variant=" + to_string(variant) + ",desc=" + to_string(descriptors)
         + ",thunks=" + to_string(thunks) + ")";
    return buildPe(p, r);
}

// Длинная строка в .rdata и множество ссылок на неё: каждая ссылка хранит копию строки
static Bytes scratchStringRefs(Rng& r, string& d)
{
    bool is64 = r.pct(30);
    const size_t lens[] = { 1024, 16 * 1024, 128 * 1024, 512 * 1024, 1024 * 1024 };
    const size_t texts[] = { 1024, 16 * 1024, 64 * 1024, 256 * 1024 };
    size_t strLen = r.pick(lens), textSize = r.pick(texts);
    vector<uint32_t> offs;
    Bytes rdata;
    addCStr(rdata, offs, string(strLen, 'S'));
    Skeleton s = skeleton(r, is64, textSize, rdata, offs);
    int kind = r.pct(50) ? 12 : 18;
    storm(r, s.p.secs[0].data, 0, textSize, s.ctx.textVa, is64, s.ctx, kind);
    s.p.entryRva = 0x1000;
    d += "scratch.stringrefs(" + string(is64 ? "pe32+" : "pe32") + ",str=" + to_string(strLen) + ",text=" + to_string(textSize) + ","
         + STORM_NAMES[kind] + ")";
    return buildPe(s.p, r);
}

// sprintf(buf, "%s%s", buf, buf) в цикле: содержимое буфера удваивается при каждом вызове
static Bytes scratchSprintfDoubling(Rng& r, string& d)
{
    const int roundsList[] = { 4, 8, 16, 20, 24, 28, 32, 64, 500 };
    int rounds = r.pick(roundsList);
    vector<uint32_t> offs;
    Bytes rdata;
    addCStr(rdata, offs, r.pct(50) ? "%s%s" : "%s%s%s%s");
    bool four = rdata.size() > 6;
    size_t textSize = 64 + (size_t)rounds * 64;
    Skeleton s = skeleton(r, false, textSize, rdata, offs);
    Emit e{ s.p.secs[0].data };
    e.u8(0x55); e.u8(0x8B); e.u8(0xEC);       // push ebp; mov ebp, esp
    uint32_t base = (uint32_t)s.ctx.textVa;
    uint32_t fmt = (uint32_t)s.ctx.strings[0];
    uint32_t subVa = base + (uint32_t)textSize - 2;
    for (int i = 0; i < rounds && !e.full(); i++)
    {
        e.u8(0x8D); e.u8(0x85); e.u32(0xFFFFFF00);   // lea eax, [ebp-100h]
        int args = four ? 4 : 2;
        for (int k = 0; k < args; k++)
            e.u8(0x50);                              // push eax
        e.u8(0x68); e.u32(fmt);
        e.u8(0x50);
        uint32_t from = base + (uint32_t)e.p;
        e.u8(0xE8); e.u32(subVa - (from + 5));
        e.u8(0x83); e.u8(0xC4); e.u8((uint8_t)((args + 2) * 4));
    }
    e.u8(0x5D); e.u8(0xC3);
    s.p.secs[0].data[textSize - 3] = 0xCC;
    s.p.secs[0].data[textSize - 2] = 0x33;
    s.p.secs[0].data[textSize - 1] = 0xC3;
    s.p.entryRva = 0x1000;
    d += "scratch.sprintfdouble(rounds=" + to_string(rounds) + ",four=" + to_string(four) + ")";
    return buildPe(s.p, r);
}

// repne scasb + rep movsb: встроенный strcat буфера к самому себе
static Bytes scratchStrcatDoubling(Rng& r, string& d)
{
    const int roundsList[] = { 4, 8, 16, 20, 24, 28, 32, 64, 500 };
    int rounds = r.pick(roundsList);
    vector<uint32_t> offs;
    Bytes rdata = defaultRdata(offs);
    size_t textSize = 64 + (size_t)rounds * 16;
    Skeleton s = skeleton(r, false, textSize, rdata, offs);
    Emit e{ s.p.secs[0].data };
    e.u8(0x55); e.u8(0x8B); e.u8(0xEC);
    for (int i = 0; i < rounds && !e.full(); i++)
    {
        e.u8(0x8D); e.u8(0xBD); e.u32(0xFFFFFF00);   // lea edi, [ebp-100h]
        e.u8(0x8D); e.u8(0xB5); e.u32(0xFFFFFF00);   // lea esi, [ebp-100h]
        e.u8(0xF2); e.u8(0xAE);                      // repne scasb
        e.u8(0xF3); e.u8(0xA4);                      // rep movsb
    }
    e.u8(0x5D); e.u8(0xC3);
    s.p.entryRva = 0x1000;
    d += "scratch.strcatdouble(rounds=" + to_string(rounds) + ")";
    return buildPe(s.p, r);
}

// Строки, удобные для std::regex и таблиц сигнатур
static Bytes scratchRegexFodder(Rng& r, string& d)
{
    bool is64 = r.pct(50);
    const size_t totals[] = { 4 * 1024, 64 * 1024, 512 * 1024, 2 * 1024 * 1024 };
    size_t total = r.pick(totals);
    int kind = (int)r.below(7);
    vector<uint32_t> offs;
    Bytes rdata;
    uint64_t n = 0;
    while (rdata.size() < total)
    {
        string s;
        size_t len = r.pct(50) ? 8 + (size_t)r.below(64) : 400 + (size_t)r.below(5000);
        switch (kind)
        {
        case 0: s = "C:\\"; while (s.size() < len) s += "abc\\"; break;
        case 1: s = "http://"; while (s.size() < len) s += "abc.def/"; break;
        case 2: while (s.size() < len) s += "1.2.3."; break;
        case 3: while (s.size() < len) s += "abc.dll."; break;
        case 4: s = "\\\\"; while (s.size() < len) s += "A"; s += ".exe"; break;
        case 5: s = to_string(n++) + "abc" + to_string(r.u32()) + ".dll"; break;      // все разные, повторы не отсекаются
        default: s = "OpenSSL 1.0.1 zlib 1.2.3 " + to_string(n++); break;
        }
        addCStr(rdata, offs, s);
    }
    Skeleton sk = skeleton(r, is64, 256, rdata, offs);
    sk.p.entryRva = 0x1000;
    d += "scratch.regex(" + string(is64 ? "pe32+" : "pe32") + ",kind=" + to_string(kind) + ",total=" + to_string(total) + ")";
    return buildPe(sk.p, r);
}

// 96 выполняемых секций поверх одного участка файла
static Bytes scratchOverlap(Rng& r, string& d)
{
    bool is64 = r.pct(50);
    size_t textSize = sizePick(r);
    PeBuild p;
    p.is64 = is64;
    p.imageBase = is64 ? 0x140000000ull : 0x400000ull;
    PeSec s;
    s.name = ".text";
    s.rva = 0x1000;
    s.chars = CHARS_CODE;
    s.data.resize(textSize);
    StormCtx c;
    c.textVa = p.imageBase + s.rva;
    c.textLen = textSize;
    int kind = (int)r.below(STORM_COUNT);
    storm(r, s.data, 0, textSize, c.textVa, is64, c, kind);
    p.secs.push_back(s);
    for (int i = 1; i < 96; i++)
    {
        PeSec e;
        e.name = ".o";
        e.rva = 0x1000;
        e.chars = CHARS_CODE;
        p.secs.push_back(e);
    }
    p.entryRva = 0x1000;
    Bytes b = buildPe(p, r);
    View v = viewOf(b);
    vector<SecView> secs = sectionsOf(b, v);
    int mode = (int)r.below(3);
    for (size_t i = 1; i < secs.size(); i++)
    {
        size_t h = secs[i].hdr;
        put32(b, h + 8, secs[0].vsize);
        put32(b, h + 12, mode == 0 ? 0x1000 : mode == 1 ? 0x1000 + (uint32_t)i * 0x10 : alignUp((uint64_t)0x1000 + i * (uint64_t)textSize, 0x1000));
        put32(b, h + 16, secs[0].rawSize);
        put32(b, h + 20, secs[0].rawPtr);
    }
    d += "scratch.overlap(" + string(is64 ? "pe32+" : "pe32") + ",text=" + to_string(textSize) + "," + STORM_NAMES[kind] + ",mode=" + to_string(mode) + ")";
    return b;
}

static Bytes scratchHeaderOnly(Rng& r, string& d)
{
    PeBuild p;
    p.is64 = r.pct(50);
    p.imageBase = p.is64 ? 0x140000000ull : 0x400000ull;
    p.entryRva = r.pct(50) ? 0x40 + (uint32_t)r.below(0x200) : nasty(r, 0x400);
    Bytes b = buildPe(p, r);
    View v = viewOf(b);
    if (r.pct(50))
        put32(b, v.oh + 60, nasty(r, b.size()));
    d += "scratch.headeronly(" + string(p.is64 ? "pe32+" : "pe32") + ")";
    return b;
}

// Случайная программа из настоящих вызовов API с аргументами и сбитым стеком
static Bytes scratchApiProgram(Rng& r, string& d)
{
    bool is64 = r.pct(50);
    size_t textSize = 512 + (size_t)r.below(16 * 1024);
    vector<uint32_t> offs;
    Bytes rdata = defaultRdata(offs);
    Skeleton s = skeleton(r, is64, textSize, rdata, offs);
    Emit e{ s.p.secs[0].data };
    vector<uint32_t> apis;
    for (const auto& item : s.iat)
        apis.push_back(item.second);
    e.u8(0x55);
    if (is64)
    {
        e.u8(0x48); e.u8(0x8B); e.u8(0xEC);
    }
    else
    {
        e.u8(0x8B); e.u8(0xEC);
    }
    while (!e.full())
    {
        uint64_t va = s.ctx.textVa + e.p;
        switch (r.below(10))
        {
        case 0:     // push addr / mov r, addr
            if (is64)
            {
                const uint8_t rexModrm[][2] = { { 0x48, 0x0D }, { 0x48, 0x15 }, { 0x4C, 0x05 }, { 0x4C, 0x0D } };   // lea rcx/rdx/r8/r9, [rip+x]
                const uint8_t* m = rexModrm[r.below(4)];
                uint64_t t = s.ctx.strings[r.below(s.ctx.strings.size())];
                e.u8(m[0]); e.u8(0x8D); e.u8(m[1]); e.u32((uint32_t)(t - (va + 7)));
            }
            else
            {
                e.u8(0x68); e.u32((uint32_t)s.ctx.strings[r.below(s.ctx.strings.size())]);
            }
            break;
        case 1:
            e.u8(0x6A); e.u8(r.u32() & 7);
            break;
        case 2:     // lea eax, [ebp-disp]; push eax
            if (is64)
                e.u8(0x48);
            e.u8(0x8D); e.u8(0x85); e.u32(0u - (uint32_t)(r.below(32) * 0x10 + 0x10));
            e.u8(0x50);
            break;
        case 3:     // call [iat]
        case 4:
        case 5:
        {
            uint64_t t = s.p.imageBase + apis[r.below(apis.size())];
            e.u8(0xFF); e.u8(0x15); e.u32(is64 ? (uint32_t)(t - (va + 6)) : (uint32_t)t);
            break;
        }
        case 6:     // проверка результата и переход вперёд или назад
            e.u8(0x85); e.u8(0xC0); e.u8(0x74); e.u8(r.u32() & 0xFF);
            break;
        case 7:
            e.u8(0xE8); e.u32((uint32_t)r.below(textSize) - (uint32_t)(textSize / 2));
            break;
        case 8:
            e.u8(0x83); e.u8(0xC4); e.u8(r.u32() & 0xFF);
            break;
        default:
            e.u8(0xF2); e.u8(0xAE);
            if (r.pct(50))
            {
                e.u8(0xF3); e.u8(0xA4);
            }
            break;
        }
    }
    s.p.entryRva = 0x1000;
    d += "scratch.apiprog(" + string(is64 ? "pe32+" : "pe32") + ",text=" + to_string(textSize) + ")";
    return buildPe(s.p, r);
}

// Отдельный сценарий (--scenario importnames), вне общего потока: иначе изменились бы все прежние seed.
// 512 дескрипторов × 4096 ячеек с настоящим именем файлового API и множество функций с обращениями к нему
static Bytes scenarioImportNames(Rng& r, string& d)
{
    const bool is64 = false;
    const uint32_t descriptors = 512, thunks = 4096, ptr = 4;
    const size_t textSize = 64 * 1024;
    PeBuild p;
    p.is64 = is64;
    PeSec text;
    text.name = ".text";
    text.rva = 0x1000;
    text.chars = CHARS_CODE;
    text.data.assign(textSize, 0x90);
    uint32_t rva = alignUp((uint64_t)text.rva + textSize, 0x1000);
    uint32_t dsz = (descriptors + 1) * 20, ilt = rva + dsz, nameRva = ilt + (thunks + 1) * ptr;
    Bytes idata(dsz + (thunks + 1) * ptr + 32, 0);
    memcpy(idata.data() + (nameRva - rva) + 2, "CreateFileA", 11);
    for (uint32_t i = 0; i < descriptors; i++)
    {
        put32(idata, i * 20, ilt);
        put32(idata, i * 20 + 12, nameRva + 2);
        put32(idata, i * 20 + 16, ilt);
    }
    for (uint32_t k = 0; k < thunks; k++)
        put32(idata, dsz + k * ptr, nameRva);
    uint64_t iatVa = p.imageBase + ilt;
    Emit e{ text.data };
    while (!e.full())     // ret; call next; call [iat]
    {
        e.u8(0xC3);
        e.u8(0xE8);
        e.u32(6);
        e.u8(0xFF);
        e.u8(0x15);
        e.u32((uint32_t)iatVa);
    }
    PeSec is;
    is.name = ".idata";
    is.rva = rva;
    is.chars = 0xC0000040;
    is.data = idata;
    p.secs.push_back(text);
    p.secs.push_back(is);
    p.importRva = rva;
    p.importSize = dsz;
    p.entryRva = 0x1000;
    d += "scenario.importnames(desc=512,thunks=4096,text=65536)";
    return buildPe(p, r);
}

static wstring gScenario;

static Bytes scratchPe(Rng& r, string& d)
{
    switch (r.below(12))
    {
    case 0:  return scratchGarbage(r, d);
    case 1: case 2: case 3: return scratchStorm(r, d);
    case 4:  return scratchImportLoop(r, d);
    case 5:  return scratchStringRefs(r, d);
    case 6:  return scratchSprintfDoubling(r, d);
    case 7:  return scratchStrcatDoubling(r, d);
    case 8:  return scratchRegexFodder(r, d);
    case 9:  return scratchOverlap(r, d);
    case 10: return scratchHeaderOnly(r, d);
    default: return scratchApiProgram(r, d);
    }
}

// ================================================================ мутации готового образа

static void mutFlips(Rng& r, Bytes& b, string& d)
{
    if (b.empty())
        return;
    uint64_t n = r.pct(70) ? 1 + r.below(16) : 16 + r.below(512);
    bool head = r.pct(50);
    for (uint64_t i = 0; i < n; i++)
    {
        size_t o = (size_t)r.below(head ? min<size_t>(b.size(), 0x800) : b.size());
        if (r.pct(50))
            b[o] ^= (uint8_t)(1u << r.below(8));
        else
            b[o] = (uint8_t)r.u32();
    }
    d += "+flips(" + to_string(n) + (head ? ",head)" : ")");
}

static void mutTruncate(Rng& r, Bytes& b, string& d)
{
    View v = viewOf(b);
    size_t size = b.size();
    switch (r.below(5))
    {
    case 0: size = (size_t)r.below(0x48); break;
    case 1: size = v.ok ? min(size, v.nt + (size_t)r.below(0x120)) : (size_t)r.below(size + 1); break;
    case 2: size = v.ok ? min(size, v.sh + (size_t)r.below(40 * 8)) : (size_t)r.below(size + 1); break;
    default: size = (size_t)r.below(size + 1); break;
    }
    d += "+truncate(" + to_string(size) + ")";
    b.resize(size);
}

static void mutLfanew(Rng& r, Bytes& b, string& d)
{
    const uint32_t size = (uint32_t)b.size();
    uint32_t values[] = { 0xFFFFFFFF, 0x80000000, 0x7FFFFFFF, 0xFFFFFFF0, 0xFFFFFFE8, size, size - 1, size - 4, size - 23, size - 24, size - 25, 0, 4, 0x3C, 0x40 };
    uint32_t val = r.pick(values);
    put32(b, 0x3C, val);
    d += "+lfanew(" + hex32(val) + ")";
}

// Переносит сигнатуру PE на новое место: заголовки «почти у конца файла»
static void mutLfanewNearEof(Rng& r, Bytes& b, string& d)
{
    View v = viewOf(b);
    if (!v.ok)
        return;
    size_t room = 24 + (size_t)r.below(260);
    if (b.size() <= room + v.nt)
        return;
    size_t to = b.size() - room;
    memmove(b.data() + to, b.data() + v.nt, room);
    put32(b, 0x3C, (uint32_t)to);
    d += "+lfanewEof(" + to_string(room) + ")";
}

static void mutSectionCount(Rng& r, Bytes& b, string& d)
{
    View v = viewOf(b);
    const uint16_t values[] = { 0, 1, 95, 96, 97, 0x7FFF, 0xFFFF };
    uint16_t val = r.pick(values);
    put16(b, v.ok ? v.fh + 2 : 0x86, val);
    d += "+nsec(" + to_string(val) + ")";
}

static void mutOptSize(Rng& r, Bytes& b, string& d)
{
    View v = viewOf(b);
    const uint16_t values[] = { 0, 1, 0x10, 0xE0, 0xF0, 0x7FFF, 0xFFFF, (uint16_t)b.size(), (uint16_t)(b.size() - 40) };
    uint16_t val = r.pick(values);
    put16(b, v.ok ? v.fh + 16 : 0x94, val);
    d += "+optsize(" + hex32(val) + ")";
}

static void mutSectionFields(Rng& r, Bytes& b, string& d)
{
    View v = viewOf(b);
    vector<SecView> secs = sectionsOf(b, v);
    if (secs.empty())
        return;
    uint64_t n = 1 + r.below(4);
    for (uint64_t i = 0; i < n; i++)
    {
        const SecView& s = secs[r.below(secs.size())];
        static const size_t fields[] = { 8, 12, 16, 20, 36 };
        size_t f = r.pick(fields);
        uint32_t val = nasty(r, b.size());
        if (f == 36)
            val = r.pct(70) ? (val | 0x20000020) : val;
        put32(b, s.hdr + f, val);
        d += "+secfield(" + to_string(f) + "=" + hex32(val) + ")";
    }
}

static void mutDataDir(Rng& r, Bytes& b, string& d)
{
    View v = viewOf(b);
    if (!v.ok)
        return;
    const int pref[] = { 1, 1, 10, 10, 14, 14, 12, 0, 2, 3, 4, 5, 6, 9, 11, 13, 15 };
    int idx = r.pick(pref);
    size_t e = v.dd + idx * 8;
    uint32_t val;
    switch (r.below(4))
    {
    case 0: val = (uint32_t)e; break;                                  // RVA заголовков = сам каталог
    case 1: val = (uint32_t)(b.size() - 1 - r.below(8)); break;        // самый конец файла
    case 2: val = 0xFFFFFFF0 + (uint32_t)r.below(16); break;
    default: val = nasty(r, b.size()); break;
    }
    put32(b, e, val);
    put32(b, e + 4, r.pct(50) ? nasty(r, b.size()) : get32(b, e + 4));
    if (r.pct(20))
        put32(b, v.dd - 4, nasty(r, b.size()));      // NumberOfRvaAndSizes
    d += "+dir(" + to_string(idx) + "=" + hex32(val) + ")";
}

// Каталог загрузки (10) с огромным размером у самого конца файла
static void mutLoadConfig(Rng& r, Bytes& b, string& d)
{
    View v = viewOf(b);
    vector<SecView> secs = sectionsOf(b, v);
    if (secs.empty())
        return;
    const SecView& s = secs[r.below(secs.size())];
    if (!s.rawSize || s.rawPtr >= b.size())
        return;
    uint32_t delta = s.rawSize - 1 - (uint32_t)r.below(min<uint32_t>(s.rawSize, 0x100));
    put32(b, v.dd + 80, s.va + delta);
    put32(b, v.dd + 84, 0x100);
    size_t o = (uint64_t)s.rawPtr + delta;
    put32(b, o, r.pct(50) ? 0xFFFFFFFF : 0x100);
    d += "+loadcfg(" + hex32(s.va + delta) + ")";
}

static void mutImports(Rng& r, Bytes& b, string& d)
{
    View v = viewOf(b);
    if (!v.ok)
        return;
    vector<SecView> secs = sectionsOf(b, v);
    uint32_t rva = get32(b, v.dd + 8);
    size_t off = rvaOff(secs, b.size(), rva);
    if (off == NPOS)
        return;
    int variant = (int)r.below(6);
    const uint32_t ptr = v.is64 ? 8 : 4;
    switch (variant)
    {
    case 0: put32(b, off, rva); put32(b, off + 16, rva); break;     // OriginalFirstThunk на сам дескриптор
    case 1:                                                         // имя упирается в конец файла без нуля
    {
        uint32_t nameRva = get32(b, off + 12);
        size_t n = rvaOff(secs, b.size(), nameRva);
        if (n != NPOS)
            for (size_t i = n; i < b.size() && i < n + 0x20000; i++)
                b[i] = 'A';
        break;
    }
    case 2:                                                         // размножить дескриптор
    {
        Bytes one(b.begin() + off, b.begin() + min(b.size(), off + 20));
        for (size_t i = 0; i < 600 && off + (i + 1) * 20 <= b.size(); i++)
            memcpy(b.data() + off + i * 20, one.data(), one.size());
        break;
    }
    case 3:                                                         // ячейки указывают сами на себя
    {
        uint32_t t = get32(b, off);
        if (!t)
            t = get32(b, off + 16);
        size_t o = rvaOff(secs, b.size(), t);
        for (size_t k = 0; o != NPOS && k < 5000 && o + k * ptr + ptr <= b.size(); k++)
        {
            uint32_t self = t + (uint32_t)k * ptr - 2;
            if (ptr == 8)
                put64(b, o + k * 8, self);
            else
                put32(b, o + k * 4, self);
        }
        break;
    }
    case 4: put32(b, off + r.below(5) * 4, nasty(r, b.size())); break;
    default:                                                        // цепочка: каждый дескриптор — на следующий
        for (size_t i = 0; i < 64 && off + i * 20 + 20 <= b.size(); i++)
        {
            put32(b, off + i * 20, rva + (uint32_t)(i + 1) * 20);
            put32(b, off + i * 20 + 12, rva);
        }
        break;
    }
    d += "+imports(" + to_string(variant) + ")";
}

static void mutRich(Rng& r, Bytes& b, string& d)
{
    View v = viewOf(b);
    size_t limit = v.ok ? v.nt : min<size_t>(b.size(), 0x200);
    if (limit < 0x90)
    {
        // места под заголовок нет: сдвигаем e_lfanew дальше, чтобы цикл поиска прошёл по случайным данным
        if (b.size() > 0x400)
            put32(b, 0x3C, (uint32_t)(b.size() - 64));
        limit = min<size_t>(b.size(), 0x200);
    }
    int variant = (int)r.below(5);
    size_t pos = 0x80 + (size_t)r.below((limit - 0x80) / 4 + 1) * 4;
    uint32_t key = r.u32();
    switch (variant)
    {
    case 0:     // Rich без DanS
        put32(b, pos, 0x68636952);
        put32(b, pos + 4, key);
        break;
    case 1:     // Rich по нечётному смещению
        put32(b, pos + 1 + r.below(3), 0x68636952);
        break;
    case 2:     // DanS сразу перед Rich: записей нет
        put32(b, pos, 0x68636952);
        put32(b, pos + 4, key);
        if (pos >= 0x84)
            put32(b, pos - 4, 0x536E6144 ^ key);
        break;
    case 3:     // DanS и Rich в одной ячейке (ключ 0x...)
        put32(b, pos, 0x68636952);
        put32(b, pos + 4, 0x68636952 ^ 0x536E6144);
        break;
    default:    // Rich в самом конце файла, сразу за ним e_lfanew
        if (b.size() > 16)
        {
            size_t at = (b.size() - 8) & ~(size_t)3;
            put32(b, at, 0x68636952);
            put32(b, 0x3C, (uint32_t)(at + 8));
        }
        break;
    }
    d += "+rich(" + to_string(variant) + "@" + hex32(pos) + ")";
}

static void mutEntry(Rng& r, Bytes& b, string& d)
{
    View v = viewOf(b);
    if (!v.ok)
        return;
    uint32_t val = nasty(r, b.size());
    vector<SecView> secs = sectionsOf(b, v);
    if (!secs.empty() && r.pct(40))
    {
        const SecView& s = secs[r.below(secs.size())];
        val = s.va + (r.pct(50) ? s.rawSize - 1 : s.rawSize);
    }
    put32(b, v.oh + 16, val);
    d += "+entry(" + hex32(val) + ")";
}

static void mutImageBase(Rng& r, Bytes& b, string& d)
{
    View v = viewOf(b);
    if (!v.ok)
        return;
    const uint64_t values[] = { 0, 1, 0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFF0000, 0xFFFFFFFF, 0xFFFFFFFFFFFF0000ull, 0xFFFFFFFFFFFFFFFFull, 0x8000000000000000ull };
    uint64_t val = r.pick(values);
    if (v.is64)
        put64(b, v.oh + 24, val);
    else
        put32(b, v.oh + 28, (uint32_t)val);
    d += "+base(" + hex32(val) + ")";
}

static void mutHeaderMisc(Rng& r, Bytes& b, string& d)
{
    View v = viewOf(b);
    if (!v.ok)
        return;
    switch (r.below(5))
    {
    case 0: put16(b, v.oh, v.is64 ? 0x10B : 0x20B); d += "+swapmagic"; break;
    case 1: put16(b, v.fh, v.is64 ? 0x14C : 0x8664); d += "+swapmachine"; break;
    case 2: put16(b, v.fh, (uint16_t)r.u32()); d += "+machine"; break;
    case 3: { uint32_t val = nasty(r, b.size()); put32(b, v.oh + 60, val); d += "+sizeofheaders(" + hex32(val) + ")"; break; }
    default: put16(b, v.oh + 68, (uint16_t)r.u32()); d += "+subsystem"; break;
    }
}

static void mutStorm(Rng& r, Bytes& b, string& d)
{
    View v = viewOf(b);
    size_t begin = 0, len = 0;
    uint64_t va = 0;
    if (!v.ok || !codeRange(b, v, begin, len, va))
        return;
    StormCtx c;
    c.textVa = va;
    c.textLen = len;
    uint32_t iatRva = get32(b, v.dd + 12 * 8), iatSize = get32(b, v.dd + 12 * 8 + 4);
    const uint32_t ptr = v.is64 ? 8 : 4;
    for (uint32_t k = 0; k < 64 && k * ptr < iatSize; k++)
        c.iat.push_back(v.imageBase + iatRva + k * ptr);
    size_t from = r.pct(30) ? 0 : (size_t)r.below(len);
    size_t n = r.pct(30) ? len - from : (size_t)r.below(min<size_t>(len - from, 8192) + 1);
    int kind = (int)r.below(STORM_COUNT);
    storm(r, b, begin + from, n, va + from, v.is64, c, kind);
    d += string("+storm(") + STORM_NAMES[kind] + ",at=" + to_string(from) + ",len=" + to_string(n) + ")";
    if (r.pct(30))
    {
        truncatedTail(r, b, begin, len);
        d += "+tail";
    }
}

static void mutStrings(Rng& r, Bytes& b, string& d)
{
    if (b.size() < 0x1000)
        return;
    size_t at = 0x400 + (size_t)r.below(b.size() - 0x400);
    size_t n = min<size_t>(b.size() - at, 64 + (size_t)r.below(8192));
    static const char* const units[] = { "C:\\abc", "\\\\host\\", "http://a.b/", "1.2.3.", "abc.dll.", "%s%s", "cmd.exe /c ", "Rich", "DanS" };
    const char* u = r.pick(units);
    size_t ul = strlen(u);
    for (size_t i = 0; i < n; i++)
        b[at + i] = (uint8_t)u[i % ul];
    d += string("+strings(") + u + "," + to_string(n) + ")";
}

static void mutAppend(Rng& r, Bytes& b, string& d)
{
    const size_t sizes[] = { 1, 7, 512, 64 * 1024, 1024 * 1024 };
    size_t n = r.pick(sizes);
    size_t old = b.size();
    b.resize(old + n, 0);
    bool text = r.pct(50);
    for (size_t i = old; i < b.size(); i++)
        b[i] = text ? (uint8_t)('a' + r.below(26)) : (uint8_t)r.u32();
    d += "+append(" + to_string(n) + ")";
}

static void mutate(Rng& r, Bytes& b, string& d)
{
    switch (r.below(20))
    {
    case 0: case 1: mutFlips(r, b, d); break;
    case 2:  mutTruncate(r, b, d); break;
    case 3:  mutLfanew(r, b, d); break;
    case 4:  mutLfanewNearEof(r, b, d); break;
    case 5:  mutSectionCount(r, b, d); break;
    case 6:  mutOptSize(r, b, d); break;
    case 7:  mutSectionFields(r, b, d); break;
    case 8:  mutDataDir(r, b, d); break;
    case 9:  mutLoadConfig(r, b, d); break;
    case 10: mutImports(r, b, d); break;
    case 11: mutRich(r, b, d); break;
    case 12: mutEntry(r, b, d); break;
    case 13: mutImageBase(r, b, d); break;
    case 14: mutHeaderMisc(r, b, d); break;
    case 15: case 16: case 17: mutStorm(r, b, d); break;
    case 18: mutStrings(r, b, d); break;
    default: mutAppend(r, b, d); break;
    }
}

// ================================================================ образцы и одна итерация

struct SeedFile { string name; Bytes bytes; };
static vector<SeedFile> gSeeds;
static fs::path gRar = L"C:\\Users\\matve\\OneDrive\\Desktop\\INF\\Whiter.a.rar";

static bool loadSeeds()
{
    string error;
    const pair<const char*, fs::path> files[] = {
        { "xcopy64", L"C:\\Windows\\System32\\xcopy.exe" },
        { "xcopy32", L"C:\\Windows\\SysWOW64\\xcopy.exe" },
        { "sample_clean", L"C:\\Claude pr\\pr7\\samples\\sample_clean.exe" },
    };
    for (const auto& f : files)
    {
        SeedFile s;
        s.name = f.first;
        if (!readFile(f.second, s.bytes, error))
        {
            printf("FATAL seed %s: cannot read\n", f.first);
            return false;
        }
        gSeeds.push_back(move(s));
    }
    // Образец ВПО: только в память, через tar -xOf на стандартный вывод
    SeedFile w;
    w.name = "whiter";
    // Повторы: снимок архива в readFromArchive не защищён от одновременного запуска (см. отчёт фаззинга)
    bool loaded = false;
    for (int attempt = 0; attempt < 8 && !loaded; attempt++)
    {
        error.clear();
        w.bytes.clear();
        loaded = readFromArchive(gRar, "Whiter.a.exe", w.bytes, error);
        if (!loaded)
        {
            printf("SEEDRETRY whiter attempt=%d error=%s\n", attempt, error.c_str());
            fflush(stdout);
            Sleep(100 + (GetCurrentProcessId() % 37) * 20 * (attempt + 1));
        }
    }
    if (!loaded)
    {
        printf("FATAL seed whiter: cannot read from archive: %s\n", error.c_str());
        return false;
    }
    gSeeds.push_back(move(w));
    for (const SeedFile& s : gSeeds)
        printf("SEEDFILE %s size=%zu\n", s.name.c_str(), s.bytes.size());
    fflush(stdout);
    return true;
}

static void generate(uint64_t seed, Bytes& out, string& d)
{
    Rng r{ seed };
    if (gScenario == L"importnames")
    {
        out = scenarioImportNames(r, d);
        return;
    }
    uint64_t c = r.below(100);
    uint64_t muts;
    if (c < 30)
    {
        out = scratchPe(r, d);
        muts = r.pct(60) ? 0 : 1 + r.below(2);
    }
    else
    {
        const SeedFile& s = gSeeds[r.below(gSeeds.size())];
        d = s.name;
        out = s.bytes;
        muts = 1 + r.below(4);
    }
    for (uint64_t i = 0; i < muts; i++)
        mutate(r, out, d);
}

// ================================================================ сбои: обнаружение и печать стека

enum FailKind { FAIL_NONE = 0, FAIL_SEH = 2, FAIL_HANG = 3, FAIL_EXC = 4, FAIL_MEM = 5, FAIL_ABORT = 6, FAIL_CRT = 7, FAIL_PARAM = 8 };

static atomic<uint64_t> gIter{ 0 }, gSeed{ 0 };
static atomic<ULONGLONG> gStart{ 0 };
static atomic<long> gInvariantFails{ 0 };
static HANDLE gFailEvent = nullptr, gDoneEvent = nullptr, gWorker = nullptr;
static uint64_t gHangMs = 20000;
static uint64_t gMemLimit = 1500ull * 1024 * 1024;
static size_t gStackBytes = 1024 * 1024;

static volatile LONG gFailClaimed = 0;
static int gFailCode = FAIL_NONE;
static DWORD gSehCode = 0;
static void* gSehAddr = nullptr;
static ULONG_PTR gSehInfo[2] = { 0, 0 };
static CONTEXT gSehContext;
static char gFailText[512] = "";
static void* gFrames[64];
static USHORT gFrameCount = 0;

// Стек в момент последнего throw: к моменту catch он уже раскручен
static void* gThrowFrames[64];
static USHORT gThrowCount = 0;

static void printSymbol(HANDLE proc, DWORD64 addr, int index)
{
    char buffer[sizeof(SYMBOL_INFO) + 512];
    SYMBOL_INFO* sym = (SYMBOL_INFO*)buffer;
    sym->SizeOfStruct = sizeof(SYMBOL_INFO);
    sym->MaxNameLen = 512;
    DWORD64 disp = 0;
    IMAGEHLP_LINE64 line = {};
    line.SizeOfStruct = sizeof(line);
    DWORD lineDisp = 0;
    const char* name = SymFromAddr(proc, addr, &disp, sym) ? sym->Name : "?";
    if (SymGetLineFromAddr64(proc, addr, &lineDisp, &line))
        printf("  #%02d 0x%llX %s+0x%llX %s:%lu\n", index, addr, name, disp, line.FileName, line.LineNumber);
    else
        printf("  #%02d 0x%llX %s+0x%llX\n", index, addr, name, disp);
}

static void walkStack(HANDLE thread, CONTEXT ctx)
{
    HANDLE proc = GetCurrentProcess();
    STACKFRAME64 sf = {};
#ifdef _WIN64
    DWORD machine = IMAGE_FILE_MACHINE_AMD64;
    sf.AddrPC.Offset = ctx.Rip;
    sf.AddrFrame.Offset = ctx.Rbp;
    sf.AddrStack.Offset = ctx.Rsp;
#else
    DWORD machine = IMAGE_FILE_MACHINE_I386;
    sf.AddrPC.Offset = ctx.Eip;
    sf.AddrFrame.Offset = ctx.Ebp;
    sf.AddrStack.Offset = ctx.Esp;
#endif
    sf.AddrPC.Mode = sf.AddrFrame.Mode = sf.AddrStack.Mode = AddrModeFlat;
    for (int i = 0; i < 40; i++)
    {
        if (!StackWalk64(machine, proc, thread, &sf, &ctx, nullptr, SymFunctionTableAccess64, SymGetModuleBase64, nullptr) || !sf.AddrPC.Offset)
            break;
        printSymbol(proc, sf.AddrPC.Offset, i);
    }
}

// Рабочий поток можно остановить только вне кучи: dbghelp сам выделяет память, и остановка
// потока с захваченной блокировкой кучи подвесила бы стенд. Проверяем пробным потоком
static DWORD WINAPI heapProbe(void*)
{
    void* p = HeapAlloc(GetProcessHeap(), 0, 64);
    HeapFree(GetProcessHeap(), 0, p);
    free(malloc(64));         // куча CRT: у отладочной CRT своя блокировка
    return 0;
}

// Без printf: поток печати сам может ждать блокировку, которую держит остановленный рабочий поток
static DWORD WINAPI deadMan(void* arg)
{
    Sleep(30000);
    TerminateProcess(GetCurrentProcess(), (UINT)(uintptr_t)arg);
    return 0;
}

static void sampleStack(int exitCode)
{
    CreateThread(nullptr, 0, deadMan, (void*)(uintptr_t)exitCode, 0, nullptr);
    for (int attempt = 0; attempt < 200; attempt++)
    {
        SuspendThread(gWorker);
        HANDLE probe = CreateThread(nullptr, 0, heapProbe, nullptr, 0, nullptr);
        bool heapFree = probe && WaitForSingleObject(probe, 100) == WAIT_OBJECT_0;
        if (heapFree)
        {
            CloseHandle(probe);
            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_FULL;
            if (GetThreadContext(gWorker, &ctx))
                walkStack(gWorker, ctx);
            return;
        }
        ResumeThread(gWorker);
        if (probe)
        {
            WaitForSingleObject(probe, 1000);
            CloseHandle(probe);
        }
        Sleep(1 + attempt % 7);
    }
    printf("  (stack unavailable: worker stayed inside the heap)\n");
}

static void printFrames(void* const* frames, USHORT count)
{
    HANDLE proc = GetCurrentProcess();
    for (USHORT i = 0; i < count && i < 40; i++)
        printSymbol(proc, (DWORD64)frames[i], i);
}

// Вызывается в рабочем потоке: стек печатает главный поток, у сбойного его может не хватить
static void reportAndPark(int code, const char* text, bool captureHere)
{
    if (InterlockedCompareExchange(&gFailClaimed, 1, 0) == 0)
    {
        gFailCode = code;
        if (text)
            strncpy_s(gFailText, text, _TRUNCATE);
        if (captureHere)
            gFrameCount = RtlCaptureStackBackTrace(1, 64, gFrames, nullptr);
        SetEvent(gFailEvent);
    }
    Sleep(INFINITE);
}

#ifndef __SANITIZE_ADDRESS__
static LONG WINAPI crashFilter(EXCEPTION_POINTERS* ep)
{
    if (InterlockedCompareExchange(&gFailClaimed, 1, 0) == 0)
    {
        gFailCode = FAIL_SEH;
        gSehCode = ep->ExceptionRecord->ExceptionCode;
        gSehAddr = ep->ExceptionRecord->ExceptionAddress;
        if (ep->ExceptionRecord->NumberParameters >= 2)
        {
            gSehInfo[0] = ep->ExceptionRecord->ExceptionInformation[0];
            gSehInfo[1] = ep->ExceptionRecord->ExceptionInformation[1];
        }
        gSehContext = *ep->ContextRecord;
        SetEvent(gFailEvent);
    }
    Sleep(INFINITE);
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif

static LONG WINAPI throwTracker(EXCEPTION_POINTERS* ep)
{
    if (ep->ExceptionRecord->ExceptionCode == 0xE06D7363)
        gThrowCount = RtlCaptureStackBackTrace(0, 64, gThrowFrames, nullptr);
    return EXCEPTION_CONTINUE_SEARCH;
}

static void onAbort(int) { reportAndPark(FAIL_ABORT, "abort() (SIGABRT)", true); }
static void onTerminate() { reportAndPark(FAIL_ABORT, "std::terminate", true); }
static void onInvalidParam(const wchar_t*, const wchar_t*, const wchar_t*, unsigned, uintptr_t)
{
    reportAndPark(FAIL_PARAM, "CRT invalid parameter", true);
}
#ifdef _DEBUG
static int onCrtReport(int type, char* message, int*)
{
    if (type == _CRT_WARN)
        return 0;
    reportAndPark(FAIL_CRT, message, true);
    return 1;
}
#endif

// ================================================================ рабочий поток

static fs::path gOutDir;

static void checkInvariants(const Analysis& a, uint64_t iter, uint64_t seed)
{
    auto fail = [&](const string& what)
    {
        gInvariantFails++;
        printf("INVARIANT iter=%llu seed=0x%016llX %s\n", iter, seed, what.c_str());
    };
    const double eps = 1e-6;
    if (a.score < 0 || a.score > 100)
        fail("score=" + to_string(a.score));
    for (const Finding& f : a.findings)
    {
        if (f.block.empty())
            fail("empty block: signature=" + f.signature + " category=" + f.category);
        if (!(f.lossMin <= f.lossExpected + eps && f.lossExpected <= f.lossMax + eps))
            fail("finding economics: " + f.signature + " min=" + to_string(f.lossMin) + " exp=" + to_string(f.lossExpected) + " max=" + to_string(f.lossMax));
    }
    const EconomicSummary& e = a.economy;
    if (!(e.lossMin <= e.lossExpected + eps && e.lossExpected <= e.lossMax + eps))
        fail("economy: min=" + to_string(e.lossMin) + " exp=" + to_string(e.lossExpected) + " max=" + to_string(e.lossMax));
    for (const EconomicLine& l : e.lines)
        if (!(l.lo <= l.expected + eps && l.expected <= l.hi + eps))
            fail("economy line " + l.name);
    for (const Section& s : a.pe.sections)
        if (!(s.entropy >= -eps && s.entropy <= 8 + eps))
            fail("entropy=" + to_string(s.entropy));
}

static void runOne(uint64_t iter, uint64_t seed, bool describeOnly)
{
    gIter = iter;
    gSeed = seed;
    gStart = GetTickCount64();
    printf("ITER %llu seed=0x%016llX\n", iter, seed);
    fflush(stdout);

    Bytes bytes;
    string desc;
    generate(seed, bytes, desc);
    printf("INPUT size=%zu %s\n", bytes.size(), desc.c_str());
    fflush(stdout);
    if (describeOnly)
    {
        gStart = 0;
        return;
    }

    ULONGLONG t0 = GetTickCount64();
    gStart = t0;
    {
        Analysis a;
        RunFiles files;
        RunOptions options;
        options.internalOnly = true;
        options.name = "fuzz";
        options.displayPath = "fuzz";
        options.outDir = gOutDir;
        runAnalysis(bytes, options, a, files);
        checkInvariants(a, iter, seed);
        printf("DONE %llu ms=%llu valid=%d funcs=%zu decoded=%zu findings=%zu behaviors=%zu score=%d\n", iter, GetTickCount64() - t0,
               a.pe.valid ? 1 : 0, a.code.functions.size(), a.code.decodedFunctions, a.findings.size(), a.behaviors.size(), a.score);
        fflush(stdout);
    }
    gStart = 0;
}

struct WorkPlan
{
    uint64_t base = 0x4558454941533031ull, start = 0, end = 0, oneSeed = 0;
    bool useOneSeed = false, describe = false;
    fs::path file;
    wstring selftest;     // проверка самого стенда: oob, crash, stack, throw, hang, mem
};

// Намеренный сбой: убедиться, что стенд его видит и печатает стек
#pragma warning(push)
#pragma warning(disable: 4717 6201 6386)
static volatile int gSink = 0;
static int overflowStack(int depth)
{
    volatile char pad[4096];
    pad[depth % 4096] = 1;
    return overflowStack(depth + 1) + pad[0];
}
static void selftest(const wstring& what)
{
    gSeed = 0x5E1F7E57;
    gStart = GetTickCount64();
    vector<unsigned char>* v = new vector<unsigned char>(16, 0);
    if (what == L"oob")
        gSink = (*v)[16 + gSink];
    else if (what == L"crash")
        gSink = *(volatile int*)(uintptr_t)(gSink + 8);
    else if (what == L"stack")
        gSink = overflowStack(0);
    else if (what == L"throw")
        throw bad_alloc();
    else if (what == L"hang")
        for (;;)
            gSink = gSink + 1;
    else if (what == L"mem")
        for (;;)
        {
            char* p = new char[64 * 1024 * 1024];
            memset(p, 1, 64 * 1024 * 1024);
            gSink = p[gSink & 1];
        }
    printf("SELFTEST %ls finished without being detected\n", what.c_str());
    fflush(stdout);
    gStart = 0;
}
#pragma warning(pop)

static uint64_t iterSeed(uint64_t base, uint64_t iter)
{
    Rng r{ base + iter * 0x100000001B3ull };
    return r.next();
}

static DWORD WINAPI workerMain(void* arg)
{
    const WorkPlan& plan = *(const WorkPlan*)arg;
    ULONG guarantee = 256 * 1024;
    SetThreadStackGuarantee(&guarantee);
    set_terminate(onTerminate);
    signal(SIGABRT, onAbort);
    _set_invalid_parameter_handler(onInvalidParam);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#ifdef _DEBUG
    _CrtSetReportHook(onCrtReport);
#endif
    try
    {
        if (!plan.selftest.empty())
            selftest(plan.selftest);
        else if (!plan.file.empty())
        {
            Bytes bytes;
            string error;
            if (!readFile(plan.file, bytes, error))
            {
                printf("cannot read file\n");
            }
            else
            {
                gStart = GetTickCount64();
                ULONGLONG t0 = GetTickCount64();
                Analysis a;
                RunFiles files;
                RunOptions options;
                options.internalOnly = true;
                options.name = "fuzz";
                options.outDir = gOutDir;
                runAnalysis(bytes, options, a, files);
                PROCESS_MEMORY_COUNTERS_EX m = {};
                GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&m, sizeof(m));
                printf("FILE size=%zu ms=%llu funcs=%zu findings=%zu score=%d peak_private_mb=%llu\n", bytes.size(), GetTickCount64() - t0,
                       a.code.functions.size(), a.findings.size(), a.score, (unsigned long long)m.PeakPagefileUsage / (1024 * 1024));
                gStart = 0;
            }
        }
        else if (plan.useOneSeed)
            runOne(0, plan.oneSeed, plan.describe);
        else
            for (uint64_t i = plan.start; i < plan.end; i++)
                runOne(i, iterSeed(plan.base, i), false);
    }
    catch (const exception& e)
    {
        reportAndPark(FAIL_EXC, e.what(), false);
    }
    catch (...)
    {
        reportAndPark(FAIL_EXC, "unknown C++ exception", false);
    }
    SetEvent(gDoneEvent);
    return 0;
}

static int runWorker(const WorkPlan& plan)
{
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
    SymInitialize(GetCurrentProcess(), nullptr, TRUE);
    gFailEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    gDoneEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    AddVectoredExceptionHandler(1, throwTracker);
#ifndef __SANITIZE_ADDRESS__
    SetUnhandledExceptionFilter(crashFilter);
#endif

    // Жёсткий предел памяти: образец не должен оставить без памяти всю машину
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (job)
    {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = {};
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        info.ProcessMemoryLimit = (SIZE_T)(gMemLimit + gMemLimit / 2);
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info, sizeof(info));
        AssignProcessToJobObject(job, GetCurrentProcess());
    }

    wchar_t tempDir[MAX_PATH];
    GetTempPathW(MAX_PATH, tempDir);
    gOutDir = fs::path(tempDir) / L"exeias_fuzz" / (L"out_" + to_wstring(GetCurrentProcessId()));
    error_code ec;
    fs::create_directories(gOutDir, ec);

    if (plan.file.empty() && plan.selftest.empty() && !loadSeeds())
        return 9;

    gWorker = CreateThread(nullptr, gStackBytes, workerMain, (void*)&plan, STACK_SIZE_PARAM_IS_A_RESERVATION, nullptr);
    if (!gWorker)
        return 9;

    int exitCode = 0;
    for (;;)
    {
        HANDLE waits[2] = { gFailEvent, gDoneEvent };
        DWORD w = WaitForMultipleObjects(2, waits, FALSE, 50);
        if (w == WAIT_OBJECT_0)
        {
            exitCode = gFailCode;
            unsigned long long iter = gIter, seed = gSeed;
            if (gFailCode == FAIL_SEH)
            {
                printf("FAIL CRASH iter=%llu seed=0x%016llX code=0x%08lX addr=%p access=%llu target=0x%llX\n", iter, seed, gSehCode, gSehAddr,
                       (unsigned long long)gSehInfo[0], (unsigned long long)gSehInfo[1]);
                SuspendThread(gWorker);
                walkStack(gWorker, gSehContext);
            }
            else if (gFailCode == FAIL_EXC)
            {
                printf("FAIL EXCEPTION iter=%llu seed=0x%016llX what=%s (stack at throw)\n", iter, seed, gFailText);
                printFrames(gThrowFrames, gThrowCount);
            }
            else
            {
                printf("FAIL RUNTIME iter=%llu seed=0x%016llX code=%d text=%s\n", iter, seed, gFailCode, gFailText);
                printFrames(gFrames, gFrameCount);
            }
            break;
        }
        if (w == WAIT_OBJECT_0 + 1)
            break;

        ULONGLONG start = gStart;
        if (start && GetTickCount64() - start > gHangMs)
        {
            exitCode = FAIL_HANG;
            printf("FAIL HANG iter=%llu seed=0x%016llX limit_ms=%llu\n", (unsigned long long)gIter, (unsigned long long)gSeed, gHangMs);
            fflush(stdout);
            sampleStack(exitCode);
            break;
        }
        PROCESS_MEMORY_COUNTERS_EX mem = {};
        mem.cb = sizeof(mem);
        if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&mem, sizeof(mem)) && mem.PrivateUsage > gMemLimit)
        {
            exitCode = FAIL_MEM;
            printf("FAIL MEMORY iter=%llu seed=0x%016llX private_mb=%llu limit_mb=%llu elapsed_ms=%llu\n", (unsigned long long)gIter, (unsigned long long)gSeed,
                   (unsigned long long)mem.PrivateUsage / (1024 * 1024), gMemLimit / (1024 * 1024), start ? GetTickCount64() - start : 0);
            fflush(stdout);
            sampleStack(exitCode);
            break;
        }
    }
    fflush(stdout);
    fflush(stderr);
    fs::remove_all(gOutDir, ec);
    TerminateProcess(GetCurrentProcess(), (UINT)exitCode);
    return exitCode;
}

// ================================================================ надзор: перезапуск после сбоя и итоги

struct Totals
{
    uint64_t done = 0, valid = 0, decoded = 0, behaviors = 0, withFindings = 0, slow = 0, invariants = 0;
    uint64_t maxMs = 0, maxMsSeed = 0;
    map<int, uint64_t> failsByCode;
};

static int runSupervisor(const wstring& exe, const WorkPlan& plan, const wstring& passThrough, const fs::path& logPath)
{
    FILE* log = nullptr;
    if (!logPath.empty())
        log = _wfsopen(logPath.c_str(), L"ab", _SH_DENYNO);   // журнал можно читать во время прогона
    auto out = [&](const string& line)
    {
        if (log)
        {
            fwrite(line.data(), 1, line.size(), log);
            fflush(log);
        }
    };

    Totals t;
    vector<string> failures;
    uint64_t next = plan.start;
    uint64_t lastSeed = 0;
    while (next < plan.end)
    {
        SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
        HANDLE readPipe = nullptr, writePipe = nullptr;
        if (!CreatePipe(&readPipe, &writePipe, &sa, 1 << 16))
            return 1;
        SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);
        wstring cmd = L"\"" + exe + L"\" --worker --start " + to_wstring(next) + L" --end " + to_wstring(plan.end) + L" --base " + to_wstring(plan.base)
                      + passThrough;
        STARTUPINFOW si = {};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        si.hStdOutput = writePipe;
        si.hStdError = writePipe;
        PROCESS_INFORMATION pi = {};
        if (!CreateProcessW(exe.c_str(), cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
            return 1;
        CloseHandle(writePipe);

        uint64_t lastIter = next;
        bool sawIter = false;
        string pending;
        char buf[65536];
        DWORD n = 0;
        vector<string> failBlock;
        bool inFail = false;
        while (ReadFile(readPipe, buf, sizeof(buf), &n, nullptr) && n > 0)
        {
            pending.append(buf, n);
            size_t pos;
            while ((pos = pending.find('\n')) != string::npos)
            {
                string line = pending.substr(0, pos + 1);
                pending.erase(0, pos + 1);
                out(line);
                unsigned long long a = 0, b = 0;
                if (sscanf_s(line.c_str(), "ITER %llu seed=0x%llX", &a, &b) == 2)
                {
                    lastIter = a;
                    lastSeed = b;
                    sawIter = true;
                }
                else if (line.rfind("DONE ", 0) == 0)
                {
                    unsigned long long ms = 0, funcs = 0, dec = 0, finds = 0, beh = 0;
                    int valid = 0, score = 0;
                    if (sscanf_s(line.c_str(), "DONE %llu ms=%llu valid=%d funcs=%llu decoded=%llu findings=%llu behaviors=%llu score=%d", &a, &ms, &valid, &funcs, &dec, &finds, &beh, &score) == 8)
                    {
                        t.done++;
                        t.valid += valid != 0;
                        t.decoded += dec != 0;
                        t.behaviors += beh != 0;
                        t.withFindings += finds != 0;
                        t.slow += ms > 5000;
                        if (ms > t.maxMs)
                        {
                            t.maxMs = ms;
                            t.maxMsSeed = lastSeed;
                        }
                    }
                }
                else if (line.rfind("INVARIANT", 0) == 0)
                    t.invariants++;
                else if (line.rfind("FAIL ", 0) == 0)
                    failures.push_back(line);
            }
        }
        if (!pending.empty())
            out(pending + "\n");
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD code = 0;
        GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(readPipe);

        if (code == 0)
            break;
        t.failsByCode[(int)code]++;
        char line[160];
        snprintf(line, sizeof(line), "CHILD-EXIT code=0x%lX lastIter=%llu seed=0x%016llX\n", code, (unsigned long long)lastIter, (unsigned long long)lastSeed);
        out(line);
        if (code != FAIL_SEH && code != FAIL_HANG && code != FAIL_EXC && code != FAIL_MEM && code != FAIL_ABORT && code != FAIL_CRT && code != FAIL_PARAM)
            failures.push_back(line);
        if (!sawIter)
        {
            out("ABORT: worker made no progress\n");
            break;
        }
        next = lastIter + 1;
    }

    string s = "SUMMARY iterations_planned=" + to_string(plan.end - plan.start) + " completed=" + to_string(t.done) + " valid_pe=" + to_string(t.valid)
               + " with_decoded_code=" + to_string(t.decoded) + " with_behaviors=" + to_string(t.behaviors) + " with_findings=" + to_string(t.withFindings)
               + " slow_over_5s=" + to_string(t.slow) + " max_ms=" + to_string(t.maxMs) + " max_ms_seed=" + hex32(t.maxMsSeed) + " invariant_violations=" + to_string(t.invariants) + "\n";
    for (const auto& item : t.failsByCode)
        s += "SUMMARY exit_code=" + hex32((uint32_t)item.first) + " count=" + to_string(item.second) + "\n";
    for (const string& f : failures)
        s += "SUMMARY " + f;
    out(s);
    fputs(s.c_str(), stdout);
    if (log)
        fclose(log);
    return failures.empty() && t.invariants == 0 ? 0 : 1;
}

// ================================================================ точка входа

int wmain(int argc, wchar_t** argv)
{
    WorkPlan plan;
    bool supervise = false, worker = false;
    fs::path logPath;
    wstring passThrough;
    uint64_t iters = 0;
#ifdef __SANITIZE_ADDRESS__
    gStackBytes = 16 * 1024 * 1024;
    gMemLimit = 3000ull * 1024 * 1024;
#elif defined(_DEBUG)
    gStackBytes = 16 * 1024 * 1024;
#endif
    for (int i = 1; i < argc; i++)
    {
        wstring a = argv[i];
        auto value = [&]() -> wstring { return i + 1 < argc ? argv[++i] : L""; };
        auto number = [&]() -> uint64_t { return wcstoull(value().c_str(), nullptr, 0); };
        if (a == L"--supervise") supervise = true;
        else if (a == L"--worker") worker = true;
        else if (a == L"--describe") plan.describe = true;
        else if (a == L"--iters") iters = number();
        else if (a == L"--start") plan.start = number();
        else if (a == L"--end") plan.end = number();
        else if (a == L"--base") plan.base = number();
        else if (a == L"--seed") { plan.oneSeed = number(); plan.useOneSeed = true; }
        else if (a == L"--log") logPath = value();
        else if (a == L"--file") plan.file = value();
        else if (a == L"--selftest") plan.selftest = value();
        else if (a == L"--scenario") gScenario = value();
        else if (a == L"--hang-sec") { uint64_t v = number(); gHangMs = v * 1000; passThrough += L" --hang-sec " + to_wstring(v); }
        else if (a == L"--mem-mb") { uint64_t v = number(); gMemLimit = v * 1024 * 1024; passThrough += L" --mem-mb " + to_wstring(v); }
        else if (a == L"--stack-kb") { uint64_t v = number(); gStackBytes = (size_t)v * 1024; passThrough += L" --stack-kb " + to_wstring(v); }
        else if (a == L"--rar") { wstring v = value(); gRar = v; passThrough += L" --rar \"" + v + L"\""; }
        else
        {
            fwprintf(stderr, L"unknown option %s\n", a.c_str());
            return 64;
        }
    }
    if (iters)
        plan.end = plan.start + iters;

    if (supervise)
    {
        wchar_t self[MAX_PATH];
        GetModuleFileNameW(nullptr, self, MAX_PATH);
        return runSupervisor(self, plan, passThrough, logPath);
    }
    if (!worker && !plan.useOneSeed && plan.file.empty() && plan.selftest.empty())
    {
        fprintf(stderr, "usage: --supervise --iters N [--base B] [--log file] | --seed S [--describe] | --file path\n");
        return 64;
    }
    return runWorker(plan);
}
