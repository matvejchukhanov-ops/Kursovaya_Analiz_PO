#include "pe.h"
#include "input.h"

#include <cmath>
#include <ctime>

uint16_t rd16(const vector<unsigned char>& b, size_t o)
{
    return o + 2 <= b.size() ? (uint16_t)(b[o] | (b[o + 1] << 8)) : 0;
}

uint32_t rd32(const vector<unsigned char>& b, size_t o)
{
    if (o + 4 > b.size())
        return 0;
    return (uint32_t)b[o] | ((uint32_t)b[o + 1] << 8) | ((uint32_t)b[o + 2] << 16) | ((uint32_t)b[o + 3] << 24);
}

uint64_t rd64(const vector<unsigned char>& b, size_t o)
{
    return (uint64_t)rd32(b, o) | ((uint64_t)rd32(b, o + 4) << 32);
}

double entropy(const vector<unsigned char>& b, size_t from, size_t to)
{
    if (to <= from)
        return 0;
    size_t counts[256] = { 0 };
    for (size_t i = from; i < to; i++)
        counts[b[i]]++;
    double h = 0, n = (double)(to - from);
    for (int i = 0; i < 256; i++)
        if (counts[i])
        {
            double p = counts[i] / n;
            h -= p * log2(p);
        }
    return h;
}

size_t rvaToOffset(const PeInfo& pe, uint64_t rva)
{
    if (rva < pe.sizeOfHeaders)
        return rva < pe.fileSize ? (size_t)rva : NPOS;
    for (const Section& s : pe.sections)
    {
        uint32_t size = max(s.vsize, s.rawSize);
        if (rva >= s.va && rva < (uint64_t)s.va + size)
        {
            // заголовок секции может указывать за конец файла (испорченный или специально собранный PE)
            size_t off = s.rawPtr + (size_t)(rva - s.va);
            return off < (size_t)s.rawPtr + s.rawSize && off < pe.fileSize ? off : NPOS;
        }
    }
    return NPOS;
}

size_t vaToOffset(const PeInfo& pe, uint64_t va)
{
    return va < pe.imageBase ? NPOS : rvaToOffset(pe, va - pe.imageBase);
}

uint64_t offsetToVa(const PeInfo& pe, size_t off)
{
    if (off >= pe.fileSize)
        return 0;
    for (const Section& s : pe.sections)
        if (off >= s.rawPtr && off < (size_t)s.rawPtr + s.rawSize)
            return pe.imageBase + s.va + (off - s.rawPtr);
    return 0;
}

bool isExecutable(const Section& s)
{
    return (s.chars & 0x20000000) || (s.chars & 0x00000020);
}

const Section* sectionOfVa(const PeInfo& pe, uint64_t va)
{
    for (const Section& s : pe.sections)
    {
        uint64_t begin = pe.imageBase + s.va;
        if (va >= begin && va < begin + max(s.vsize, s.rawSize))
            return &s;
    }
    return nullptr;
}

string readCString(const vector<unsigned char>& b, size_t off, size_t maxLen = 256)
{
    string s;
    if (off == NPOS)
        return s;
    for (size_t i = off; i < b.size() && s.length() < maxLen && b[i]; i++)
        s += (char)b[i];
    return s;
}

void parseImports(const vector<unsigned char>& b, PeInfo& pe)
{
    size_t off = rvaToOffset(pe, pe.dirs[1].va);
    size_t ptr = pe.is64 ? 8 : 4;
    for (int d = 0; d < 512 && pe.dirs[1].va && off != NPOS && off + 20 <= b.size(); d++, off += 20)
    {
        uint32_t oft = rd32(b, off), nameRva = rd32(b, off + 12), ft = rd32(b, off + 16);
        if (!oft && !nameRva && !ft)
            break;

        ImportDll dll;
        dll.name = readCString(b, rvaToOffset(pe, nameRva));
        uint32_t thunks = oft ? oft : ft;
        for (size_t k = 0; k < 4096; k++)
        {
            size_t to = rvaToOffset(pe, thunks + k * ptr);
            if (to == NPOS)
                break;
            uint64_t v = pe.is64 ? rd64(b, to) : rd32(b, to);
            if (!v)
                break;
            bool byOrdinal = pe.is64 ? (v >> 63) != 0 : (v >> 31) != 0;
            string name = byOrdinal ? "#" + to_string(v & 0xFFFF)
                                    : readCString(b, rvaToOffset(pe, (uint32_t)v + 2));
            dll.funcs.push_back({ name, pe.imageBase + ft + k * ptr });
        }
        pe.imports.push_back(dll);
    }
}

PeInfo parsePe(const vector<unsigned char>& b)
{
    PeInfo pe;
    pe.fileSize = b.size();
    if (!isPeFile(b) || b.size() < 0x40)
    {
        pe.error = "нет сигнатуры MZ — файл не является исполняемым PE, анализируются только строки";
        return pe;
    }
    uint32_t nt = rd32(b, 0x3C);
    if ((size_t)nt + 24 > b.size() || rd32(b, nt) != 0x00004550)
    {
        pe.error = "нет сигнатуры PE\\0\\0 — заголовок повреждён или файл DOS";
        return pe;
    }

    size_t fh = nt + 4;
    pe.machine = rd16(b, fh);
    uint16_t sectionCount = rd16(b, fh + 2);
    pe.timestamp = rd32(b, fh + 4);
    uint16_t optionalSize = rd16(b, fh + 16);
    pe.isDll = (rd16(b, fh + 18) & 0x2000) != 0;

    size_t oh = fh + 20;
    uint16_t magic = rd16(b, oh);
    if (magic != 0x10B && magic != 0x20B)
    {
        pe.error = "неизвестный формат дополнительного заголовка";
        return pe;
    }
    pe.is64 = magic == 0x20B;
    pe.linker = to_string(oh + 3 < b.size() ? b[oh + 2] : 0) + "." + to_string(oh + 3 < b.size() ? b[oh + 3] : 0);
    pe.entryRva = rd32(b, oh + 16);
    pe.imageBase = pe.is64 ? rd64(b, oh + 24) : rd32(b, oh + 28);
    pe.sizeOfHeaders = rd32(b, oh + 60);
    pe.checksum = rd32(b, oh + 64);
    pe.subsystem = rd16(b, oh + 68);
    pe.dllChars = rd16(b, oh + 70);

    size_t dd = oh + (pe.is64 ? 112 : 96);
    uint32_t dirCount = rd32(b, dd - 4);
    for (uint32_t i = 0; i < 16 && i < dirCount; i++)
        pe.dirs[i] = { rd32(b, dd + i * 8), rd32(b, dd + i * 8 + 4) };

    size_t sh = oh + optionalSize;
    size_t end = pe.sizeOfHeaders;
    for (uint16_t i = 0; i < sectionCount && i < 96; i++, sh += 40)
    {
        if (sh + 40 > b.size())
            break;
        Section s;
        for (size_t c = 0; c < 8 && b[sh + c]; c++)
            s.name += (char)b[sh + c];
        s.vsize = rd32(b, sh + 8);
        s.va = rd32(b, sh + 12);
        s.rawSize = rd32(b, sh + 16);
        s.rawPtr = rd32(b, sh + 20);
        s.chars = rd32(b, sh + 36);
        size_t rawEnd = min(b.size(), (size_t)s.rawPtr + s.rawSize);
        s.entropy = entropy(b, min((size_t)s.rawPtr, b.size()), rawEnd);
        end = max(end, rawEnd);
        pe.sections.push_back(s);
    }
    pe.overlay = b.size() > end ? b.size() - end : 0;
    pe.isDotNet = pe.dirs[14].va != 0;
    parseImports(b, pe);
    pe.valid = true;
    return pe;
}

string machineName(uint16_t m)
{
    switch (m)
    {
    case 0x14C:  return "x86 (Intel 386)";
    case 0x8664: return "x64 (AMD64)";
    case 0x1C0:  return "ARM";
    case 0xAA64: return "ARM64";
    default:     return "неизвестная";
    }
}

string subsystemName(uint16_t s)
{
    switch (s)
    {
    case 1:  return "драйвер (Native)";
    case 2:  return "графическое приложение (Windows GUI)";
    case 3:  return "консольное приложение (Windows CUI)";
    default: return "другая (" + to_string(s) + ")";
    }
}

string formatTime(uint32_t t)
{
    time_t tt = t;
    tm g = {};
#ifdef _WIN32
    if (gmtime_s(&g, &tt) != 0)
        return "-";
#else
    gmtime_r(&tt, &g);
#endif
    char buf[32];
    strftime(buf, sizeof(buf), "%d.%m.%Y %H:%M:%S UTC", &g);
    return buf;
}
