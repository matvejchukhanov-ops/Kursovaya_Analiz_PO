#include "fsanalysis.h"
#include "disasm.h"
#include "pe.h"

#include <cstring>
#include <regex>

// ================================================================ операции с ФС

const string FS_OP_NAMES[FS_OP_COUNT] = {
    "Перечисление файлов и каталогов",
    "Перечисление логических дисков",
    "Открытие и чтение файлов",
    "Запись в файлы",
    "Копирование (в т.ч. поверх существующих файлов)",
    "Перемещение и замена",
    "Удаление файлов и каталогов",
    "Изменение атрибутов и меток времени",
    "Системные и временные каталоги",
    "Получение собственного пути",
    "Запуск файлов",
};

const vector<FsApi> FS_APIS = {
    { "FindFirstFile", FS_ENUM, false }, { "FindFirstFileEx", FS_ENUM, false },
    { "FindNextFile", FS_ENUM, false },  { "FindClose", FS_ENUM, false },
    { "GetLogicalDrives", FS_DRIVES, false }, { "GetLogicalDriveStrings", FS_DRIVES, false },
    { "GetDriveType", FS_DRIVES, false },     { "GetVolumeInformation", FS_DRIVES, false },
    { "CreateFile", FS_OPEN, true }, { "ReadFile", FS_OPEN, true }, { "OpenFile", FS_OPEN, false },
    { "WriteFile", FS_WRITE, true }, { "SetEndOfFile", FS_WRITE, true }, { "SetFilePointer", FS_WRITE, true },
    { "SetFilePointerEx", FS_WRITE, true }, { "FlushFileBuffers", FS_WRITE, true },
    { "CreateFileMapping", FS_WRITE, false }, { "MapViewOfFile", FS_WRITE, false },
    { "CopyFile", FS_COPY, false }, { "CopyFileEx", FS_COPY, false },
    { "MoveFile", FS_MOVE, false }, { "MoveFileEx", FS_MOVE, false }, { "ReplaceFile", FS_MOVE, false },
    { "DeleteFile", FS_DELETE, false }, { "RemoveDirectory", FS_DELETE, false }, { "SHFileOperation", FS_DELETE, false },
    { "SetFileAttributes", FS_ATTR, false }, { "SetFileTime", FS_ATTR, false }, { "SetFileSecurity", FS_ATTR, false },
    { "CreateDirectory", FS_DIRS, false }, { "GetSystemDirectory", FS_DIRS, false },
    { "GetWindowsDirectory", FS_DIRS, false }, { "GetTempPath", FS_DIRS, false },
    { "GetTempFileName", FS_DIRS, false }, { "SHGetFolderPath", FS_DIRS, false },
    { "SHGetSpecialFolderPath", FS_DIRS, false }, { "GetCurrentDirectory", FS_DIRS, true },
    { "GetModuleFileName", FS_SELF, true }, { "GetCommandLine", FS_SELF, true },
    { "WinExec", FS_EXEC, false }, { "ShellExecute", FS_EXEC, false }, { "ShellExecuteEx", FS_EXEC, false },
    { "CreateProcess", FS_EXEC, false },
};

bool apiMatches(const string& name, const string& stem)
{
    return name == stem || name == stem + "A" || name == stem + "W";
}

string fsOpOf(const string& api, bool& lowLevel)
{
    for (const FsApi& a : FS_APIS)
        if (apiMatches(api, a.stem))
        {
            lowLevel = a.lowLevel;
            return FS_OP_NAMES[a.op];
        }
    return "";
}

// ================================================================ прототипы WinAPI

// Как показывать аргумент
enum ArgFmt { A_ANY, A_STR, A_NUM, A_BOOL, A_FATTR, A_ACCESS, A_SHARE, A_DISP, A_SHOW, A_HKEY, A_REGTYPE, A_MOVE, A_SAM };

struct ApiProto
{
    string name;              // имя без суффикса A/W (или полное, если варианты отличаются)
    vector<ArgFmt> args;
    bool cdeclConv = false;   // стек чистит вызывающий
};

const vector<ApiProto> PROTOS = {
    // файловая система
    { "CopyFile", { A_STR, A_STR, A_BOOL } },
    { "CopyFileEx", { A_STR, A_STR, A_ANY, A_ANY, A_ANY, A_NUM } },
    { "MoveFile", { A_STR, A_STR } },
    { "MoveFileEx", { A_STR, A_STR, A_MOVE } },
    { "DeleteFile", { A_STR } },
    { "RemoveDirectory", { A_STR } },
    { "CreateDirectory", { A_STR, A_ANY } },
    { "SetFileAttributes", { A_STR, A_FATTR } },
    { "GetFileAttributes", { A_STR } },
    { "FindFirstFile", { A_STR, A_ANY } },
    { "FindFirstFileEx", { A_STR, A_NUM, A_ANY, A_NUM, A_ANY, A_NUM } },
    { "FindNextFile", { A_ANY, A_ANY } },
    { "FindClose", { A_ANY } },
    { "CreateFile", { A_STR, A_ACCESS, A_SHARE, A_ANY, A_DISP, A_FATTR, A_ANY } },
    { "ReadFile", { A_ANY, A_ANY, A_NUM, A_ANY, A_ANY } },
    { "WriteFile", { A_ANY, A_STR, A_NUM, A_ANY, A_ANY } },
    { "SetFilePointer", { A_ANY, A_NUM, A_ANY, A_NUM } },
    { "SetEndOfFile", { A_ANY } },
    { "FlushFileBuffers", { A_ANY } },
    { "CloseHandle", { A_ANY } },
    { "SetFileTime", { A_ANY, A_ANY, A_ANY, A_ANY } },
    { "GetSystemDirectory", { A_ANY, A_NUM } },
    { "GetWindowsDirectory", { A_ANY, A_NUM } },
    { "GetTempPath", { A_NUM, A_ANY } },
    { "GetTempFileName", { A_STR, A_STR, A_NUM, A_ANY } },
    { "GetModuleFileName", { A_ANY, A_ANY, A_NUM } },
    { "GetCommandLine", {} },
    { "GetLogicalDrives", {} },
    { "GetLogicalDriveStrings", { A_NUM, A_ANY } },
    { "GetDriveType", { A_STR } },
    // запуск
    { "WinExec", { A_STR, A_SHOW } },
    { "ShellExecute", { A_ANY, A_STR, A_STR, A_STR, A_STR, A_SHOW } },
    { "CreateProcess", { A_STR, A_STR, A_ANY, A_ANY, A_BOOL, A_NUM, A_ANY, A_STR, A_ANY, A_ANY } },
    // реестр
    { "RegCreateKey", { A_HKEY, A_STR, A_ANY } },
    { "RegOpenKey", { A_HKEY, A_STR, A_ANY } },
    { "RegCreateKeyEx", { A_HKEY, A_STR, A_NUM, A_ANY, A_NUM, A_SAM, A_ANY, A_ANY, A_ANY } },
    { "RegOpenKeyEx", { A_HKEY, A_STR, A_NUM, A_SAM, A_ANY } },
    { "RegSetValueEx", { A_HKEY, A_STR, A_NUM, A_REGTYPE, A_STR, A_NUM } },
    { "RegSetValue", { A_HKEY, A_STR, A_REGTYPE, A_STR, A_NUM } },
    { "RegQueryValueEx", { A_HKEY, A_STR, A_ANY, A_ANY, A_ANY, A_ANY } },
    { "RegDeleteValue", { A_HKEY, A_STR } },
    { "RegDeleteKey", { A_HKEY, A_STR } },
    { "RegCloseKey", { A_HKEY } },
    // синхронизация, модули, прочее
    { "CreateMutex", { A_ANY, A_BOOL, A_STR } },
    { "OpenMutex", { A_NUM, A_BOOL, A_STR } },
    { "GetLastError", {} },
    { "LoadLibrary", { A_STR } },
    { "LoadLibraryEx", { A_STR, A_ANY, A_NUM } },
    { "GetProcAddress", { A_ANY, A_STR } },
    { "GetModuleHandle", { A_STR } },
    { "ExitProcess", { A_NUM } },
    { "Sleep", { A_NUM } },
    { "MessageBox", { A_ANY, A_STR, A_STR, A_NUM } },
    { "GetLocalTime", { A_ANY } },
    { "GetSystemTime", { A_ANY } },
    { "GetTimeZoneInformation", { A_ANY } },
    { "GetVersion", {} },
    { "GetVersionEx", { A_ANY } },
    { "GetStartupInfo", { A_ANY } },
    { "HeapAlloc", { A_ANY, A_NUM, A_NUM } },
    { "HeapFree", { A_ANY, A_NUM, A_ANY } },
    { "HeapReAlloc", { A_ANY, A_NUM, A_ANY, A_NUM } },
    { "HeapSize", { A_ANY, A_NUM, A_ANY } },
    { "HeapCreate", { A_NUM, A_NUM, A_NUM } },
    { "HeapDestroy", { A_ANY } },
    { "VirtualAlloc", { A_ANY, A_NUM, A_NUM, A_NUM } },
    { "VirtualFree", { A_ANY, A_NUM, A_NUM } },
    { "GetStdHandle", { A_NUM } },
    { "GetFileType", { A_ANY } },
    { "SetHandleCount", { A_NUM } },
    { "SetStdHandle", { A_NUM, A_ANY } },
    { "GetEnvironmentStrings", {} },
    { "FreeEnvironmentStrings", { A_ANY } },
    { "GetEnvironmentVariable", { A_STR, A_ANY, A_NUM } },
    { "SetEnvironmentVariable", { A_STR, A_STR } },
    { "GetCurrentProcess", {} },
    { "TerminateProcess", { A_ANY, A_NUM } },
    { "UnhandledExceptionFilter", { A_ANY } },
    { "RtlUnwind", { A_ANY, A_ANY, A_ANY, A_ANY } },
    { "MultiByteToWideChar", { A_NUM, A_NUM, A_ANY, A_NUM, A_ANY, A_NUM } },
    { "WideCharToMultiByte", { A_NUM, A_NUM, A_ANY, A_NUM, A_ANY, A_NUM, A_ANY, A_ANY } },
    { "GetCPInfo", { A_NUM, A_ANY } },
    { "GetACP", {} },
    { "GetOEMCP", {} },
    { "LCMapString", { A_NUM, A_NUM, A_ANY, A_NUM, A_ANY, A_NUM } },
    { "CompareString", { A_NUM, A_NUM, A_ANY, A_NUM, A_ANY, A_NUM } },
    { "GetStringTypeA", { A_NUM, A_NUM, A_ANY, A_NUM, A_ANY } },
    { "GetStringTypeW", { A_NUM, A_ANY, A_NUM, A_ANY } },
    { "GetActiveWindow", {} },
    { "GetLastActivePopup", { A_ANY } },
    { "wsprintf", { A_ANY, A_STR }, true },
};

const ApiProto* findProto(const string& name)
{
    for (const ApiProto& p : PROTOS)
        if (apiMatches(name, p.name))
            return &p;
    return nullptr;
}

ArgFmt argFormat(const CallSite& c, size_t i)
{
    const ApiProto* p = c.isApi ? findProto(c.target) : nullptr;
    return p && i < p->args.size() ? p->args[i] : A_ANY;
}

// ---------------------------------------------------------------- константы WinAPI

struct Named
{
    uint64_t value;
    const char* name;
};

const vector<Named> FILE_ATTRS = {
    { 0x1, "FILE_ATTRIBUTE_READONLY" }, { 0x2, "FILE_ATTRIBUTE_HIDDEN" }, { 0x4, "FILE_ATTRIBUTE_SYSTEM" },
    { 0x10, "FILE_ATTRIBUTE_DIRECTORY" }, { 0x20, "FILE_ATTRIBUTE_ARCHIVE" }, { 0x80, "FILE_ATTRIBUTE_NORMAL" },
    { 0x100, "FILE_ATTRIBUTE_TEMPORARY" }, { 0x04000000, "FILE_FLAG_DELETE_ON_CLOSE" },
    { 0x40000000, "FILE_FLAG_OVERLAPPED" }, { 0x80000000, "FILE_FLAG_WRITE_THROUGH" },
};
const vector<Named> ACCESS = {
    { 0x80000000, "GENERIC_READ" }, { 0x40000000, "GENERIC_WRITE" }, { 0x20000000, "GENERIC_EXECUTE" },
    { 0x10000000, "GENERIC_ALL" }, { 0x10000, "DELETE" },
};
const vector<Named> SHARE = { { 1, "FILE_SHARE_READ" }, { 2, "FILE_SHARE_WRITE" }, { 4, "FILE_SHARE_DELETE" } };
const vector<Named> DISPOSITION = {
    { 1, "CREATE_NEW" }, { 2, "CREATE_ALWAYS" }, { 3, "OPEN_EXISTING" }, { 4, "OPEN_ALWAYS" }, { 5, "TRUNCATE_EXISTING" },
};
const vector<Named> SHOW = {
    { 0, "SW_HIDE" }, { 1, "SW_SHOWNORMAL" }, { 2, "SW_SHOWMINIMIZED" }, { 3, "SW_SHOWMAXIMIZED" },
    { 4, "SW_SHOWNOACTIVATE" }, { 5, "SW_SHOW" }, { 6, "SW_MINIMIZE" }, { 7, "SW_SHOWMINNOACTIVE" },
    { 8, "SW_SHOWNA" }, { 9, "SW_RESTORE" }, { 10, "SW_SHOWDEFAULT" },
};
const vector<Named> HKEYS = {
    { 0x80000000, "HKEY_CLASSES_ROOT" }, { 0x80000001, "HKEY_CURRENT_USER" }, { 0x80000002, "HKEY_LOCAL_MACHINE" },
    { 0x80000003, "HKEY_USERS" }, { 0x80000005, "HKEY_CURRENT_CONFIG" },
};
const vector<Named> REG_TYPES = {
    { 0, "REG_NONE" }, { 1, "REG_SZ" }, { 2, "REG_EXPAND_SZ" }, { 3, "REG_BINARY" }, { 4, "REG_DWORD" },
    { 7, "REG_MULTI_SZ" }, { 11, "REG_QWORD" },
};
const vector<Named> MOVE_FLAGS = {
    { 1, "MOVEFILE_REPLACE_EXISTING" }, { 2, "MOVEFILE_COPY_ALLOWED" }, { 4, "MOVEFILE_DELAY_UNTIL_REBOOT" },
    { 8, "MOVEFILE_WRITE_THROUGH" },
};
const vector<Named> SAM = {
    { 0xF003F, "KEY_ALL_ACCESS" }, { 0x20019, "KEY_READ" }, { 0x20006, "KEY_WRITE" },
    { 0x1, "KEY_QUERY_VALUE" }, { 0x2, "KEY_SET_VALUE" },
};

string exactName(uint64_t v, const vector<Named>& table)
{
    for (const Named& n : table)
        if (n.value == v)
            return n.name;
    return hexNum(v);
}

string flagNames(uint64_t v, const vector<Named>& table)
{
    if (v == 0)
        return "0";
    string s;
    uint64_t rest = v;
    for (const Named& n : table)
        if ((v & n.value) == n.value)
        {
            s += (s.empty() ? "" : " | ") + string(n.name);
            rest &= ~n.value;
        }
    if (rest)
        s += (s.empty() ? "" : " | ") + hexNum(rest);
    return s;
}

string hkeyShort(uint64_t v)
{
    switch (v & 0xFFFFFFFF)
    {
    case 0x80000000: return "HKCR";
    case 0x80000001: return "HKCU";
    case 0x80000002: return "HKLM";
    case 0x80000003: return "HKU";
    default:         return "";
    }
}

string quoted(const string& s)
{
    return "\"" + s + "\"";
}

string formatValue(const Value& v, ArgFmt f)
{
    switch (v.kind)
    {
    case V_STRING:
        return quoted(v.text);
    case V_LOCAL:
        return v.content.empty() ? v.text : v.text + " = " + quoted(v.content);
    case V_ARG:
    case V_API:
    case V_SYMBOL:
        return v.text;
    case V_CONST:
    {
        uint64_t n = (uint64_t)v.num;
        switch (f)
        {
        case A_BOOL:    return n ? "TRUE" : "FALSE";
        case A_STR:     return n == 0 ? "NULL" : hexNum(n);
        case A_ANY:     return n == 0 ? "NULL" : hexNum(n);
        case A_FATTR:   return flagNames(n, FILE_ATTRS);
        case A_ACCESS:  return flagNames(n, ACCESS);
        case A_SHARE:   return flagNames(n, SHARE);
        case A_DISP:    return exactName(n, DISPOSITION);
        case A_SHOW:    return exactName(n, SHOW);
        case A_HKEY:    return exactName(n & 0xFFFFFFFF, HKEYS);
        case A_REGTYPE: return exactName(n, REG_TYPES);
        case A_MOVE:    return flagNames(n, MOVE_FLAGS);
        case A_SAM:     return exactName(n, SAM);
        default:        return hexNum(n);
        }
    }
    default:
        return "?";
    }
}

// Текст значения для сборки строк (пути, sprintf)
string textOf(const Value& v)
{
    switch (v.kind)
    {
    case V_STRING: return v.text;
    case V_LOCAL:  return v.content.empty() ? "<" + v.text + ">" : v.content;
    case V_ARG:    return "<" + v.text + ">";
    case V_SYMBOL: return v.text;
    case V_CONST:  return hexNum((uint64_t)v.num);
    default:       return "?";
    }
}

string formatCall(const CallSite& c)
{
    if (!c.argsKnown)
        return c.target + "(…)";
    string s = c.target + "(";
    for (size_t i = 0; i < c.args.size(); i++)
        s += (i ? ", " : "") + formatValue(c.args[i], argFormat(c, i));
    return s + ")";
}

bool isConst(const CallSite& c, size_t i, uint64_t v)
{
    return i < c.args.size() && c.args[i].kind == V_CONST && (uint64_t)c.args[i].num == v;
}

string callNote(const CallSite& c)
{
    if (!c.isApi || !c.argsKnown)
        return "";
    const string& n = c.target;
    if (apiMatches(n, "CopyFile") && isConst(c, 2, 0))
        return "файл-приёмник перезаписывается, если существует";
    if (apiMatches(n, "SetFileAttributes") && c.args.size() > 1 && c.args[1].kind == V_CONST)
    {
        uint64_t a = (uint64_t)c.args[1].num;
        if (a == 0x80)
            return "сбрасываются атрибуты «только чтение», «скрытый», «системный»";
        if (a & 0x6)
            return "файл скрывается атрибутами «скрытый»/«системный»";
    }
    if (apiMatches(n, "CreateFile") && (isConst(c, 4, 2) || isConst(c, 4, 5)))
        return "содержимое существующего файла уничтожается (усечение до нуля)";
    if (apiMatches(n, "MoveFileEx") && c.args.size() > 2 && c.args[2].kind == V_CONST && (c.args[2].num & 4))
        return "операция откладывается до перезагрузки";
    if (apiMatches(n, "DeleteFile"))
        return "файл удаляется безвозвратно, минуя корзину";
    if (apiMatches(n, "FindFirstFile") && !c.args.empty() && textOf(c.args[0]).find("*.*") != NPOS)
        return "перебираются все файлы каталога";
    if ((apiMatches(n, "RegCreateKey") || apiMatches(n, "RegOpenKey") || apiMatches(n, "RegCreateKeyEx")
         || apiMatches(n, "RegOpenKeyEx")) && c.args.size() > 1
        && containsNoCase(textOf(c.args[1]), "currentversion\\run") && c.args[0].kind == V_CONST)
    {
        string hive = hkeyShort((uint64_t)c.args[0].num);
        if (hive == "HKLM")
            return "автозапуск для всех пользователей (нужны права администратора)";
        if (hive == "HKCU")
            return "автозапуск для текущего пользователя";
    }
    if ((apiMatches(n, "WinExec") && c.args.size() > 1) || (apiMatches(n, "ShellExecute") && c.args.size() > 5))
    {
        const Value& show = c.args[apiMatches(n, "WinExec") ? 1 : 5];
        if (show.kind == V_CONST)
            return show.num == 0 ? "скрытый запуск (окно не показывается)" : "окно программы показывается пользователю";
    }
    if (apiMatches(n, "CreateMutex") && c.args.size() > 2 && c.args[2].kind == V_STRING)
        return "имя мьютекса — индикатор заражения";
    return "";
}

// ================================================================ строки образа

struct StringTable
{
    map<uint64_t, pair<string, bool>> byVa;   // адрес -> (текст, UTF-16)

    // Строка, начинающаяся с адреса или содержащая его (тогда — её хвост)
    string at(uint64_t va) const
    {
        auto it = byVa.upper_bound(va);
        if (it == byVa.begin())
            return "";
        --it;
        const string& text = it->second.first;
        size_t width = it->second.second ? 2 : 1;
        uint64_t offset = va - it->first;
        if (offset >= text.length() * width || offset % width)
            return "";
        return text.substr((size_t)(offset / width));
    }
};

// ================================================================ разбор функции: стек и регистры

struct SimContext
{
    const PeInfo& pe;
    const map<uint64_t, string>& iat;
    const map<uint64_t, string>& thunks;
    const StringTable& strings;
    const map<uint64_t, int>& retPop;       // внутренние stdcall-функции: сколько байт снимает ret N
    const set<string>& cdeclApis;           // импорт из CRT — стек чистит вызывающий
    int64_t ptr;
};

class FunctionSimulator
{
public:
    FunctionSimulator(const SimContext& ctx, FunctionInfo& f, const vector<Insn>& code)
        : ctx(ctx), f(f), code(code) {}

    void run()
    {
        bool dead = false;
        for (size_t i = 0; i < code.size(); i++)
        {
            const Insn& in = code[i];
            if (dead)
            {
                // сюда попадаем только переходом — берём глубину стека из точки перехода
                auto it = pending.find(in.addr);
                if (it != pending.end())
                {
                    depth = it->second.depth;
                    depthValid = it->second.depthValid;
                    for (int r = 0; r < 16; r++)
                        regs[r] = it->second.regs[r];
                }
                else
                    depthValid = false;
                stack.clear();
                consumed.clear();
                dead = false;
            }
            dead = step(i);
        }
    }

private:
    const SimContext& ctx;
    FunctionInfo& f;
    const vector<Insn>& code;

    Value regs[16];
    vector<Value> stack;            // значения, положенные push (аргументы будущих вызовов)
    vector<bool> consumed;          // уже отнесены к cdecl-вызову, ждут add esp
    int64_t depth = 0;              // на сколько байт стек опустился от входа в функцию
    bool depthValid = true;
    bool hasFrame = false;          // ebp = esp (кадр стека)
    int64_t frameDepth = 0;
    map<int64_t, Value> slots;      // ячейки кадра: позиция -> значение
    map<int64_t, string> buffers;   // содержимое буферов в стеке: позиция -> текст

    // Состояние в точке перехода: туда возвращаемся после ret/jmp
    struct BranchState
    {
        int64_t depth;
        bool depthValid;
        Value regs[16];
    };
    map<uint64_t, BranchState> pending;

    bool is64() const { return ctx.pe.is64; }

    Value constValue(uint64_t v)
    {
        Value r;
        string s = ctx.strings.at(v);
        if (!s.empty())
        {
            r.kind = V_STRING;
            r.text = s;
        }
        else
            r.kind = V_CONST;
        r.num = (int64_t)v;
        return r;
    }

    Value symbol(const string& text)
    {
        Value v;
        v.kind = V_SYMBOL;
        v.text = text;
        return v;
    }

    string slotName(int64_t pos)
    {
        if (pos < 0)
            return "var_" + hexPlain((uint64_t)-pos);
        if (pos >= ctx.ptr)
            return "arg_" + hexPlain((uint64_t)(pos - ctx.ptr));
        return "ret_addr";
    }

    void unknown(int r)
    {
        if (r >= 0 && r < 16)
            regs[r] = Value();
    }

    void unknown8(int r)
    {
        unknown(r);
        if (r < 8)
            unknown(r & 3);   // ah, ch, dh, bh
    }

    void clobberVolatile()
    {
        unknown(R_AX);
        unknown(R_CX);
        unknown(R_DX);
        if (is64())
            for (int r = 8; r <= 11; r++)
                unknown(r);
    }

    // Позиция ячейки кадра для [esp+disp] / [ebp+disp]
    bool slotOf(const Insn& in, int64_t& pos)
    {
        if (!isMemory(in) || in.index >= 0)
            return false;
        if (in.base == R_SP && depthValid)
        {
            pos = in.disp - depth;
            return true;
        }
        if (in.base == R_BP && hasFrame)
        {
            pos = in.disp - frameDepth;
            return true;
        }
        return false;
    }

    Value loadMem(const Insn& in)
    {
        if (in.absolute || in.ripRel)
        {
            auto f = ctx.iat.find(in.memAddr);
            if (f != ctx.iat.end())
            {
                Value v;
                v.kind = V_API;
                v.text = f->second;
                return v;
            }
            // кусок строки, копируемый в стек по 2–4 байта («c:\zwxp» -> [esp+14h])
            string s = ctx.strings.at(in.memAddr);
            if (!s.empty())
            {
                Value v;
                v.kind = V_STRING;
                v.num = (int64_t)in.memAddr;
                v.text = s;
                return v;
            }
            return Value();
        }
        int64_t pos;
        if (!slotOf(in, pos))
            return Value();
        auto s = slots.find(pos);
        if (s != slots.end())
            return s->second;
        if (pos >= ctx.ptr)
        {
            Value v;
            v.kind = V_ARG;
            v.num = pos;
            v.text = slotName(pos);
            return v;
        }
        return Value();
    }

    void storeMem(const Insn& in, const Value& v)
    {
        int64_t pos;
        if (slotOf(in, pos))
            slots[pos] = v;
    }

    Value addressOf(const Insn& in)
    {
        int64_t pos;
        if (slotOf(in, pos))
        {
            Value v;
            v.kind = pos >= ctx.ptr ? V_ARG : V_LOCAL;
            v.num = pos;
            v.text = pos >= ctx.ptr ? "&" + slotName(pos) : slotName(pos);
            return v;
        }
        if (in.absolute || in.ripRel)
            return constValue(in.memAddr);
        return Value();
    }

    string bufferText(int64_t pos)
    {
        auto it = buffers.find(pos);
        if (it != buffers.end())
            return it->second;
        auto slot = slots.find(pos);
        if (slot != slots.end() && slot->second.kind == V_STRING)
            return slot->second.text;              // строка, собранная в стеке командами mov
        // указатель внутрь буфера с символическим содержимым («<командная строка>» + 1)
        for (int64_t d = 1; d <= 8; d++)
        {
            auto near = buffers.find(pos - d);
            if (near != buffers.end() && !near->second.empty() && near->second[0] == '<')
                return near->second;
        }
        return "";
    }

    Value resolve(Value v)
    {
        if (v.kind == V_LOCAL)
            v.content = bufferText(v.num);
        v.atEnd = false;
        return v;
    }

    void push(const Value& v)
    {
        if (depthValid)
            depth += ctx.ptr;
        stack.push_back(v);
        consumed.push_back(false);
    }

    Value pop()
    {
        if (depthValid)
            depth -= ctx.ptr;
        if (stack.empty())
            return Value();
        Value v = stack.back();
        stack.pop_back();
        consumed.pop_back();
        return v;
    }

    void dropEntries(int64_t n)
    {
        for (int64_t i = 0; i < n && !stack.empty(); i++)
        {
            stack.pop_back();
            consumed.pop_back();
        }
    }

    void branchTo(uint64_t target, uint64_t from)
    {
        if (target <= from || pending.count(target))
            return;
        BranchState& st = pending[target];
        st.depth = depth;
        st.depthValid = depthValid;
        for (int r = 0; r < 16; r++)
            st.regs[r] = regs[r];
    }

    bool isPush(const Insn& c)
    {
        return !c.twoByte && ((c.op >= 0x50 && c.op <= 0x57) || c.op == 0x68 || c.op == 0x6A
                              || (c.op == 0xFF && c.regRaw == 6));
    }

    bool isPop(const Insn& c)
    {
        return !c.twoByte && ((c.op >= 0x58 && c.op <= 0x5F) || c.op == 0x8F);
    }

    // cdecl: сколько аргументов снимет «add esp, N» после вызова (с поправкой на чужие push между ними)
    int cleanupArgc(size_t idx)
    {
        int pushes = 0;
        for (size_t j = idx + 1; j < code.size() && j <= idx + 12; j++)
        {
            const Insn& c = code[j];
            if (!c.twoByte && (c.op == 0x83 || c.op == 0x81) && c.mod == 3 && c.rm == R_SP && c.regRaw == 0)
            {
                int total = (int)(c.imm / ctx.ptr);
                int window = total - pushes;
                if (window < 0)
                    return -1;
                int alreadyTaken = 0;
                for (int k = 0; k < window && k < (int)stack.size(); k++)
                    if (consumed[stack.size() - 1 - k])
                        alreadyTaken++;
                int n = window - alreadyTaken;
                return n >= 0 ? n : -1;
            }
            if (isPush(c))
                pushes++;
            else if (isPop(c))
                pushes--;
            bool branch = (c.relBranch && !(c.op == 0xE8 && !c.twoByte)) || (!c.twoByte && (c.op == 0xC2 || c.op == 0xC3))
                          || (!c.twoByte && c.op == 0xFF && (c.regRaw == 4 || c.regRaw == 5));
            if (branch)
                return -1;
        }
        return -1;
    }

    // Снять со стека n аргументов stdcall-вызова (или только пометить для cdecl)
    vector<Value> takeArgs(int n, bool popThem)
    {
        vector<Value> args;
        for (int i = 0; i < n; i++)
        {
            size_t k = stack.size() - 1 - i;
            args.push_back(i < (int)stack.size() ? resolve(stack[k]) : Value());
            if (!popThem && i < (int)stack.size())
                consumed[k] = true;
        }
        if (popThem)
        {
            dropEntries(n);
            if (depthValid)
                depth -= n * ctx.ptr;
        }
        return args;
    }

    void setBuffer(const Value& v, const string& text)
    {
        if (v.kind == V_LOCAL)
            buffers[v.num] = text;
    }

    void setSlot(const Value& v, const Value& value)
    {
        if (v.kind == V_LOCAL)
            slots[v.num] = value;
    }

    // Что API записывает в выходные буферы и возвращает — для следующих вызовов
    void applyOutputs(CallSite& cs)
    {
        const string& n = cs.target;
        const vector<Value>& a = cs.args;
        Value ret;
        if (apiMatches(n, "GetSystemDirectory") && !a.empty())
            setBuffer(a[0], "%SystemRoot%\\system32");
        else if (apiMatches(n, "GetWindowsDirectory") && !a.empty())
            setBuffer(a[0], "%SystemRoot%");
        else if (apiMatches(n, "GetTempPath") && a.size() > 1)
            setBuffer(a[1], "%TEMP%\\");
        else if (apiMatches(n, "GetTempFileName") && a.size() > 3)
        {
            string dir = textOf(a[0]);
            if (!dir.empty() && dir.back() != '\\')
                dir += "\\";
            setBuffer(a[3], dir + (a[1].kind == V_STRING ? a[1].text : "") + "XXXX.tmp");
        }
        else if (apiMatches(n, "GetModuleFileName") && a.size() > 1)
            setBuffer(a[1], "<путь к себе>");
        else if (apiMatches(n, "GetCommandLine"))
            ret = symbol("<командная строка>");
        else if (apiMatches(n, "RegQueryValueEx") && a.size() > 4)
            setBuffer(a[4], "<реестр: " + textOf(a[1]) + ">");
        else if ((apiMatches(n, "RegCreateKey") || apiMatches(n, "RegOpenKey")) && a.size() > 2)
            setSlot(a[2], symbol("hKey(" + keyPath(a[0], a[1]) + ")"));
        else if (apiMatches(n, "RegCreateKeyEx") && a.size() > 7)
            setSlot(a[7], symbol("hKey(" + keyPath(a[0], a[1]) + ")"));
        else if (apiMatches(n, "RegOpenKeyEx") && a.size() > 4)
            setSlot(a[4], symbol("hKey(" + keyPath(a[0], a[1]) + ")"));
        else if ((apiMatches(n, "FindFirstFile") || apiMatches(n, "FindNextFile")) && a.size() > 1)
        {
            if (a[1].kind == V_LOCAL)
                buffers[a[1].num + 0x2C] = "<найденный файл>";   // WIN32_FIND_DATA.cFileName
            if (apiMatches(n, "FindFirstFile"))
                ret = symbol("hFind");
        }
        else if (apiMatches(n, "CreateFile") && !a.empty())
            ret = symbol("hFile(" + textOf(a[0]) + ")");
        else if (apiMatches(n, "CreateMutex"))
            ret = symbol("hMutex");
        else if (apiMatches(n, "GetLogicalDriveStrings") && a.size() > 1)
            setBuffer(a[1], "<список дисков>");
        clobberVolatile();
        regs[R_AX] = ret;
    }

    string keyPath(const Value& hkey, const Value& subkey)
    {
        string hive = hkey.kind == V_CONST ? hkeyShort((uint64_t)hkey.num) : "";
        if (hive.empty())
            hive = hkey.kind == V_SYMBOL ? hkey.text : "?";
        return hive + "\\" + textOf(subkey);
    }

    void apiCall(const string& name, size_t idx)
    {
        CallSite cs = { code[idx].addr, name, true, 0, {}, false };
        const ApiProto* p = findProto(name);
        bool cdeclApi = ctx.cdeclApis.count(name) || (p && p->cdeclConv);
        if (is64())
        {
            if (p)
            {
                const int order[4] = { R_CX, R_DX, 8, 9 };
                for (size_t i = 0; i < p->args.size(); i++)
                {
                    Value v;
                    if (i < 4)
                        v = regs[order[i]];
                    else if (depthValid)
                    {
                        auto s = slots.find(0x20 + 8 * (int64_t)(i - 4) - depth);
                        if (s != slots.end())
                            v = s->second;
                    }
                    cs.args.push_back(resolve(v));
                }
                cs.argsKnown = true;
            }
        }
        else if (cdeclApi)
        {
            int n = cleanupArgc(idx);
            if (n >= 0)
            {
                cs.args = takeArgs(n, false);
                cs.argsKnown = true;
            }
        }
        else if (p)
        {
            cs.args = takeArgs((int)p->args.size(), true);
            cs.argsKnown = true;
        }
        else
        {
            // stdcall с неизвестным числом аргументов: глубина стека дальше неизвестна
            stack.clear();
            consumed.clear();
            depthValid = false;
        }
        // буфер, переданный не как строка, — выходной параметр: прежнее содержимое ячейки устарело
        for (size_t i = 0; i < cs.args.size(); i++)
            if (cs.args[i].kind == V_LOCAL && argFormat(cs, i) != A_STR)
            {
                cs.args[i].content.clear();
                buffers.erase(cs.args[i].num);
                slots.erase(cs.args[i].num);
            }
        applyOutputs(cs);
        f.calls.push_back(cs);
    }

    // Подстановка аргументов в формат sprintf: «%s\%s» -> «<arg_0>\<найденный файл>»
    string formatPrintf(const vector<Value>& args)
    {
        const string& fmt = args[1].text;
        string out;
        size_t next = 2;
        for (size_t i = 0; i < fmt.length(); i++)
        {
            if (fmt[i] == '%' && i + 1 < fmt.length())
            {
                char c = fmt[++i];
                if (c == '%')
                    out += '%';
                else
                {
                    while (i < fmt.length() && strchr("0123456789.-+l", fmt[i]))
                        i++;
                    out += next < args.size() ? textOf(args[next++]) : "?";
                }
            }
            else
                out += fmt[i];
        }
        return out;
    }

    void internalCall(uint64_t target, size_t idx)
    {
        CallSite cs = { code[idx].addr, "sub_" + hexPlain(target), false, target, {}, false };
        if (!is64())
        {
            auto rp = ctx.retPop.find(target);
            if (rp != ctx.retPop.end() && rp->second > 0)
            {
                cs.args = takeArgs((int)(rp->second / ctx.ptr), true);
                cs.argsKnown = true;
            }
            else
            {
                int n = cleanupArgc(idx);
                if (n >= 0)
                {
                    cs.args = takeArgs(n, false);
                    cs.argsKnown = true;
                }
            }
        }
        // sprintf-подобная функция: (буфер, "формат", ...)
        if (cs.args.size() >= 2 && cs.args[0].kind == V_LOCAL && cs.args[1].kind == V_STRING
            && cs.args[1].text.find('%') != NPOS)
            buffers[cs.args[0].num] = formatPrintf(cs.args);
        clobberVolatile();
        // fopen-подобная функция: (путь, "w") — результат запоминаем как FILE* этого файла
        static const set<string> modes = { "r", "w", "a", "rb", "wb", "ab", "r+", "w+", "a+", "wt", "rt" };
        if (cs.args.size() == 2 && cs.args[1].kind == V_STRING && modes.count(cs.args[1].text)
            && (cs.args[0].kind == V_STRING || cs.args[0].kind == V_LOCAL))
            regs[R_AX] = symbol("FILE*(" + textOf(cs.args[0]) + ")");
        f.calls.push_back(cs);
    }

    void unknownCall()
    {
        clobberVolatile();
    }

    // rep movs: копирование строки (strcpy) или дописывание в конец (strcat)
    void copyString()
    {
        const Value& dst = regs[R_DI];
        const Value& src = regs[R_SI];
        if (dst.kind == V_LOCAL && src.kind != V_UNKNOWN && src.kind != V_CONST)
        {
            string text = src.kind == V_LOCAL ? bufferText(src.num) : textOf(src);
            if (src.kind == V_LOCAL && text.empty())
                text = "<" + src.text + ">";
            if (dst.atEnd)
                buffers[dst.num] += text;
            else
                buffers[dst.num] = text;
        }
    }

    void setFrame()
    {
        hasFrame = depthValid;
        frameDepth = depth;
        unknown(R_BP);
    }

    void invalidateMem(const Insn& in)
    {
        int64_t pos;
        if (slotOf(in, pos))
            slots[pos] = Value();
    }

    // Возвращает true, если после инструкции нет перехода на следующую (ret, jmp)
    bool step(size_t idx)
    {
        const Insn& in = code[idx];
        const uint8_t op = in.op;

        if (in.twoByte)
        {
            if (op >= 0x80 && op <= 0x8F)
                branchTo(in.target, in.addr);
            else if (op == 0xB6 || op == 0xB7 || op == 0xBE || op == 0xBF || op == 0xAF || op == 0xBC || op == 0xBD
                     || (op >= 0x40 && op <= 0x4F) || op == 0x02 || op == 0x03 || op == 0xC5 || op == 0xD7
                     || op == 0x50 || op == 0x2C || op == 0x2D)
                unknown(in.reg);
            else if (op >= 0x90 && op <= 0x9F)
                in.mod == 3 ? unknown8(in.rm) : invalidateMem(in);
            else if (op == 0x31)
            {
                unknown(R_AX);
                unknown(R_DX);
            }
            else if (op == 0xA2)
                for (int r = 0; r < 4; r++)
                    unknown(r);
            else if (op >= 0xC8 && op <= 0xCF)
                unknown((op & 7) | (in.rexB << 3));
            else if (op == 0xA3 || op == 0xAB || op == 0xB3 || op == 0xBB || op == 0xBA || op == 0xA4 || op == 0xA5
                     || op == 0xAC || op == 0xAD || op == 0x7E)
            {
                if (in.mod == 3)
                    unknown(in.rm);
                else
                    invalidateMem(in);
            }
            else if (op == 0xB0 || op == 0xB1 || op == 0xC0 || op == 0xC1)
            {
                unknown(R_AX);
                unknown(in.reg);
                if (in.mod == 3)
                    unknown(in.rm);
            }
            else if (op == 0x05)
            {
                unknown(R_AX);
                unknown(R_CX);
                unknown(11);
            }
            return false;
        }

        // арифметика и логика r/m, r (00–3F)
        if (op < 0x40 && in.hasModrm)
        {
            bool regIsDest = (op & 2) != 0;
            bool byteOp = (op & 1) == 0;
            int kind = op & 0xF8;
            if (kind == 0x38)
                return false;                         // cmp
            if (in.mod == 3)
            {
                int dst = regIsDest ? in.reg : in.rm;
                int src = regIsDest ? in.rm : in.reg;
                if ((kind == 0x30 || kind == 0x28) && dst == src && !byteOp)
                {
                    regs[dst] = constValue(0);       // xor r, r / sub r, r
                    regs[dst].kind = V_CONST;
                    return false;
                }
                if (kind == 0x28 && dst == R_DI && src == R_CX && regs[R_DI].atEnd)
                {
                    regs[R_DI].atEnd = false;        // sub edi, ecx после repne scasb — начало строки
                    return false;
                }
                if (dst == R_SP)
                {
                    depthValid = false;
                    return false;
                }
                byteOp ? unknown8(dst) : unknown(dst);
            }
            else if (regIsDest)
                byteOp ? unknown8(in.reg) : unknown(in.reg);
            else
                invalidateMem(in);
            return false;
        }

        if (op >= 0x50 && op <= 0x57)
        {
            push(regs[(op & 7) | (in.rexB << 3)]);
            return false;
        }
        if (op >= 0x58 && op <= 0x5F)
        {
            int r = (op & 7) | (in.rexB << 3);
            Value v = pop();
            if (r == R_BP && hasFrame && depthValid && depth < frameDepth)
                hasFrame = false;
            regs[r] = v;
            return false;
        }
        if (!is64() && op >= 0x40 && op <= 0x4F)
        {
            int r = op & 7;
            if (!(op == 0x4F && regs[R_DI].atEnd))   // dec edi после repne scasb: указатель на конец строки
                unknown(r);
            return false;
        }
        if ((op >= 0x70 && op <= 0x7F) || (op >= 0xE0 && op <= 0xE3))
        {
            branchTo(in.target, in.addr);
            return false;
        }

        switch (op)
        {
        case 0x60:
            for (int i = 0; i < 8; i++)
                push(Value());
            return false;
        case 0x61:
            for (int i = 0; i < 8; i++)
                pop();
            for (int r = 0; r < 8; r++)
                if (r != R_SP)
                    unknown(r);
            return false;
        case 0x63: case 0x69: case 0x6B:
            unknown(in.reg);
            return false;
        case 0x68:
            push(constValue(is64() ? (uint64_t)in.imm : (uint32_t)in.uimm));
            return false;
        case 0x6A:
            push(constValue(is64() ? (uint64_t)in.imm : (uint32_t)(int32_t)in.imm));
            return false;
        case 0x80: case 0x81: case 0x82: case 0x83:
        {
            int k = in.regRaw;
            if (k == 7)
                return false;
            if (in.mod == 3)
            {
                if (in.rm == R_SP && op != 0x80 && op != 0x82)
                {
                    if (k == 0)
                    {
                        if (depthValid)
                            depth -= in.imm;
                        dropEntries(in.imm / ctx.ptr);
                    }
                    else if (k == 5)
                    {
                        if (depthValid)
                            depth += in.imm;
                    }
                    else
                        depthValid = false;
                    return false;
                }
                (op == 0x80 || op == 0x82) ? unknown8(in.rm) : unknown(in.rm);
            }
            else
                invalidateMem(in);
            return false;
        }
        case 0x86: case 0x87:
            if (in.mod == 3 && op == 0x87)
                swap(regs[in.reg], regs[in.rm]);
            else
            {
                unknown8(in.reg);
                if (in.mod == 3)
                    unknown8(in.rm);
                else
                    invalidateMem(in);
            }
            return false;
        case 0x88:
            if (in.mod == 3)
                unknown8(in.rm);
            else
            {
                // замена буквы диска в строке пути: mov [esp+X], bl при «c:\...» в ячейке
                int64_t pos;
                auto slot = slotOf(in, pos) ? slots.find(pos) : slots.end();
                if (slot != slots.end() && slot->second.kind == V_STRING && slot->second.text.length() >= 2
                    && slot->second.text[1] == ':')
                    slot->second.text = "<диск>" + slot->second.text.substr(1);
                else
                    invalidateMem(in);
            }
            return false;
        case 0x89:
            if (in.mod == 3)
            {
                if (in.rm == R_BP && in.reg == R_SP)
                    setFrame();
                else if (in.rm == R_SP)
                {
                    if (in.reg == R_BP && hasFrame)
                    {
                        depth = frameDepth;
                        depthValid = true;
                    }
                    else
                        depthValid = false;
                }
                else
                    regs[in.rm] = in.opsize16 ? Value() : regs[in.reg];
            }
            else
                storeMem(in, in.opsize16 && regs[in.reg].kind != V_STRING ? Value() : regs[in.reg]);
            return false;
        case 0x8A:
            unknown8(in.reg);
            return false;
        case 0x8B:
            if (in.mod == 3)
            {
                if (in.reg == R_BP && in.rm == R_SP)
                    setFrame();
                else if (in.reg == R_SP)
                {
                    if (in.rm == R_BP && hasFrame)
                    {
                        depth = frameDepth;
                        depthValid = true;
                    }
                    else
                        depthValid = false;
                }
                else
                    regs[in.reg] = in.opsize16 ? Value() : regs[in.rm];
            }
            else
            {
                Value v = loadMem(in);
                regs[in.reg] = in.opsize16 && v.kind != V_STRING ? Value() : v;
            }
            return false;
        case 0x8D:
            if (in.reg == R_SP)
            {
                if (in.base == R_BP && hasFrame && in.index < 0)
                {
                    depth = frameDepth - in.disp;
                    depthValid = true;
                }
                else
                    depthValid = false;
            }
            else
                regs[in.reg] = addressOf(in);
            return false;
        case 0x8F:
        {
            Value v = pop();
            if (in.mod == 3)
                regs[in.rm] = v;
            else
                storeMem(in, v);
            return false;
        }
        case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
            swap(regs[R_AX], regs[(op & 7) | (in.rexB << 3)]);
            return false;
        case 0x98:
            unknown(R_AX);
            return false;
        case 0x99:
            unknown(R_DX);
            return false;
        case 0x9C:
            push(Value());
            return false;
        case 0x9D:
            pop();
            return false;
        case 0xA0:
            unknown8(R_AX);
            return false;
        case 0xA1:
        {
            Value v = loadMem(in);      // absolute: IAT или кусок строки
            regs[R_AX] = in.opsize16 && v.kind != V_STRING ? Value() : v;
            return false;
        }
        case 0xA4: case 0xA5:
            if (in.rep)
            {
                copyString();
                unknown(R_CX);
            }
            unknown(R_SI);
            unknown(R_DI);
            return false;
        case 0xA6: case 0xA7:
            unknown(R_SI);
            unknown(R_DI);
            if (in.rep)
                unknown(R_CX);
            return false;
        case 0xAA: case 0xAB:
            unknown(R_DI);
            if (in.rep)
                unknown(R_CX);
            return false;
        case 0xAC: case 0xAD:
            unknown(R_AX);
            unknown(R_SI);
            return false;
        case 0xAE: case 0xAF:
            if (in.rep && regs[R_DI].kind != V_UNKNOWN && regs[R_DI].kind != V_CONST)
                regs[R_DI].atEnd = true;            // repne scasb — поиск конца строки
            else
                unknown(R_DI);
            if (in.rep)
                unknown(R_CX);
            return false;
        case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4: case 0xB5: case 0xB6: case 0xB7:
            unknown8((op & 7) | (in.rexB << 3));
            return false;
        case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            regs[(op & 7) | (in.rexB << 3)] = in.opsize16 ? Value() : constValue(in.uimm);
            return false;
        case 0xC0: case 0xC1: case 0xD0: case 0xD1: case 0xD2: case 0xD3:
            if (in.mod == 3)
            {
                if (in.rm == R_SP)
                    depthValid = false;
                (op == 0xC0 || op == 0xD0 || op == 0xD2) ? unknown8(in.rm) : unknown(in.rm);
            }
            else
                invalidateMem(in);
            return false;
        case 0xC2: case 0xC3: case 0xCC: case 0xF4:
            return true;
        case 0xC6:
            in.mod == 3 ? unknown8(in.rm) : invalidateMem(in);
            return false;
        case 0xC7:
        {
            Value v = in.opsize16 ? Value() : constValue(in.rexW ? (uint64_t)in.imm : (uint32_t)in.uimm);
            if (in.mod == 3)
                regs[in.rm] = v;
            else
                storeMem(in, v);
            return false;
        }
        case 0xC8:
            depthValid = false;
            return false;
        case 0xC9:
            if (hasFrame)
            {
                depth = frameDepth;
                depthValid = true;
            }
            else
                depthValid = false;
            regs[R_BP] = pop();
            hasFrame = false;
            return false;
        case 0xE8:
        {
            auto t = ctx.thunks.find(in.target);
            if (t != ctx.thunks.end())
                apiCall(t->second, idx);
            else
                internalCall(in.target, idx);
            return false;
        }
        case 0xE9: case 0xEB:
            branchTo(in.target, in.addr);
            return true;
        case 0xF6: case 0xF7:
        {
            int k = in.regRaw;
            if (k == 2 || k == 3)
                in.mod == 3 ? unknown(in.rm) : invalidateMem(in);
            else if (k >= 4)
            {
                unknown(R_AX);
                if (op == 0xF7)
                    unknown(R_DX);
            }
            return false;
        }
        case 0xFE: case 0xFF:
        {
            int k = in.regRaw;
            if (k == 0 || k == 1)
            {
                if (in.mod == 3)
                    unknown(in.rm);
                else
                    invalidateMem(in);
            }
            else if (op == 0xFF && (k == 2 || k == 3))
            {
                Value v = in.mod == 3 ? regs[in.rm] : loadMem(in);
                if (v.kind == V_API)
                    apiCall(v.text, idx);
                else
                    unknownCall();
            }
            else if (op == 0xFF && (k == 4 || k == 5))
                return true;
            else if (op == 0xFF && k == 6)
                push(in.mod == 3 ? regs[in.rm] : loadMem(in));
            return false;
        }
        default:
            return false;
        }
    }
};

// ================================================================ поиск ссылок и функций

// Похоже на начало функции (типичные прологи MSVC)
bool looksLikePrologue(const vector<unsigned char>& b, size_t o, bool is64)
{
    if (o + 4 > b.size())
        return false;
    unsigned char c0 = b[o], c1 = b[o + 1], c2 = b[o + 2];
    if (!is64)
        return (c0 == 0x55 && c1 == 0x8B && c2 == 0xEC) || (c0 == 0x83 && c1 == 0xEC) || (c0 == 0x81 && c1 == 0xEC)
            || (c0 == 0x8B && c1 == 0xFF) || (c0 == 0x6A && c2 == 0x68);
    return (c0 == 0x48 && (c1 == 0x83 || c1 == 0x81) && c2 == 0xEC) || (c0 == 0x48 && c1 == 0x89 && c2 == 0x5C)
        || (c0 == 0x40 && c1 >= 0x53 && c1 <= 0x57) || (c0 == 0x4C && c1 == 0x8B && c2 == 0xDC);
}

CodeMap analyzeCode(const vector<unsigned char>& b, const PeInfo& pe, const vector<FoundString>& strs)
{
    CodeMap cm;
    if (!pe.valid)
    {
        cm.note = "файл не является PE — анализ машинного кода не выполнялся";
        return cm;
    }
    if (pe.machine != 0x14C && pe.machine != 0x8664)
    {
        cm.note = "архитектура " + machineName(pe.machine) + " не поддерживается анализатором кода";
        return cm;
    }

    map<uint64_t, string> iat;
    set<string> cdeclApis;
    for (const ImportDll& d : pe.imports)
    {
        string dll = toLower(d.name);
        bool crt = dll.rfind("msvcr", 0) == 0 || dll.rfind("ucrtbase", 0) == 0 || dll.rfind("api-ms-win-crt", 0) == 0;
        for (const ImportFunc& f : d.funcs)
        {
            iat[f.iatVa] = f.name;
            if (crt)
                cdeclApis.insert(f.name);
        }
    }

    // строки в невыполняемых секциях
    StringTable table;
    for (const FoundString& s : strs)
    {
        uint64_t va = offsetToVa(pe, s.offset);
        const Section* sec = va ? sectionOfVa(pe, va) : nullptr;
        if (!sec || isExecutable(*sec))
            continue;
        // по одному адресу ASCII «U» и UTF-16 «UBR» — берём более длинное прочтение
        auto old = table.byVa.find(va);
        if (old == table.byVa.end() || old->second.first.length() < s.text.length())
            table.byVa[va] = { s.text, s.wide };
    }

    struct Call { uint64_t from, to; };
    vector<CodeRef> raw;
    vector<Call> calls;
    vector<uint64_t> letterLoops;
    map<uint64_t, string> thunks;

    auto addAbsolute = [&](uint64_t at, uint64_t target, bool allowApi)
    {
        auto f = iat.find(target);
        if (allowApi && f != iat.end())
        {
            raw.push_back({ at, f->second, true });
            return;
        }
        string s = table.at(target);
        if (s.length() >= 2)
            raw.push_back({ at, s, false });
    };

    // 1. Быстрый проход по байтам: ссылки на IAT и строки, вызовы, переходники
    for (const Section& s : pe.sections)
    {
        if (!isExecutable(s))
            continue;
        size_t begin = s.rawPtr;
        size_t end = min(b.size(), (size_t)s.rawPtr + (s.vsize ? min(s.vsize, s.rawSize) : s.rawSize));
        uint64_t base = pe.imageBase + s.va;
        for (size_t i = begin; i + 7 <= end; i++)
        {
            uint64_t va = base + (i - begin);
            unsigned char b0 = b[i], b1 = b[i + 1], b2 = b[i + 2];

            if (b0 == 0xFF && (b1 == 0x15 || b1 == 0x25))
            {
                uint64_t target = pe.is64 ? va + 6 + (int32_t)rd32(b, i + 2) : rd32(b, i + 2);
                auto f = iat.find(target);
                if (f != iat.end())
                {
                    if (b1 == 0x15)
                        raw.push_back({ va, f->second, true });
                    else
                        thunks[va] = f->second;
                }
            }
            if (b0 == 0xE8)
            {
                uint64_t target = va + 5 + (int32_t)rd32(b, i + 1);
                const Section* ts = sectionOfVa(pe, target);
                if (ts && isExecutable(*ts))
                    calls.push_back({ va, target });
            }

            if (!pe.is64)
            {
                if ((b0 == 0x8B || b0 == 0x8A) && (b1 & 0xC7) == 0x05)        // mov r, [imm32] (66h — 16 бит)
                    addAbsolute(i > begin && b[i - 1] == 0x66 ? va - 1 : va, rd32(b, i + 2), b0 == 0x8B);
                else if (b0 == 0xA1)                                           // mov eax, [imm32]
                    addAbsolute(va, rd32(b, i + 1), true);
                else if (b0 == 0x68 || (b0 >= 0xB8 && b0 <= 0xBF))             // push imm32 / mov r, imm32
                    addAbsolute(va, rd32(b, i + 1), false);
            }
            else if ((b0 & 0xF0) == 0x40 && (b1 == 0x8D || b1 == 0x8B) && (b2 & 0xC7) == 0x05)
                addAbsolute(va, va + 7 + (int32_t)rd32(b, i + 3), b1 == 0x8B);  // lea/mov r, [rip+rel32]

            if ((b0 == 0x80 && (b1 & 0xF8) == 0xF8 && (b2 == 0x5A || b2 == 0x7A))
                || (b0 == 0x3C && (b1 == 0x5A || b1 == 0x7A)))
                letterLoops.push_back(va);
        }
    }

    // 2. Границы функций: точка входа и цели call, похожие на начало функции
    map<uint64_t, int> callCount;
    for (const Call& c : calls)
        callCount[c.to]++;
    set<uint64_t> starts;
    starts.insert(pe.imageBase + pe.entryRva);
    for (const auto& item : callCount)
    {
        uint64_t target = item.first;
        if (thunks.count(target))
            continue;
        size_t off = vaToOffset(pe, target);
        const Section* sec = sectionOfVa(pe, target);
        if (off == NPOS || !sec)
            continue;
        bool sectionStart = target == pe.imageBase + sec->va;
        unsigned char prev = off > 0 ? b[off - 1] : 0x90;
        bool padded = sectionStart || prev == 0x90 || prev == 0xCC || prev == 0xC3 || (off >= 3 && b[off - 3] == 0xC2);
        if (padded || (looksLikePrologue(b, off, pe.is64) && item.second >= 2))
            starts.insert(target);
    }

    vector<uint64_t> sorted(starts.begin(), starts.end());
    map<uint64_t, FunctionInfo> byStart;
    auto functionOf = [&](uint64_t va) -> FunctionInfo*
    {
        auto it = upper_bound(sorted.begin(), sorted.end(), va);
        if (it == sorted.begin())
            return nullptr;
        uint64_t start = *(it - 1);
        FunctionInfo& f = byStart[start];
        f.start = start;
        return &f;
    };

    for (const CodeRef& r : raw)
        if (FunctionInfo* f = functionOf(r.addr))
            f->refs.push_back(r);
    for (const Call& c : calls)
    {
        FunctionInfo* f = functionOf(c.from);
        if (!f)
            continue;
        auto t = thunks.find(c.to);
        if (t != thunks.end())
            f->refs.push_back({ c.from, t->second, true });
        else if (starts.count(c.to))
        {
            f->callees.insert(c.to);
            if (c.to == f->start)
                f->recursive = true;
        }
    }
    for (uint64_t va : letterLoops)
        if (FunctionInfo* f = functionOf(va))
            f->letterLoop = true;

    // 3. Декодирование инструкций каждой функции
    map<uint64_t, vector<Insn>> decoded;
    map<uint64_t, int> retPop;
    for (size_t i = 0; i < sorted.size(); i++)
    {
        uint64_t start = sorted[i];
        const Section* sec = sectionOfVa(pe, start);
        size_t off = vaToOffset(pe, start);
        if (!sec || off == NPOS)
            continue;
        uint64_t limit = min<uint64_t>(i + 1 < sorted.size() ? sorted[i + 1] : UINT64_MAX,
                                       pe.imageBase + sec->va + min(sec->vsize ? sec->vsize : sec->rawSize, sec->rawSize));
        size_t endOff = min(b.size(), (size_t)sec->rawPtr + sec->rawSize);
        vector<Insn>& list = decoded[start];
        uint64_t va = start;
        while (va < limit && off < endOff)
        {
            Insn in;
            if (!decodeInsn(b, off, endOff, va, pe.is64, in))
                break;
            if (!in.twoByte && in.op == 0xC2 && !retPop.count(start))
                retPop[start] = (int)in.uimm;
            list.push_back(in);
            off += in.len;
            va += in.len;
        }
    }

    // 4. Восстановление аргументов вызовов в функциях, где есть обращения к API или строкам
    SimContext ctx = { pe, iat, thunks, table, retPop, cdeclApis, pe.is64 ? 8 : 4 };
    for (auto& item : byStart)
    {
        FunctionInfo& f = item.second;
        auto d = decoded.find(f.start);
        if (d != decoded.end() && !d->second.empty())
        {
            FunctionSimulator sim(ctx, f, d->second);
            sim.run();
            f.decoded = true;
            cm.decodedFunctions++;
            for (const CallSite& c : f.calls)
                if (c.argsKnown)
                    cm.resolvedCalls++;
        }
        sort(f.refs.begin(), f.refs.end(), [](const CodeRef& a, const CodeRef& c) { return a.addr < c.addr; });
        for (const CodeRef& r : f.refs)
            (r.isApi ? cm.apiRefs : cm.stringRefs)++;
        cm.functions.push_back(f);
    }
    cm.done = true;
    if (pe.isDotNet)
        cm.note = "сборка .NET: логика программы записана в IL-коде, проанализирован только машинный код загрузчика";
    return cm;
}

// ================================================================ цепочки поведения

bool hasApi(const FunctionInfo& f, const vector<string>& stems)
{
    for (const CodeRef& r : f.refs)
        if (r.isApi)
            for (const string& stem : stems)
                if (apiMatches(r.text, stem))
                    return true;
    for (const CallSite& c : f.calls)
        if (c.isApi)
            for (const string& stem : stems)
                if (apiMatches(c.target, stem))
                    return true;
    return false;
}

vector<const CallSite*> callsTo(const FunctionInfo& f, const vector<string>& stems)
{
    vector<const CallSite*> found;
    for (const CallSite& c : f.calls)
        if (c.isApi)
            for (const string& stem : stems)
                if (apiMatches(c.target, stem))
                {
                    found.push_back(&c);
                    break;
                }
    return found;
}

string callLine(const CallSite& c)
{
    string s = hexVa(c.addr) + "  " + formatCall(c);
    string note = callNote(c);
    if (!note.empty())
        s += "  — " + note;
    return s;
}

// Доказательства: восстановленные вызовы, а если код не разобран — адреса обращений к API
vector<string> evidenceFor(const FunctionInfo& f, const vector<string>& stems)
{
    vector<string> found;
    for (const CallSite* c : callsTo(f, stems))
        found.push_back(callLine(*c));
    if (!found.empty())
        return found;
    for (const CodeRef& r : f.refs)
        if (r.isApi)
            for (const string& stem : stems)
                if (apiMatches(r.text, stem))
                {
                    addUnique(found, r.text + " (" + hexVa(r.addr) + ")");
                    break;
                }
    return found;
}

vector<string> stringsOf(const FunctionInfo& f)
{
    vector<string> found;
    for (const CodeRef& r : f.refs)
        if (!r.isApi)
            addUnique(found, r.text);
    return found;
}

string findString(const FunctionInfo& f, const string& lowerSub)
{
    for (const CodeRef& r : f.refs)
        if (!r.isApi && containsNoCase(r.text, lowerSub))
            return r.text;
    for (const CallSite& c : f.calls)
        for (const Value& v : c.args)
        {
            string t = v.kind == V_LOCAL ? v.content : v.kind == V_STRING ? v.text : "";
            if (containsNoCase(t, lowerSub))
                return t;
        }
    return "";
}

bool isRootFilePath(const string& s)
{
    static const regex root("^[A-Za-z]:\\\\[^\\\\ ]+$");
    return regex_match(s, root);
}

bool isDriveString(const string& s)
{
    return s.length() >= 2 && isalpha((unsigned char)s[0]) && s[1] == ':';
}

bool sameBuffer(const Value& a, const Value& b)
{
    return a.kind == V_LOCAL && b.kind == V_LOCAL && a.num == b.num;
}

const vector<string> FIND_FIRST = { "FindFirstFile", "FindFirstFileEx" };
const vector<string> FIND_NEXT = { "FindNextFile" };
const vector<string> DELETES = { "DeleteFile", "RemoveDirectory", "SHFileOperation" };
const vector<string> OVERWRITES = { "CopyFile", "CopyFileEx", "WriteFile" };
const vector<string> MOVES = { "MoveFile", "MoveFileEx", "ReplaceFile" };
const vector<string> EXECS = { "WinExec", "ShellExecute", "ShellExecuteEx", "CreateProcess" };
const vector<string> REG_OPEN = { "RegCreateKey", "RegCreateKeyEx", "RegOpenKey", "RegOpenKeyEx" };

Behavior makeBehavior(const string& code, const string& title, const string& attack, const string& attackName,
                      Severity sev, const FunctionInfo& f, const string& recommendation)
{
    return { code, title, attack, attackName, sev, f.start, {}, "", recommendation, {} };
}

// Тексты, которые программа пишет в файлы: FILE*(путь) из fopen-подобного вызова + строка
map<string, string> writtenFiles(const CodeMap& cm)
{
    map<string, string> files;
    for (const FunctionInfo& f : cm.functions)
        for (const CallSite& c : f.calls)
        {
            string path, text;
            for (const Value& v : c.args)
                if (v.kind == V_SYMBOL && v.text.rfind("FILE*(", 0) == 0)
                    path = v.text.substr(6, v.text.length() - 7);
                else if (v.kind == V_STRING && v.text.length() > 3)
                    text = v.text;
            if (!path.empty() && !text.empty())
                files[path] = text;
        }
    return files;
}

vector<Behavior> detectBehaviors(const CodeMap& cm)
{
    vector<Behavior> list;
    map<uint64_t, set<string>> roles;
    const map<string, string> allWritten = writtenFiles(cm);
    map<string, string> written = allWritten;     // из него вычёркиваем уже показанные файлы

    for (const FunctionInfo& f : cm.functions)
    {
        // файл, в который записывается текст (fopen + fprintf)
        for (const CallSite& c : f.calls)
            for (const Value& v : c.args)
                if (v.kind == V_SYMBOL && v.text.rfind("FILE*(", 0) == 0)
                {
                    string path = v.text.substr(6, v.text.length() - 7);
                    auto w = written.find(path);
                    if (w == written.end() || w->second.empty())
                        continue;
                    Behavior b = makeBehavior("DROPFILE", "Создание файла с текстом-посланием", "T1491.001",
                                              "Defacement: Internal Defacement", MEDIUM, f,
                                              "Искать файл и текст послания на узлах как признак заражения");
                    for (const CallSite& o : f.calls)
                        for (const Value& a : o.args)
                            if ((a.kind == V_STRING && a.text == path) || (a.kind == V_SYMBOL && a.text == v.text))
                            {
                                addUnique(b.evidence, callLine(o));
                                break;
                            }
                    b.details = "в файл " + path + " записывается текст «" + w->second + "»";
                    if (isRootFilePath(path))
                        b.iocs.push_back("файл \"" + path + "\" с текстом «" + w->second + "»");
                    list.push_back(b);
                    written[path].clear();          // одна находка на файл
                }

        bool enumerate = hasApi(f, FIND_FIRST) && hasApi(f, FIND_NEXT);
        bool deletes = hasApi(f, DELETES);
        bool overwrites = hasApi(f, OVERWRITES);
        bool attributes = hasApi(f, { "SetFileAttributes" });
        vector<string> strs = stringsOf(f);

        if (enumerate)
        {
            Behavior b = makeBehavior("ENUM", f.recursive ? "Рекурсивный обход дерева каталогов" : "Обход каталога",
                                      "T1083", "File and Directory Discovery", LOW, f,
                                      "Отслеживать массовый перебор файлов одним процессом (EDR, аудит доступа к объектам ФС)");
            b.evidence = evidenceFor(f, { "FindFirstFile", "FindFirstFileEx", "FindNextFile" });
            b.details = f.recursive ? "функция вызывает сама себя для каждого найденного подкаталога — обходится всё дерево"
                                    : "перебираются файлы одного каталога";
            list.push_back(b);
        }

        if (enumerate && deletes)
        {
            Behavior b = makeBehavior("DESTROY", "Массовое уничтожение файлов", "T1485", "Data Destruction", CRITICAL, f,
                                      "Изолировать узел, отключить сетевые и съёмные диски; восстановить данные из резервной копии; заблокировать файл по SHA-256");
            b.evidence = evidenceFor(f, { "FindFirstFile", "SetFileAttributes", "CopyFile", "WriteFile", "DeleteFile",
                                          "RemoveDirectory", "FindNextFile" });
            string details = "каждый найденный файл удаляется (DeleteFile)";

            vector<const CallSite*> copies = callsTo(f, { "CopyFile", "CopyFileEx" });
            vector<const CallSite*> dels = callsTo(f, { "DeleteFile" });
            if (!copies.empty() && copies[0]->argsKnown && copies[0]->args.size() >= 2)
            {
                const CallSite& cp = *copies[0];
                if (cp.args[0].kind == V_STRING)
                {
                    details += "; перед удалением содержимое файла заменяется копией файла-шаблона " + cp.args[0].text
                             + " (CopyFile поверх найденного файла" + (isConst(cp, 2, 0) ? ", bFailIfExists = FALSE)" : ")");
                    auto w = allWritten.find(cp.args[0].text);
                    if (w != allWritten.end())
                        details += ", в котором записано «" + w->second + "»";
                }
                if (!dels.empty() && dels[0]->argsKnown && !dels[0]->args.empty() && sameBuffer(cp.args[1], dels[0]->args[0]))
                    details += "; затем удаляется тот же файл (" + cp.args[1].text + ")";
            }
            else if (overwrites)
            {
                details += "; перед удалением содержимое файла перезаписывается";
                for (const string& s : strs)
                    if (isRootFilePath(s) && hasApi(f, { "CopyFile", "CopyFileEx" }))
                    {
                        details += " копией файла-шаблона " + s;
                        b.iocs.push_back("файл-шаблон \"" + s + "\"");
                        break;
                    }
            }
            if (attributes)
                details += "; атрибуты «только чтение»/«системный» предварительно снимаются";
            if (f.recursive)
                details += "; обход рекурсивный — затрагиваются все вложенные каталоги";
            b.details = details;
            list.push_back(b);
            roles[f.start].insert("DESTROY");
        }
        else if (enumerate && (overwrites || hasApi(f, MOVES)))
        {
            Behavior b = makeBehavior("MANIPULATE", "Массовая перезапись или перемещение файлов", "T1565.001",
                                      "Stored Data Manipulation", HIGH, f,
                                      "Проверить целостность файлов в затронутых каталогах, восстановить из резервной копии");
            b.evidence = evidenceFor(f, { "CopyFile", "WriteFile", "MoveFile", "MoveFileEx" });
            b.details = "для найденных файлов выполняется запись, копирование поверх или перемещение";
            list.push_back(b);
        }

        if (enumerate && attributes)
        {
            // опасно в связке с уничтожением/перезаписью; само по себе — как attrib или del /f
            Severity sev = deletes || overwrites || hasApi(f, MOVES) ? HIGH : MEDIUM;
            Behavior b = makeBehavior("ATTR", "Снятие защитных атрибутов с файлов", "T1222.001",
                                      "File and Directory Permissions Modification", sev, f,
                                      "Включить аудит изменения атрибутов и контролируемый доступ к папкам (Controlled Folder Access)");
            b.evidence = evidenceFor(f, { "SetFileAttributes" });
            b.details = "атрибуты найденных файлов меняются перед записью/удалением — защита атрибутом «только чтение» не помогает";
            list.push_back(b);
        }

        if (hasApi(f, { "GetSystemDirectory", "GetWindowsDirectory" }) && hasApi(f, { "CopyFile", "CopyFileEx", "MoveFile", "MoveFileEx" })
            && hasApi(f, { "GetModuleFileName", "GetCommandLine" }))
        {
            Behavior b = makeBehavior("SELFCOPY", "Самокопирование в системный каталог", "T1036.005",
                                      "Masquerading: Match Legitimate Name or Location", HIGH, f,
                                      "Удалить копию из системного каталога; запретить запись в System32 непривилегированным процессам");
            b.evidence = evidenceFor(f, { "GetCommandLine", "GetModuleFileName", "GetSystemDirectory", "GetWindowsDirectory",
                                          "CopyFile", "MoveFile" });
            for (const CallSite* c : callsTo(f, { "CopyFile", "CopyFileEx", "MoveFile", "MoveFileEx" }))
                if (c->argsKnown && c->args.size() > 1 && c->args[1].kind == V_LOCAL && !c->args[1].content.empty())
                    b.iocs.push_back("копия \"" + c->args[1].content + "\"");
            if (b.iocs.empty())
                for (const string& s : strs)
                    if (containsNoCase(s, ".exe"))
                        b.iocs.push_back("имя копии \"" + s + "\"");
            b.details = "путь к себе берётся из командной строки/модуля, к системному каталогу добавляется имя копии, файл копируется";
            list.push_back(b);
            roles[f.start].insert("SELFCOPY");
        }

        string runKey = findString(f, "currentversion\\run");
        if (!runKey.empty() && hasApi(f, { "RegSetValueEx", "RegSetValue" }))
        {
            Behavior b = makeBehavior("AUTORUN", "Закрепление через ключ автозапуска", "T1547.001",
                                      "Registry Run Keys / Startup Folder", HIGH, f,
                                      "Удалить параметр автозапуска; контролировать ключи Run (Sysmon, событие 13)");
            b.evidence = evidenceFor(f, { "RegCreateKey", "RegCreateKeyEx", "RegOpenKey", "RegOpenKeyEx", "RegSetValueEx" });
            for (const CallSite* c : callsTo(f, REG_OPEN))
                if (c->argsKnown && c->args.size() > 1 && containsNoCase(textOf(c->args[1]), "currentversion\\run"))
                {
                    string hive = c->args[0].kind == V_CONST ? hkeyShort((uint64_t)c->args[0].num) : "";
                    b.iocs.push_back("ключ \"" + (hive.empty() ? "" : hive + "\\") + textOf(c->args[1]) + "\"");
                }
            for (const CallSite* c : callsTo(f, { "RegSetValueEx" }))
                if (c->argsKnown && c->args.size() > 4)
                {
                    if (c->args[1].kind == V_STRING)
                        b.iocs.push_back("параметр автозапуска \"" + c->args[1].text + "\"");
                    if (c->args[4].kind == V_LOCAL && !c->args[4].content.empty())
                        b.iocs.push_back("команда автозапуска \"" + c->args[4].content + "\"");
                }
            if (b.iocs.empty())
                b.iocs.push_back("ключ \"" + runKey + "\"");
            b.details = "программа записывает в ключ Run команду своего запуска при входе в систему";
            list.push_back(b);
            roles[f.start].insert("AUTORUN");
        }

        string shellFolders = findString(f, "shell folders");
        if (!shellFolders.empty() && hasApi(f, { "RegQueryValueEx", "RegQueryValue" }))
        {
            Behavior b = makeBehavior("USERDIRS", "Поиск каталогов с документами пользователя", "T1083",
                                      "File and Directory Discovery", MEDIUM, f,
                                      "Включить контролируемый доступ к папкам для каталогов пользователя");
            b.evidence = evidenceFor(f, { "RegCreateKey", "RegOpenKey", "RegOpenKeyEx", "RegQueryValueEx" });
            b.details = "путь к каталогу пользователя читается из реестра (Explorer\\Shell Folders)";
            for (const CallSite* c : callsTo(f, { "RegQueryValueEx" }))
                if (c->argsKnown && c->args.size() > 1 && c->args[1].kind == V_STRING && c->args[1].text == "Personal")
                    b.details += "; параметр Personal — папка «Мои документы»";
            list.push_back(b);
            roles[f.start].insert("USERDIRS");
        }

        bool driveApi = hasApi(f, { "GetLogicalDrives", "GetLogicalDriveStrings", "GetDriveType" });
        bool driveLoop = false;
        if (f.letterLoop)
            for (const string& s : strs)
                if (isDriveString(s))
                    driveLoop = true;
        if (driveApi || driveLoop)
        {
            Behavior b = makeBehavior("DRIVES", "Перебор логических дисков", "T1083",
                                      "File and Directory Discovery", MEDIUM, f,
                                      "Отключать съёмные и сетевые диски от подозрительного узла, ограничить запись на сетевые ресурсы");
            b.evidence = evidenceFor(f, { "GetLogicalDrives", "GetLogicalDriveStrings", "GetDriveType" });
            for (const string& s : strs)
                if (isDriveString(s))
                    b.evidence.push_back("строка с буквой диска \"" + s + "\"");
            b.details = driveLoop ? "буква диска перебирается в цикле (сравнение с 'z') и подставляется в шаблон пути"
                                  : "список дисков получается через WinAPI";
            list.push_back(b);
            roles[f.start].insert("DRIVES");
        }

        if (hasApi(f, { "GetTempPath", "GetTempFileName" }) && hasApi(f, EXECS))
        {
            Behavior b = makeBehavior("TEMPEXEC", "Создание временного файла и запуск внешней программы", "T1106",
                                      "Native API", MEDIUM, f,
                                      "Проверить содержимое временного файла и запускаемую программу; отслеживать дочерние процессы");
            b.evidence = evidenceFor(f, { "GetTempPath", "GetTempFileName", "WinExec", "ShellExecute", "CreateProcess" });
            for (const CallSite& c : f.calls)
                if (!c.isApi && c.argsKnown && c.args.size() >= 2 && c.args[1].kind == V_STRING && c.args[1].text.find('%') != NPOS)
                    b.evidence.push_back(callLine(c) + "  — сборка командной строки");
            b.details = "во временном каталоге создаётся файл, который сразу открывается внешней программой";
            list.push_back(b);
        }

        if (hasApi(f, { "CreateMutex", "CreateMutexEx" }) && hasApi(f, { "GetLastError" }))
        {
            Behavior b = makeBehavior("MUTEX", "Контроль единственного экземпляра (мьютекс)", "T1480",
                                      "Execution Guardrails", LOW, f,
                                      "Имя мьютекса — индикатор для поиска заражённых узлов; заранее созданный мьютекс может блокировать запуск программы");
            b.evidence = evidenceFor(f, { "CreateMutex", "GetLastError" });
            for (const CallSite* c : callsTo(f, { "CreateMutex" }))
                if (c->argsKnown && c->args.size() > 2 && c->args[2].kind == V_STRING)
                    b.iocs.push_back("мьютекс \"" + c->args[2].text + "\"");
            if (b.iocs.empty())
                for (const string& s : strs)
                    if (containsNoCase(s, "mutex"))
                        b.iocs.push_back("мьютекс \"" + s + "\"");
            b.details = "при существующем мьютексе (ERROR_ALREADY_EXISTS) повторный экземпляр завершает работу";
            list.push_back(b);
        }
    }

    // Связки «разведка -> уничтожение» по графу вызовов
    for (const FunctionInfo& f : cm.functions)
        for (uint64_t callee : f.callees)
        {
            if (!roles[callee].count("DESTROY") || callee == f.start)
                continue;
            // какие пути передаются в функцию уничтожения: папка из реестра или корень диска
            vector<string> userDirs, drives, probes;
            for (const CallSite& c : f.calls)
            {
                if (c.args.empty())
                    continue;
                string path = c.args[0].kind == V_LOCAL ? c.args[0].content : c.args[0].kind == V_STRING ? c.args[0].text : "";
                if (!c.isApi && c.targetVa == callee)
                {
                    if (path.rfind("<реестр", 0) == 0)
                        userDirs.push_back(callLine(c));
                    else if (path.rfind("<диск>", 0) == 0 || isDriveString(path))
                        drives.push_back(callLine(c));
                }
                else if (!c.isApi && c.args.size() == 2 && c.args[1].kind == V_STRING && c.args[1].text == "w"
                         && path.rfind("<диск>", 0) == 0)
                    probes.push_back(callLine(c));
            }
            if (roles[f.start].count("USERDIRS"))
            {
                Behavior b = makeBehavior("TARGETED", "Целевое уничтожение документов пользователя", "T1485",
                                          "Data Destruction", CRITICAL, f,
                                          "Хранить резервные копии документов отдельно от узла (офлайн), включить теневые копии и контролируемый доступ к папкам");
                b.evidence = userDirs.empty() ? vector<string>{ "путь из Shell Folders передаётся в функцию уничтожения sub_" + hexPlain(callee) } : userDirs;
                b.details = "путь к папке «Документы» из реестра передаётся в функцию уничтожения sub_" + hexPlain(callee);
                list.push_back(b);
            }
            if (roles[f.start].count("DRIVES"))
            {
                Behavior b = makeBehavior("ALLDRIVES", "Уничтожение данных на всех доступных дисках", "T1485",
                                          "Data Destruction", CRITICAL, f,
                                          "Немедленно отключить узел от сети и съёмные носители; проверить общие сетевые папки");
                b.evidence = probes;
                b.evidence.insert(b.evidence.end(), drives.begin(), drives.end());
                if (b.evidence.empty())
                    b.evidence.push_back("корень каждого найденного диска передаётся в функцию уничтожения sub_" + hexPlain(callee));
                b.details = "корень каждого диска передаётся в функцию уничтожения sub_" + hexPlain(callee)
                          + (probes.empty() ? "" : "; перед этим диск проверяется на запись созданием пробного файла")
                          + " — затрагиваются все логические диски, доступные на запись, включая съёмные и сетевые";
                list.push_back(b);
            }
            break;
        }
    return list;
}
