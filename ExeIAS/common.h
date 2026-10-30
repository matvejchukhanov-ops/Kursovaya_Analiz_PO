// Общие типы ИАС: результаты разбора PE, анализа кода, находки и итог анализа
#pragma once

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace std;

const size_t MIN_LENGTH = 4;          // минимальная длина строки, как у strings.exe
const size_t MAX_EXAMPLES = 3;        // сколько строк-примеров показывать в находке
const size_t MAX_LINE = 512;          // длиннее строки обрезаются: std::regex на огромной строке уходит в глубокую рекурсию
const size_t NPOS = string::npos;

enum Severity { NONE = 0, LOW, MEDIUM, HIGH, CRITICAL };

// ---------------------------------------------------------------- входные данные

struct FoundString
{
    size_t offset;    // смещение в файле
    string text;
    bool wide;        // UTF-16LE
};

// ---------------------------------------------------------------- PE

struct Section
{
    string name;
    uint32_t va = 0, vsize = 0, rawPtr = 0, rawSize = 0, chars = 0;
    double entropy = 0;
};

struct ImportFunc
{
    string name;
    uint64_t iatVa;   // адрес ячейки таблицы адресов импорта (IAT)
};

struct ImportDll
{
    string name;
    vector<ImportFunc> funcs;
};

struct DataDir
{
    uint32_t va = 0, size = 0;
};

struct PeInfo
{
    bool valid = false;
    string error;
    bool is64 = false, isDll = false, isDotNet = false;
    uint16_t machine = 0, subsystem = 0, dllChars = 0;
    uint32_t timestamp = 0, entryRva = 0, sizeOfHeaders = 0, checksum = 0;
    uint64_t imageBase = 0;
    size_t fileSize = 0;        // смещения из заголовков проверяются по реальному размеру файла
    string linker;
    size_t overlay = 0;
    DataDir dirs[16];
    vector<Section> sections;
    vector<ImportDll> imports;
};

// ---------------------------------------------------------------- анализ машинного кода

struct CodeRef
{
    uint64_t addr;    // адрес инструкции
    string text;      // имя API или строка
    bool isApi;
};

// Значение регистра, ячейки стека или аргумента, восстановленное при разборе кода
enum ValueKind
{
    V_UNKNOWN,
    V_CONST,     // число
    V_STRING,    // адрес строки из образа
    V_API,       // адрес функции из IAT
    V_LOCAL,     // адрес локальной переменной (буфера) в стеке: var_434
    V_ARG,       // аргумент функции: arg_0
    V_SYMBOL,    // результат API: «<командная строка>», описатель ключа реестра
};

struct Value
{
    ValueKind kind = V_UNKNOWN;
    int64_t num = 0;      // константа, адрес строки или позиция переменной в кадре стека
    string text;          // строка, имя API, имя переменной или символ
    string content;       // для V_LOCAL — что известно о содержимом буфера
    bool atEnd = false;   // указатель стоит в конце строки (после repne scasb — шаблон strlen/strcat)
};

// Вызов функции с восстановленными аргументами
struct CallSite
{
    uint64_t addr;
    string target;        // имя API или адрес внутренней функции
    bool isApi;
    uint64_t targetVa;    // для внутренних вызовов
    vector<Value> args;
    bool argsKnown;       // число аргументов известно (прототип или add esp после вызова)
};

struct FunctionInfo
{
    uint64_t start = 0;
    vector<CodeRef> refs;
    vector<CallSite> calls;
    bool decoded = false;        // инструкции функции разобраны декодером
    set<uint64_t> callees;
    bool recursive = false;
    bool letterLoop = false;     // сравнение с 'z' / 'Z' — цикл перебора букв (дисков)
};

struct CodeMap
{
    bool done = false;
    string note;
    vector<FunctionInfo> functions;
    size_t apiRefs = 0, stringRefs = 0, decodedFunctions = 0, resolvedCalls = 0;
};

struct Behavior
{
    string code;
    string title;
    string attack;
    string attackName;
    Severity severity;
    uint64_t func;
    vector<string> evidence;
    string details;
    string recommendation;
    vector<string> iocs;         // индикаторы для блокировки (ключи, имена файлов, мьютексы)
};

// ---------------------------------------------------------------- классификация

struct Finding
{
    string block;
    string category;
    string signature;
    string cwe;
    string cweName;
    string attack;
    string incident;
    Severity severity;
    Severity baseSeverity;
    string cve;
    double cvss;
    string recommendation;
    string note;
    string source;          // таблица импорта / строки / машинный код / заголовки PE
    size_t hits;
    vector<string> examples;
};

struct Library
{
    string name;
    string version;
};

struct Metadata
{
    vector<string> dlls, files, paths, versions, developers;
};

// Итог работы всех модулей — вход генератора отчёта
struct Analysis
{
    string inputPath, name, stringsSource;
    size_t fileSize = 0;
    string md5, sha1, sha256;
    PeInfo pe;
    size_t rawCount = 0, meaningful = 0;
    vector<string> data;
    Metadata meta;
    vector<string> errors;
    vector<string> context;
    CodeMap code;
    vector<Behavior> behaviors;
    vector<Finding> findings;
    int score = 0;
    string probability;
    Severity overall = NONE;
    string verdict;
};

// ---------------------------------------------------------------- общие функции (common.cpp)

string toLower(string s);
bool containsNoCase(const string& text, const string& lowerPattern);
void addUnique(vector<string>& list, const string& value);
string hexVa(uint64_t v);
string hexNum(uint64_t v);
string hexPlain(uint64_t v);
string severityName(Severity s);
