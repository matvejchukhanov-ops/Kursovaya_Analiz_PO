// Общие типы ИАС: результаты разбора PE, анализа кода, находки и итог анализа
#pragma once

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace std;
namespace fs = std::filesystem;

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

    // Защиты компилятора из IMAGE_LOAD_CONFIG_DIRECTORY
    bool hasLoadConfig = false;
    bool stackCookie = false;     // /GS — защита стека от переполнения
    bool safeSeh = false;         // /SAFESEH — таблица обработчиков исключений (x86)
    bool controlFlowGuard = false;

    // Заголовок Rich: инструменты Microsoft, которыми собран файл (prodid, build, count)
    struct RichEntry { uint16_t prodId, build; uint32_t count; };
    vector<RichEntry> rich;
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

// Ошибка программиста, найденная в машинном коде (CWE-252, CWE-120, CWE-835, CWE-674)
struct CodeIssue
{
    string cwe;
    uint64_t addr;
    string text;
};

struct FunctionInfo
{
    uint64_t start = 0;
    vector<CodeRef> refs;
    vector<CallSite> calls;
    vector<CodeIssue> issues;
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

    // Экономическая опасность (модуль economics)
    string damage;          // вид ущерба: потеря данных, простой, расследование и т.д.
    double lossMin = 0, lossMax = 0, lossExpected = 0;   // руб. за один инцидент
    string econLevel;       // низкая / средняя / высокая / критическая
};

// Язык программирования и средства сборки исследуемого файла
struct LanguageInfo
{
    string language = "не определён";
    string toolchain;           // компилятор / среда
    string runtime;             // библиотека времени выполнения
    int confidence = 0;         // уверенность, %
    bool cpp = false, dotnet = false, legacy = false;
    vector<string> evidence;
};

// Параметры организации для оценки ущерба (economics.ini рядом с ExeIAS.exe)
struct EconomicProfile
{
    string name = "малая организация, 20 рабочих мест";
    double workstations = 20;          // рабочих мест в организации
    double hourCost = 2000;            // руб.: потери за 1 час простоя одного рабочего места
    double specialistHour = 2500;      // руб.: час работы специалиста ИТ / ИБ
    double hostRebuildHours = 8;       // ч: переустановка и настройка одного узла
    double investigationHours = 40;    // ч: расследование инцидента
    double dataValue = 500000;         // руб.: воссоздание данных одного узла без резервной копии
    double sharedDataValue = 2000000;  // руб.: данные в сетевых папках организации
    double backupShare = 0.7;          // доля данных, восстанавливаемых из резервных копий
    double leakFineMin = 3000000;      // руб.: штраф за утечку персональных данных (ст. 13.11 КоАП РФ)
    double leakFineMax = 5000000;
    string source = "значения по умолчанию";
};

struct EconomicLine
{
    string name;
    double lo = 0, hi = 0, expected = 0;
};

// Итоговая экономическая оценка: по каждому виду ущерба берётся наихудшая находка
struct EconomicSummary
{
    double lossMin = 0, lossMax = 0, lossExpected = 0;
    string level = "нет";
    vector<string> breakdown;
    vector<EconomicLine> lines;
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
    LanguageInfo lang;
    vector<Finding> findings;
    EconomicProfile profile;
    EconomicSummary economy;
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

// Внутри программы текст хранится в UTF-8, пути — в fs::path (UTF-16): так работают имена с кириллицей
string toUtf8(const wstring& w);
wstring fromUtf8(const string& s);
fs::path pathFromUtf8(const string& s);
string pathToUtf8(const fs::path& p);
