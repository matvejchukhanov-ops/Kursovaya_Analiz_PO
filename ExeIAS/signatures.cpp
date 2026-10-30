#include "signatures.h"
#include "fsanalysis.h"
#include "pe.h"

#include <ctime>
#include <iomanip>
#include <regex>
#include <sstream>

const string BLOCK_VULN = "Признаки уязвимостей";
const string BLOCK_IOC = "Индикаторы компрометации";
const string BLOCK_FS = "Взаимодействие с файловой системой";
const string BLOCK_LANG = "Ошибки языка и компилятора";

// Категории сигнатур расширенной матрицы
const string CAT_ERROR = "Ошибка / исключение";
const string CAT_UNSAFE = "Небезопасная функция";
const string CAT_LIBRARY = "Системная библиотека";
const string CAT_DATA = "Чувствительные данные";
const string CAT_HARDENING = "Защитные механизмы PE";
const string CAT_API = "Вызов WinAPI";
const string CAT_NETWORK = "Сетевой ресурс";
const string CAT_REGISTRY = "Реестр";
const string CAT_FILE = "Файловая система";
const string CAT_COMMAND = "Команда / запуск";
const string CAT_SYNC = "Синхронизация";
const string CAT_MESSAGE = "Сообщение злоумышленника";
const string CAT_PE = "Аномалия структуры PE";

string blockOf(const string& category)
{
    if (category == CAT_ERROR || category == CAT_UNSAFE || category == CAT_LIBRARY
        || category == CAT_DATA || category == CAT_HARDENING)
        return BLOCK_VULN;
    return BLOCK_IOC;
}

// Сигнатура -> CWE / MITRE ATT&CK -> потенциальный тип инцидента
struct SignatureRule
{
    string pattern;         // что ищем
    bool exact;             // true — строка целиком (имя импорта), false — подстрока без учёта регистра
    string category;
    string cwe;
    string cweName;
    string attack;          // техника MITRE ATT&CK ("" — нет)
    string incident;
    Severity severity;      // базовый уровень критичности
    string cve;             // связанный CVE ("" — не связан)
    string recommendation;
};

const vector<SignatureRule> RULES = {
    // --- Ошибки и исключения (ПР №7)
    { "bad allocation", false, CAT_ERROR, "CWE-789", "Memory Allocation with Excessive Size Value", "",
      "Отказ в обслуживании (DoS)", MEDIUM, "",
      "Проверять размер запрашиваемой памяти, ограничить объём входных данных, обрабатывать std::bad_alloc" },
    { "permission denied", false, CAT_ERROR, "CWE-276", "Incorrect Default Permissions", "",
      "Некорректное управление правами / повышение привилегий", MEDIUM, "",
      "Проверить права на каталог приложения и файлы, запускать с минимальными привилегиями" },
    { "unknown exception", false, CAT_ERROR, "CWE-248", "Uncaught Exception", "",
      "Отказ в обслуживании (аварийное завершение)", LOW, "",
      "Перехватывать исключения на верхнем уровне и журналировать их" },
    { "abnormal program termination", false, CAT_ERROR, "CWE-248", "Uncaught Exception", "",
      "Отказ в обслуживании (аварийное завершение)", LOW, "",
      "Перехватывать исключения на верхнем уровне и журналировать их" },
    { "stack overflow", false, CAT_ERROR, "CWE-674", "Uncontrolled Recursion", "",
      "Отказ в обслуживании (DoS)", MEDIUM, "",
      "Ограничить глубину рекурсии и размер входных структур" },
    { "buffer overrun", false, CAT_ERROR, "CWE-120", "Buffer Copy without Checking Size of Input", "",
      "Удалённое выполнение кода (RCE)", HIGH, "",
      "Найти место переполнения, включить /GS, ASLR, DEP" },
    { "access violation", false, CAT_ERROR, "CWE-119", "Improper Restriction of Operations within Memory Buffer", "",
      "Повреждение памяти / RCE", HIGH, "",
      "Воспроизвести сбой, проверить работу с указателями и границы буферов" },

    // --- Загрузка библиотек: вектор DLL Hijacking
    { "kernel32.dll", false, CAT_LIBRARY, "CWE-426", "Untrusted Search Path", "",
      "DLL Hijacking (подмена библиотеки)", MEDIUM, "",
      "Загружать DLL только из System32 (SetDefaultDllDirectories / LOAD_LIBRARY_SEARCH_SYSTEM32)" },
    { "LoadLibraryExW", true, CAT_API, "CWE-426", "Untrusted Search Path", "T1129",
      "DLL Hijacking (подмена библиотеки)", MEDIUM, "",
      "Передавать полный путь к DLL и флаги LOAD_LIBRARY_SEARCH_*, проверять цифровую подпись" },
    { "LoadLibraryA", true, CAT_API, "CWE-427", "Uncontrolled Search Path Element", "T1129",
      "DLL Hijacking (подмена библиотеки)", MEDIUM, "",
      "Заменить на LoadLibraryExW с полным путём и LOAD_LIBRARY_SEARCH_SYSTEM32" },
    { "LoadLibraryW", true, CAT_API, "CWE-427", "Uncontrolled Search Path Element", "T1129",
      "DLL Hijacking (подмена библиотеки)", MEDIUM, "",
      "Заменить на LoadLibraryExW с полным путём и LOAD_LIBRARY_SEARCH_SYSTEM32" },

    // --- Внедрение кода в процессы
    { "VirtualAllocEx", true, CAT_API, "CWE-94", "Improper Control of Generation of Code", "T1055",
      "Внедрение кода в процесс (Process Injection)", HIGH, "",
      "Проверить, зачем приложению память в чужом процессе; запустить в песочнице" },
    { "WriteProcessMemory", true, CAT_API, "CWE-94", "Improper Control of Generation of Code", "T1055",
      "Внедрение кода в процесс (Process Injection)", HIGH, "",
      "Проверить, зачем приложению запись в чужой процесс; запустить в песочнице" },
    { "CreateRemoteThread", true, CAT_API, "CWE-94", "Improper Control of Generation of Code", "T1055",
      "Внедрение кода в процесс (Process Injection)", CRITICAL, "",
      "Изолировать файл, проанализировать динамически в песочнице" },

    // --- Запуск внешних команд
    { "system", true, CAT_COMMAND, "CWE-78", "OS Command Injection", "T1059",
      "Выполнение команд ОС", HIGH, "",
      "Не передавать пользовательский ввод в командную строку, использовать CreateProcess с фиксированным путём" },
    { "WinExec", true, CAT_COMMAND, "CWE-78", "OS Command Injection", "T1106",
      "Запуск внешней программы", HIGH, "",
      "Выяснить, какая программа запускается; отслеживать дочерние процессы в EDR" },
    { "ShellExecuteA", true, CAT_COMMAND, "CWE-78", "OS Command Injection", "T1106",
      "Запуск внешней программы", HIGH, "",
      "Проверять запускаемый путь, не передавать пользовательский ввод" },
    { "ShellExecuteW", true, CAT_COMMAND, "CWE-78", "OS Command Injection", "T1106",
      "Запуск внешней программы", HIGH, "",
      "Проверять запускаемый путь, не передавать пользовательский ввод" },
    { "CreateProcessA", true, CAT_COMMAND, "CWE-78", "OS Command Injection", "T1106",
      "Запуск внешней программы", HIGH, "",
      "Задавать полный путь к программе, не собирать командную строку из ввода" },
    { "CreateProcessW", true, CAT_COMMAND, "CWE-78", "OS Command Injection", "T1106",
      "Запуск внешней программы", HIGH, "",
      "Задавать полный путь к программе, не собирать командную строку из ввода" },
    { "cmd.exe", false, CAT_COMMAND, "CWE-78", "OS Command Injection", "T1059.003",
      "Выполнение команд через cmd.exe", HIGH, "",
      "Выяснить, какие команды запускаются, отслеживать дочерние процессы в EDR" },
    { "powershell", false, CAT_COMMAND, "CWE-78", "OS Command Injection", "T1059.001",
      "Выполнение сценариев PowerShell", HIGH, "",
      "Выяснить, какие сценарии запускаются, включить журналирование PowerShell" },
    { "notepad.exe", false, CAT_COMMAND, "", "", "T1106",
      "Запуск штатной программы Windows из кода", LOW, "",
      "Выяснить, какой файл открывается в программе и откуда он берётся" },

    // --- Уничтожение резервных копий и восстановления
    { "vssadmin", false, CAT_COMMAND, "CWE-506", "Embedded Malicious Code", "T1490",
      "Удаление теневых копий (препятствие восстановлению)", CRITICAL, "",
      "Изолировать узел, проверить наличие теневых копий и офлайн-резервов" },
    { "wbadmin", false, CAT_COMMAND, "CWE-506", "Embedded Malicious Code", "T1490",
      "Удаление резервных копий Windows", HIGH, "",
      "Проверить состояние резервных копий, хранить их вне узла" },
    { "bcdedit", false, CAT_COMMAND, "CWE-506", "Embedded Malicious Code", "T1490",
      "Отключение среды восстановления", HIGH, "",
      "Проверить конфигурацию загрузки (bcdedit /enum)" },
    { "cipher /w", false, CAT_COMMAND, "CWE-506", "Embedded Malicious Code", "T1485",
      "Затирание свободного места на диске", HIGH, "",
      "Изолировать узел, восстанавливать данные только из резервной копии" },

    // --- Небезопасная работа с буферами и числами
    { "strcpy", true, CAT_UNSAFE, "CWE-120", "Buffer Copy without Checking Size of Input", "",
      "Переполнение буфера / RCE", HIGH, "", "Заменить на strcpy_s / std::string" },
    { "strcat", true, CAT_UNSAFE, "CWE-120", "Buffer Copy without Checking Size of Input", "",
      "Переполнение буфера / RCE", HIGH, "", "Заменить на strcat_s / std::string" },
    { "sprintf", true, CAT_UNSAFE, "CWE-120", "Buffer Copy without Checking Size of Input", "",
      "Переполнение буфера / RCE", HIGH, "", "Заменить на snprintf / std::format" },
    { "gets", true, CAT_UNSAFE, "CWE-242", "Use of Inherently Dangerous Function", "",
      "Переполнение буфера / RCE", CRITICAL, "", "Заменить на fgets / std::getline" },
    { "strtoul", true, CAT_UNSAFE, "CWE-190", "Integer Overflow or Wraparound", "",
      "Отказ в обслуживании (DoS)", MEDIUM, "CVE-2026-45352", "Проверять знак и диапазон числа и конец разбора" },
    { "atoi", true, CAT_UNSAFE, "CWE-190", "Integer Overflow or Wraparound", "",
      "Логическая ошибка / DoS", LOW, "", "Заменить на std::from_chars с проверкой результата" },

    // --- Сеть
    { "URLDownloadToFile", false, CAT_NETWORK, "CWE-494", "Download of Code Without Integrity Check", "T1105",
      "Загрузка вредоносной нагрузки", HIGH, "", "Проверять подпись загружаемых файлов, блокировать адрес на шлюзе" },
    { "InternetOpen", false, CAT_NETWORK, "CWE-319", "Cleartext Transmission of Sensitive Information", "T1071",
      "Связь с управляющим сервером (C2) / утечка данных", MEDIUM, "",
      "Выяснить, к каким адресам идёт обращение, отслеживать трафик" },
    { "WinHttpOpen", true, CAT_NETWORK, "CWE-319", "Cleartext Transmission of Sensitive Information", "T1071",
      "Связь с управляющим сервером (C2) / утечка данных", MEDIUM, "",
      "Выяснить, к каким адресам идёт обращение, отслеживать трафик" },
    { "WSAStartup", true, CAT_NETWORK, "CWE-319", "Cleartext Transmission of Sensitive Information", "T1095",
      "Сетевое взаимодействие / утечка данных", LOW, "",
      "Проверить, нужна ли приложению сеть, ограничить её межсетевым экраном" },
    { "x-forwarded-for", false, CAT_NETWORK, "CWE-476", "NULL Pointer Dereference", "",
      "Отказ в обслуживании (DoS)", HIGH, "CVE-2026-46527", "Проверять заголовок на пустоту, обновить cpp-httplib" },
    { "remote_addr", false, CAT_NETWORK, "CWE-290", "Authentication Bypass by Spoofing", "",
      "Подмена адреса клиента", CRITICAL, "CVE-2025-66570", "Брать адрес клиента из сокета, а не из заголовков" },

    // --- Реестр: закрепление и разведка
    { "CurrentVersion\\Run", false, CAT_REGISTRY, "CWE-506", "Embedded Malicious Code", "T1547.001",
      "Закрепление в системе через ключ автозапуска", HIGH, "",
      "Проверить ключи Run/RunOnce (HKLM и HKCU), удалить посторонние параметры" },
    { "Image File Execution Options", false, CAT_REGISTRY, "CWE-506", "Embedded Malicious Code", "T1546.012",
      "Перехват запуска программ через IFEO", HIGH, "", "Проверить параметры Debugger в ключе IFEO" },
    { "Winlogon", false, CAT_REGISTRY, "CWE-506", "Embedded Malicious Code", "T1547.004",
      "Закрепление через Winlogon (Shell / Userinit)", HIGH, "", "Сверить параметры Shell и Userinit с эталоном" },
    { "Shell Folders", false, CAT_REGISTRY, "", "", "T1083",
      "Определение пользовательских каталогов (Документы, Рабочий стол)", MEDIUM, "",
      "Выяснить, что программа делает с каталогами пользователя; включить контролируемый доступ к папкам" },
    { "RegSetValueEx", false, CAT_REGISTRY, "CWE-284", "Improper Access Control", "T1112",
      "Изменение реестра", MEDIUM, "", "Проверить изменяемые ключи реестра (Run, RunOnce, Services)" },

    // --- Файловая система: маски и операции, видимые по строкам
    { "*.*", false, CAT_FILE, "", "", "T1083",
      "Маска перебора всех файлов каталога", MEDIUM, "",
      "Сопоставить с вызовами FindFirstFile/FindNextFile: какие операции выполняются над найденными файлами" },
    { "attrib +h", false, CAT_FILE, "CWE-506", "Embedded Malicious Code", "T1564.001",
      "Сокрытие файлов атрибутом «скрытый»", MEDIUM, "", "Проверить скрытые файлы в каталогах пользователя" },

    // --- Сообщения злоумышленника (записки, угрозы)
    { "piracy", false, CAT_MESSAGE, "CWE-506", "Embedded Malicious Code", "T1491.001",
      "Текст-послание злоумышленника", MEDIUM, "", "Искать текст послания в файлах как признак заражения" },
    { "deserve", false, CAT_MESSAGE, "CWE-506", "Embedded Malicious Code", "T1491.001",
      "Текст-послание злоумышленника", MEDIUM, "", "Искать текст послания в файлах как признак заражения" },
    { "your files", false, CAT_MESSAGE, "CWE-506", "Embedded Malicious Code", "T1486",
      "Записка о выкупе / уничтожении файлов", HIGH, "", "Изолировать узел, не платить выкуп, восстанавливать из резервной копии" },
    { "decrypt", false, CAT_MESSAGE, "CWE-506", "Embedded Malicious Code", "T1486",
      "Упоминание расшифровки данных (шифровальщик)", HIGH, "", "Изолировать узел, проверить наличие зашифрованных файлов" },
    { "bitcoin", false, CAT_MESSAGE, "CWE-506", "Embedded Malicious Code", "T1486",
      "Требование оплаты в криптовалюте", HIGH, "", "Изолировать узел, сообщить в службу ИБ" },

    // --- Сокрытие и противодействие анализу
    { "IsDebuggerPresent", true, CAT_API, "CWE-693", "Protection Mechanism Failure", "T1622",
      "Противодействие анализу", LOW, "", "Обычно это CRT; при сочетании с упаковкой — анализ в песочнице" },

    // --- Раскрытие данных
    { ".pdb", false, CAT_DATA, "CWE-215", "Insertion of Sensitive Information Into Debugging Code", "",
      "Раскрытие данных (пути сборочной среды)", LOW, "", "Не оставлять полный путь к PDB в релизной сборке (/PDBALTPATH)" },
    { "password", false, CAT_DATA, "CWE-798", "Use of Hard-coded Credentials", "",
      "Раскрытие учётных данных", HIGH, "", "Убрать учётные данные из кода, хранить в защищённом хранилище" },
    { "BEGIN RSA PRIVATE KEY", false, CAT_DATA, "CWE-321", "Use of Hard-coded Cryptographic Key", "",
      "Раскрытие ключа шифрования", CRITICAL, "", "Отозвать ключ, вынести ключи из кода" },
};

// Признаки легитимного происхождения файла (ПР №7)
struct ContextMarker
{
    string pattern;
    string meaning;
};

const vector<ContextMarker> CONTEXT_MARKERS = {
    { "apphost",               "стандартный загрузчик .NET (apphost)" },
    { "hostfxr",               "библиотека хоста .NET (hostfxr)" },
    { "dotnet_root",           "переменная окружения .NET (DOTNET_ROOT)" },
    { "microsoft.netcore.app", "среда выполнения .NET Core" },
};

struct ContextExplanation
{
    string cwe;
    string reason;
};

const vector<ContextExplanation> DOTNET_EXPLANATIONS = {
    { "CWE-426", "apphost штатно загружает hostfxr.dll и системные библиотеки" },
    { "CWE-427", "apphost штатно загружает hostfxr.dll и системные библиотеки" },
    { "CWE-78",  "apphost вызывает ShellExecuteW, чтобы открыть страницу загрузки .NET, если среда не установлена" },
};

// Локальная база CVE (как в ПР №6–7, сверять с NVD)
struct CveRecord
{
    string library;
    string cve;
    string from;
    string fixed;
    string cwe;
    string incident;
    double cvss;
};

const vector<CveRecord> CVE_DATABASE = {
    { "cpp-httplib", "CVE-2026-45352", "",      "0.43.4", "CWE-129", "Отказ в обслуживании (chunk-size)",        7.5 },
    { "cpp-httplib", "CVE-2026-46527", "",      "",       "CWE-476", "Отказ в обслуживании (X-Forwarded-For)",   8.7 },
    { "cpp-httplib", "CVE-2025-66570", "",      "",       "CWE-290", "Подмена REMOTE_ADDR / LOCAL_ADDR",         10.0 },
    { "OpenSSL",     "CVE-2014-0160",  "1.0.1", "1.0.1g", "CWE-125", "Раскрытие данных (Heartbleed)",            7.5 },
    { "zlib",        "CVE-2018-25032", "",      "1.2.12", "CWE-787", "Повреждение памяти при сжатии",            7.5 },
};

struct LibraryMarker
{
    string library;
    string prefix;
};

const vector<LibraryMarker> LIBRARY_MARKERS = {
    { "cpp-httplib", "cpp-httplib/" },
    { "OpenSSL",     "OpenSSL " },
    { "zlib",        "inflate " },
    { "zlib",        "deflate " },
};

// Названия известных упаковщиков в именах секций
const vector<string> PACKER_SECTIONS = { "UPX0", "UPX1", ".aspack", ".adata", ".petite", ".packed", "MPRESS1", ".nsp0", ".themida", ".vmp0" };

Finding makeFinding(const string& category, const string& signature, const string& cwe, const string& cweName,
                    const string& attack, const string& incident, Severity sev, const string& recommendation,
                    const string& source)
{
    return { blockOf(category), category, signature, cwe, cweName, attack, incident, sev, sev, "", 0,
             recommendation, "", source, 1, {} };
}

void addExample(Finding& f, const string& line)
{
    if (f.examples.size() < MAX_EXAMPLES && find(f.examples.begin(), f.examples.end(), line) == f.examples.end())
        f.examples.push_back(line);
}

// ---------------------------------------------------------------- мета-данные и ошибки

Metadata collectMetadata(const vector<string>& data)
{
    const regex dll("[A-Za-z0-9_.-]+\\.dll", regex::icase);
    const regex file("[A-Za-z0-9_~-]+\\.(exe|sys|pdb|txt|ini|dat|bat|cmd|ps1|vbs|tmp|log|cfg|json)\\b", regex::icase);
    const regex path("([A-Za-z]:\\\\|\\\\\\\\)[^\"<>|]+");
    const regex version("\\b[0-9]+\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?\\b");
    const char* developers[] = { "copyright", "(c)", "corporation", "inc.", "ltd", "llc", "visual c++", "borland",
                                 "delphi", "embarcadero", "mingw", "gcc", "companyname", "productname",
                                 "fileversion", ".netframework", ".netcoreapp", "microsoft corporation" };

    Metadata meta;
    for (const string& line : data)
    {
        smatch m;
        if (regex_search(line, m, path))
            addUnique(meta.paths, m.str());
        else if (regex_search(line, m, dll))
            addUnique(meta.dlls, m.str());
        if (regex_search(line, m, file))
            addUnique(meta.files, m.str());
        if (regex_search(line, m, version))
            addUnique(meta.versions, line);
        if (line.find('\\') != NPOS)    // ключи реестра и пути — не сведения о разработчике
            continue;
        for (const char* d : developers)
            if (containsNoCase(line, d))
            {
                addUnique(meta.developers, line);
                break;
            }
    }
    return meta;
}

vector<string> collectErrors(const vector<string>& data)
{
    const char* keywords[] = { "error", "exception", "failed", "abort", "terminat", "invalid", "denied",
                               "overflow", "not enough space", "unable to", "cannot" };
    vector<string> errors;
    for (const string& line : data)
    {
        if (containsNoCase(line, "dos mode"))    // заглушка DOS есть в любом PE
            continue;
        for (const char* k : keywords)
            if (containsNoCase(line, k))
            {
                addUnique(errors, line);
                break;
            }
    }
    return errors;
}

// ---------------------------------------------------------------- версии библиотек и CVE

vector<int> versionParts(const string& v)
{
    vector<int> parts;
    int number = -1;
    for (size_t i = 0; i < v.length(); i++)
    {
        char c = v[i];
        if (c >= '0' && c <= '9')
            number = (number < 0 ? 0 : number * 10) + (c - '0');
        else
        {
            if (number >= 0)
                parts.push_back(number);
            number = -1;
            if (c >= 'a' && c <= 'z')
                parts.push_back(c - 'a' + 1);
        }
    }
    if (number >= 0)
        parts.push_back(number);
    return parts;
}

int compareVersions(const string& a, const string& b)
{
    vector<int> pa = versionParts(a), pb = versionParts(b);
    size_t n = max(pa.size(), pb.size());
    for (size_t i = 0; i < n; i++)
    {
        int x = i < pa.size() ? pa[i] : 0;
        int y = i < pb.size() ? pb[i] : 0;
        if (x != y)
            return x - y;
    }
    return 0;
}

bool isVulnerableVersion(const string& version, const CveRecord& rec)
{
    if (!rec.from.empty() && compareVersions(version, rec.from) < 0)
        return false;
    if (!rec.fixed.empty() && compareVersions(version, rec.fixed) >= 0)
        return false;
    return true;
}

vector<Library> detectLibraries(const vector<string>& data)
{
    vector<Library> libs;
    for (const LibraryMarker& marker : LIBRARY_MARKERS)
    {
        bool known = false;
        for (const Library& l : libs)
            if (l.name == marker.library)
                known = true;
        if (known)
            continue;

        for (const string& line : data)
        {
            size_t pos = line.find(marker.prefix);
            if (pos == NPOS)
                continue;
            string version;
            for (size_t j = pos + marker.prefix.length(); j < line.length(); j++)
            {
                char c = line[j];
                if ((c >= '0' && c <= '9') || c == '.' || (c >= 'a' && c <= 'z'))
                    version += c;
                else
                    break;
            }
            if (!version.empty() && version[0] >= '0' && version[0] <= '9')
            {
                libs.push_back({ marker.library, version });
                break;
            }
        }
    }
    return libs;
}

vector<Finding> matchCve(const vector<Library>& libs)
{
    vector<Finding> found;
    for (const Library& lib : libs)
        for (const CveRecord& rec : CVE_DATABASE)
        {
            if (rec.library != lib.name || !isVulnerableVersion(lib.version, rec))
                continue;
            Severity sev = rec.cvss >= 9.0 ? CRITICAL : rec.cvss >= 7.0 ? HIGH : rec.cvss >= 4.0 ? MEDIUM : LOW;
            string fix = rec.fixed.empty() ? "следить за выпуском исправления в NVD" : "обновить до " + rec.fixed;
            Finding f = makeFinding(CAT_LIBRARY, rec.library + " " + lib.version, rec.cwe, "", "", rec.incident, sev,
                                    "Уязвимая версия библиотеки: " + fix, "строки");
            f.cve = rec.cve;
            f.cvss = rec.cvss;
            found.push_back(f);
        }
    return found;
}

// ---------------------------------------------------------------- матрица сигнатур

vector<Finding> matchRules(const vector<string>& data, const PeInfo& pe, const set<string>& confirmedCves)
{
    set<string> imported;
    for (const ImportDll& d : pe.imports)
        for (const ImportFunc& f : d.funcs)
            imported.insert(f.name);

    vector<Finding> found;
    for (const SignatureRule& rule : RULES)
    {
        string lowerPattern = toLower(rule.pattern);
        Finding f = { blockOf(rule.category), rule.category, rule.pattern, rule.cwe, rule.cweName, rule.attack,
                      rule.incident, rule.severity, rule.severity, confirmedCves.count(rule.cve) ? rule.cve : "", 0,
                      rule.recommendation, "", "строки", 0, {} };

        // послание — это фраза, а не имя функции (DecryptFileW — штатный API шифрования EFS)
        bool phraseOnly = rule.category == CAT_MESSAGE;

        bool inImports = false;
        for (const string& name : imported)
            if (!phraseOnly && (rule.exact ? name == rule.pattern : containsNoCase(name, lowerPattern)))
                inImports = true;

        for (const string& line : data)
        {
            if (phraseOnly && (line.find(' ') == NPOS || imported.count(line)))
                continue;
            bool hit = rule.exact ? line == rule.pattern : containsNoCase(line, lowerPattern);
            if (hit)
            {
                f.hits++;
                addExample(f, line);
            }
        }
        if (inImports)
        {
            f.source = "таблица импорта";
            f.hits = max<size_t>(f.hits, 1);
        }
        if (f.hits == 0)
            continue;

        // одна и та же строка под двумя ключевыми словами (послание) — одна находка
        bool duplicate = false;
        for (const Finding& prev : found)
            if (prev.incident == f.incident && !prev.examples.empty() && !f.examples.empty()
                && prev.examples[0] == f.examples[0])
                duplicate = true;
        if (!duplicate)
            found.push_back(f);
    }
    return found;
}

// Сетевые адреса: URL и IPv4 (ПР №7)
vector<Finding> matchNetwork(const vector<string>& data)
{
    const regex url("(https?|ftp)://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+", regex::icase);
    const regex ipv4("\\b((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\\b");

    Finding urls = makeFinding(CAT_NETWORK, "URL", "CWE-829", "Inclusion of Functionality from Untrusted Control Sphere",
                               "T1071", "Связь с внешним ресурсом (C2 / загрузка нагрузки)", MEDIUM,
                               "Проверить адреса по репутационным базам, при подозрении — заблокировать на шлюзе", "строки");
    Finding ips = makeFinding(CAT_NETWORK, "IPv4-адрес", "CWE-829", "Inclusion of Functionality from Untrusted Control Sphere",
                              "T1071", "Связь с внешним узлом (C2)", MEDIUM,
                              "Проверить адрес по репутационным базам, при подозрении — заблокировать на межсетевом экране", "строки");
    urls.hits = ips.hits = 0;

    for (const string& line : data)
    {
        smatch m;
        if (regex_search(line, m, url))
        {
            string found = toLower(m.str());
            if (found.find("schemas.microsoft.com") == NPOS && found.find("www.w3.org") == NPOS
                && found.find("crl.") == NPOS && found.find("ocsp.") == NPOS)
            {
                urls.hits++;
                addExample(urls, m.str());
            }
        }
        else if (regex_search(line, m, ipv4))
        {
            string ip = m.str();
            if (ip.rfind("0.", 0) != 0 && ip.find(".0.0") == NPOS)
            {
                ips.hits++;
                addExample(ips, ip);
            }
        }
    }

    vector<Finding> result;
    if (urls.hits > 0) result.push_back(urls);
    if (ips.hits > 0) result.push_back(ips);
    return result;
}

// Пути и имена файлов, которые программа создаёт или использует
vector<Finding> matchPaths(const vector<FoundString>& all)
{
    const regex exeName("^\\\\[A-Za-z0-9_.-]+\\.(exe|dll|sys|scr)$", regex::icase);
    Finding roots = makeFinding(CAT_FILE, "Файл в корне диска", "", "", "T1074.001",
                                "Создание служебного файла в корне системного диска", MEDIUM,
                                "Проверить наличие файла на узлах — признак заражения", "строки");
    Finding names = makeFinding(CAT_FILE, "Имя исполняемого файла для размещения в системе", "", "", "T1036.005",
                                "Копирование программы под новым именем (дроп)", MEDIUM,
                                "Искать файл с этим именем в системных каталогах и автозагрузке", "строки");
    roots.hits = names.hits = 0;
    for (const FoundString& s : all)
    {
        if (s.text.length() > 260)      // длиннее MAX_PATH — не путь; regex на огромных строках не запускаем
            continue;
        if (isRootFilePath(s.text))
        {
            roots.hits++;
            addExample(roots, s.text);
        }
        if (regex_match(s.text, exeName))
        {
            names.hits++;
            addExample(names, s.text);
        }
    }
    vector<Finding> result;
    if (roots.hits > 0) result.push_back(roots);
    if (names.hits > 0) result.push_back(names);
    return result;
}

// ---------------------------------------------------------------- структура PE

vector<Finding> checkPeStructure(const PeInfo& pe)
{
    vector<Finding> found;
    if (!pe.valid)
        return found;

    bool entryInCode = false;
    for (const Section& s : pe.sections)
    {
        if (pe.entryRva >= s.va && pe.entryRva < s.va + max(s.vsize, s.rawSize) && isExecutable(s))
            entryInCode = true;

        for (const string& packer : PACKER_SECTIONS)
            if (s.name == packer)
                found.push_back(makeFinding(CAT_PE, "Секция " + s.name, "CWE-506", "Embedded Malicious Code", "T1027.002",
                                            "Упаковка исполняемого файла", HIGH,
                                            "Распаковать файл и повторить анализ", "заголовки PE"));
        if (s.entropy > 7.2 && s.rawSize > 0x200)
        {
            ostringstream ss;
            ss << "Секция " << s.name << ": энтропия " << fixed << setprecision(2) << s.entropy;
            found.push_back(makeFinding(CAT_PE, ss.str(), "", "", "T1027", "Упакованные или зашифрованные данные", HIGH,
                                        "Распаковать/расшифровать содержимое, анализ в песочнице", "заголовки PE"));
        }
        if (s.vsize > 2 * (uint64_t)s.rawSize && s.vsize - s.rawSize > 0x10000)
            found.push_back(makeFinding(CAT_PE, "Секция " + s.name + ": VirtualSize >> SizeOfRawData", "", "", "T1027",
                                        "Распаковка кода в память при запуске", MEDIUM,
                                        "Снять дамп памяти процесса в песочнице", "заголовки PE"));
        if ((s.chars & 0x20000000) && (s.chars & 0x80000000))
            found.push_back(makeFinding(CAT_PE, "Секция " + s.name + ": запись + исполнение (RWX)", "CWE-506", "Embedded Malicious Code",
                                        "T1027", "Самомодифицирующийся код", MEDIUM,
                                        "Проверить, изменяется ли код при выполнении", "заголовки PE"));
    }
    if (!entryInCode && !pe.isDotNet)
        found.push_back(makeFinding(CAT_PE, "Точка входа вне исполняемой секции", "", "", "T1027",
                                    "Нестандартная точка входа (упаковщик / протектор)", HIGH,
                                    "Анализировать код точки входа в отладчике", "заголовки PE"));
    if (pe.timestamp == 0 || pe.timestamp > (uint32_t)time(nullptr))
    {
        Finding f = makeFinding(CAT_PE, "Метка времени компиляции: " + (pe.timestamp ? formatTime(pe.timestamp) : string("0")),
                                "", "", "T1070.006", "Подделка метки времени", LOW,
                                "Не доверять дате сборки при атрибуции", "заголовки PE");
        f.note = "у системных файлов Windows 10+ в этом поле хэш воспроизводимой сборки, а не дата";
        found.push_back(f);
    }

    size_t importCount = 0;
    bool dynamicImports = false;
    for (const ImportDll& d : pe.imports)
        for (const ImportFunc& f : d.funcs)
        {
            importCount++;
            if (f.name == "GetProcAddress")
                dynamicImports = true;
        }
    if (!pe.isDotNet && importCount < 6 && dynamicImports)
        found.push_back(makeFinding(CAT_PE, "Импортов всего " + to_string(importCount) + ", есть GetProcAddress", "", "", "T1027",
                                    "Скрытие используемых функций (динамический импорт)", MEDIUM,
                                    "Восстановить реальный импорт в отладчике", "заголовки PE"));

    if (!(pe.dllChars & 0x0040))
        found.push_back(makeFinding(CAT_HARDENING, "Нет ASLR (DYNAMIC_BASE)", "CWE-693", "Protection Mechanism Failure", "",
                                    "Упрощение эксплуатации уязвимостей памяти", LOW,
                                    "Собирать с ключом /DYNAMICBASE", "заголовки PE"));
    if (!(pe.dllChars & 0x0100))
        found.push_back(makeFinding(CAT_HARDENING, "Нет DEP (NX_COMPAT)", "CWE-693", "Protection Mechanism Failure", "",
                                    "Исполнение кода из области данных", LOW,
                                    "Собирать с ключом /NXCOMPAT", "заголовки PE"));
    return found;
}

// ---------------------------------------------------------------- находки анализа кода

vector<Finding> behaviorFindings(const vector<Behavior>& behaviors)
{
    vector<Finding> found;
    for (const Behavior& b : behaviors)
    {
        bool malicious = b.severity >= HIGH;
        string category = b.code == "AUTORUN" || b.code == "USERDIRS" ? CAT_REGISTRY
                        : b.code == "MUTEX" ? CAT_SYNC : b.code == "TEMPEXEC" ? CAT_COMMAND : CAT_FILE;
        Finding f = { BLOCK_FS, category, b.title + " @ " + hexVa(b.func), malicious ? "CWE-506" : "",
                      malicious ? "Embedded Malicious Code" : "", b.attack + " " + b.attackName, b.title,
                      b.severity, b.severity, "", 0, b.recommendation, b.details, "машинный код", 1, {} };
        f.examples = b.evidence;   // все восстановленные вызовы, без ограничения MAX_EXAMPLES
        found.push_back(f);
    }
    return found;
}

vector<Finding> importOnlyFsFindings(const PeInfo& pe, bool codeConfirmed)
{
    vector<Finding> found;
    if (codeConfirmed)
        return found;
    set<string> names;
    for (const ImportDll& d : pe.imports)
        for (const ImportFunc& f : d.funcs)
            names.insert(f.name);
    auto any = [&](const vector<string>& stems)
    {
        for (const string& n : names)
            for (const string& s : stems)
                if (apiMatches(n, s))
                    return true;
        return false;
    };
    if (any({ "FindFirstFile", "FindFirstFileEx" }) && any({ "FindNextFile" }) && any({ "DeleteFile", "RemoveDirectory" }))
    {
        Finding f = makeFinding(CAT_FILE, "FindFirstFile + FindNextFile + DeleteFile", "", "", "T1485",
                                "Возможное массовое удаление файлов", HIGH,
                                "Проверить поведение файла в песочнице с мониторингом ФС (Process Monitor)", "таблица импорта");
        f.block = BLOCK_FS;
        f.note = "не подтверждено анализом кода";
        found.push_back(f);
    }
    return found;
}

vector<string> applyContext(const vector<string>& data, vector<Finding>& findings)
{
    vector<string> found;
    for (const ContextMarker& marker : CONTEXT_MARKERS)
        for (const string& line : data)
            if (containsNoCase(line, marker.pattern))
            {
                found.push_back(marker.meaning + ": " + line);
                break;
            }
    if (found.empty())
        return found;

    for (Finding& f : findings)
        for (const ContextExplanation& e : DOTNET_EXPLANATIONS)
            if (f.cwe == e.cwe && f.severity > LOW)
            {
                f.severity = (Severity)(f.severity - 1);
                f.note = "критичность понижена: " + e.reason;
            }
    return found;
}
