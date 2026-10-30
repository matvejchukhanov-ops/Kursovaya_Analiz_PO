#include "language.h"
#include "signatures.h"

#include <cstdlib>

// ================================================================ признаки языка

// Хотя бы одна строка содержит подстроку (без учёта регистра); найденная попадает в доказательства
bool hasString(const vector<string>& data, const string& lowerPattern, string* found = nullptr)
{
    for (const string& line : data)
        if (containsNoCase(line, lowerPattern))
        {
            if (found)
                *found = line;
            return true;
        }
    return false;
}

bool importsDll(const PeInfo& pe, const string& lowerPrefix)
{
    for (const ImportDll& d : pe.imports)
        if (toLower(d.name).rfind(lowerPrefix, 0) == 0)
            return true;
    return false;
}

bool hasSection(const PeInfo& pe, const string& name)
{
    for (const Section& s : pe.sections)
        if (s.name == name)
            return true;
    return false;
}

struct Marker
{
    const char* pattern;   // подстрока в нижнем регистре
    const char* meaning;
};

// Первый сработавший признак из списка: true и запись в доказательства
bool matchMarkers(const vector<string>& data, const vector<Marker>& markers, LanguageInfo& lang)
{
    bool any = false;
    for (const Marker& m : markers)
    {
        string line;
        if (hasString(data, m.pattern, &line))
        {
            lang.evidence.push_back(string(m.meaning) + ": «" + line.substr(0, 70) + "»");
            any = true;
        }
    }
    return any;
}

// Версия Visual Studio по версии компоновщика из дополнительного заголовка
string visualStudioName(const string& linker, int& major)
{
    major = atoi(linker.c_str());
    size_t dot = linker.find('.');
    int minor = dot == NPOS ? 0 : atoi(linker.c_str() + dot + 1);
    switch (major)
    {
    case 5:  return "Microsoft Visual C++ 5.0";
    case 6:  return "Microsoft Visual C++ 6.0";
    case 7:  return minor >= 10 ? "Visual Studio .NET 2003" : "Visual Studio .NET 2002";
    case 8:  return "Visual Studio 2005";
    case 9:  return "Visual Studio 2008";
    case 10: return "Visual Studio 2010";
    case 11: return "Visual Studio 2012";
    case 12: return "Visual Studio 2013";
    case 14:
        if (minor < 10) return "Visual Studio 2015";
        if (minor < 20) return "Visual Studio 2017";
        if (minor < 30) return "Visual Studio 2019";
        if (minor < 50) return "Visual Studio 2022";
        return "Visual Studio 2026";
    default: return "";
    }
}

LanguageInfo detectLanguage(const PeInfo& pe, const vector<string>& data)
{
    LanguageInfo lang;
    if (!pe.valid)
    {
        lang.evidence.push_back("файл не является PE");
        return lang;
    }
    const string linkerNote = "версия компоновщика " + pe.linker;

    // --- Управляемый код .NET
    if (pe.isDotNet)
    {
        lang.dotnet = true;
        lang.toolchain = ".NET (компилятор в IL)";
        lang.runtime = "CLR (mscoree.dll)";
        lang.evidence.push_back("в каталоге данных PE есть заголовок CLR");
        if (hasString(data, "microsoft.visualbasic"))
        {
            lang.language = "Visual Basic .NET";
            lang.confidence = 85;
            lang.evidence.push_back("ссылка на сборку Microsoft.VisualBasic");
        }
        else if (hasString(data, "fsharp.core"))
        {
            lang.language = "F#";
            lang.confidence = 85;
            lang.evidence.push_back("ссылка на сборку FSharp.Core");
        }
        else
        {
            lang.language = "C#";
            lang.confidence = 70;
            lang.evidence.push_back("сборка .NET без признаков VB.NET и F#: чаще всего это C#");
        }
        return lang;
    }

    // --- Языки с характерной средой выполнения: признаки сильнее, чем версия компоновщика
    if (matchMarkers(data, { { "go build id", "идентификатор сборки Go" }, { "runtime.gopanic", "среда выполнения Go" },
                             { "runtime.morestack", "среда выполнения Go" } }, lang))
    {
        lang.language = "Go";
        lang.toolchain = "компилятор Go (gc)";
        lang.runtime = "среда выполнения Go (сборщик мусора, горутины)";
        lang.confidence = 95;
        return lang;
    }
    if (matchMarkers(data, { { "rust_backtrace", "переменная среды Rust" }, { "/rustc/", "путь к исходникам компилятора Rust" },
                             { "rust_panic", "обработчик паники Rust" }, { "called `option::unwrap()`", "сообщение стандартной библиотеки Rust" } }, lang))
    {
        lang.language = "Rust";
        lang.toolchain = "компилятор rustc";
        lang.runtime = "стандартная библиотека Rust";
        lang.confidence = 90;
        return lang;
    }
    if (importsDll(pe, "msvbvm"))
    {
        lang.language = "Visual Basic 6";
        lang.toolchain = "Microsoft Visual Basic 5/6";
        lang.runtime = "MSVBVM60.DLL";
        lang.confidence = 98;
        lang.legacy = true;
        lang.evidence.push_back("импорт среды выполнения MSVBVM");
        return lang;
    }
    if (matchMarkers(data, { { "au3!ea06", "метка сценария AutoIt" }, { ">>>autoit", "метка сценария AutoIt" },
                             { "autoit v3", "строка AutoIt" } }, lang))
    {
        lang.language = "AutoIt";
        lang.toolchain = "AutoIt (сценарий внутри интерпретатора)";
        lang.confidence = 90;
        return lang;
    }
    if (matchMarkers(data, { { "pyinstaller", "упаковщик PyInstaller" }, { "_meipass", "распаковка PyInstaller" },
                             { "pyi-runtime", "загрузчик PyInstaller" }, { "pythonscript", "упаковщик py2exe" } }, lang))
    {
        lang.language = "Python";
        lang.toolchain = "Python, упакованный в EXE (PyInstaller / py2exe)";
        lang.runtime = "встроенный интерпретатор Python";
        lang.confidence = 90;
        lang.evidence.push_back("сам код Python сжат в архив внутри файла, строки программы могут быть не видны");
        return lang;
    }
    bool delphiSections = hasSection(pe, "CODE") || hasSection(pe, ".itext");
    if (matchMarkers(data, { { "borland\\delphi", "ключ реестра Delphi" }, { "embarcadero delphi", "среда Embarcadero" },
                             { "tobject", "базовый класс Delphi" }, { "fastmm", "менеджер памяти Delphi" } }, lang)
        && (delphiSections || lang.evidence.size() > 1))
    {
        lang.language = "Delphi (Object Pascal)";
        lang.toolchain = "Borland / Embarcadero Delphi";
        lang.runtime = "RTL / VCL Delphi";
        lang.confidence = delphiSections ? 90 : 75;
        if (delphiSections)
            lang.evidence.push_back("секции в стиле Borland (CODE / .itext)");
        return lang;
    }
    lang.evidence.clear();
    if (matchMarkers(data, { { "fpc ", "компилятор Free Pascal" } }, lang) && hasString(data, "free pascal"))
    {
        lang.language = "Free Pascal";
        lang.toolchain = "Free Pascal Compiler";
        lang.confidence = 85;
        return lang;
    }
    lang.evidence.clear();
    if (matchMarkers(data, { { "fatal.nim", "модуль Nim" }, { "system.nim", "модуль Nim" } }, lang))
    {
        lang.language = "Nim";
        lang.toolchain = "компилятор Nim";
        lang.confidence = 85;
        return lang;
    }
    lang.evidence.clear();

    // --- C и C++: компилятор определяем по компоновщику и среде выполнения
    bool gcc = matchMarkers(data, { { "gcc: (", "метка компилятора GCC" }, { "mingw", "среда MinGW" }, { "libgcc", "библиотека GCC" } }, lang);
    int major = 0;
    string vs = visualStudioName(pe.linker, major);
    bool msRuntime = !pe.rich.empty() || importsDll(pe, "vcruntime") || importsDll(pe, "msvcr") || importsDll(pe, "ucrtbase")
                  || importsDll(pe, "api-ms-win-crt") || hasString(data, "microsoft visual c++ runtime");

    if (gcc)
    {
        lang.toolchain = "GCC (MinGW)";
        lang.runtime = importsDll(pe, "msvcrt") ? "msvcrt.dll" : "libgcc / статическая CRT";
    }
    else if (msRuntime || !vs.empty())
    {
        lang.toolchain = (vs.empty() ? string("Microsoft Visual C++") : vs) + " (" + linkerNote + ")";
        lang.evidence.push_back(linkerNote);
        if (!pe.rich.empty())
        {
            uint16_t maxBuild = 0;
            for (const PeInfo::RichEntry& e : pe.rich)
                maxBuild = max(maxBuild, e.build);
            lang.evidence.push_back("заголовок Rich: " + to_string(pe.rich.size()) + " инструментов Microsoft, сборка до " + to_string(maxBuild));
        }
        lang.legacy = major > 0 && major < 10;
        lang.runtime = importsDll(pe, "vcruntime") || importsDll(pe, "api-ms-win-crt") ? "Universal CRT (динамически)"
                     : importsDll(pe, "msvcr") ? "msvcrt (динамически)" : "CRT Microsoft (статически)";
    }
    else
    {
        lang.evidence.push_back(linkerNote + ", известных признаков нет");
        lang.confidence = 0;
        return lang;
    }

    // C++: собственные классы в RTTI или стандартная библиотека C++. Классы std:: и type_info
    // есть и в обычной программе на C со статической CRT, поэтому они не считаются
    bool userClasses = false;
    string classLine;
    for (const string& line : data)
        if (line.find(".?AV") != NPOS && line.find("@std@@") == NPOS && line.find("type_info") == NPOS)
        {
            userClasses = true;
            classLine = line;
            break;
        }
    bool cppImports = importsDll(pe, "msvcp") || importsDll(pe, "libstdc++");
    bool anyRtti = hasString(data, ".?av");
    if (userClasses || cppImports)
    {
        lang.language = "C++";
        lang.cpp = true;
        lang.confidence = 90;
        lang.evidence.push_back(userClasses ? "классы C++ в RTTI: «" + classLine.substr(0, 60) + "»" : "импорт стандартной библиотеки C++");
    }
    else if (anyRtti)
    {
        lang.language = "C или C++";
        lang.confidence = 60;
        lang.evidence.push_back("в CRT есть только служебные классы std::, собственных классов нет");
    }
    else
    {
        lang.language = "C";
        lang.confidence = 75;
        lang.evidence.push_back("нет классов C++ (RTTI) и стандартной библиотеки C++");
    }
    return lang;
}

// ================================================================ ошибки языка

struct LanguageRule
{
    const char* language;   // подстрока названия языка (C# и VB — «.NET» через lang.dotnet)
    const char* pattern;    // строка в нижнем регистре
    const char* cwe;
    const char* cweName;
    const char* incident;
    Severity severity;
    const char* recommendation;
};

const vector<LanguageRule> LANGUAGE_RULES = {
    { ".NET", "binaryformatter", "CWE-502", "Deserialization of Untrusted Data", "Выполнение кода при десериализации данных", HIGH,
      "Заменить BinaryFormatter на System.Text.Json или DataContractSerializer" },
    { ".NET", "netdatacontractserializer", "CWE-502", "Deserialization of Untrusted Data", "Выполнение кода при десериализации данных", HIGH,
      "Не десериализовать недоверенные данные этим классом" },
    { ".NET", "sqlcommand", "CWE-89", "SQL Injection", "Внедрение SQL при сборке запроса из строк", MEDIUM,
      "Использовать параметризованные запросы (SqlParameter)" },
    { ".NET", "processstartinfo", "CWE-78", "OS Command Injection", "Запуск команд с данными пользователя", MEDIUM,
      "Задавать полный путь к программе, не собирать аргументы из ввода" },
    { ".NET", "md5cryptoserviceprovider", "CWE-327", "Use of a Broken or Risky Cryptographic Algorithm", "Слабая криптография", MEDIUM,
      "Заменить MD5 на SHA-256" },
    { ".NET", "descryptoserviceprovider", "CWE-327", "Use of a Broken or Risky Cryptographic Algorithm", "Слабая криптография", MEDIUM,
      "Заменить DES на AES" },
    { "Go", "os/exec", "CWE-78", "OS Command Injection", "Запуск команд с данными пользователя", MEDIUM,
      "Не передавать ввод пользователя в exec.Command" },
    { "Go", "crypto/md5", "CWE-327", "Use of a Broken or Risky Cryptographic Algorithm", "Слабая криптография", MEDIUM,
      "Заменить crypto/md5 на crypto/sha256" },
    { "Go", "crypto/des", "CWE-327", "Use of a Broken or Risky Cryptographic Algorithm", "Слабая криптография", MEDIUM,
      "Заменить crypto/des на crypto/aes" },
    { "Go", "insecureskipverify", "CWE-295", "Improper Certificate Validation", "Отключённая проверка сертификата TLS", HIGH,
      "Не отключать проверку сертификата в tls.Config" },
    { "Rust", "called `option::unwrap()`", "CWE-248", "Uncaught Exception", "Аварийное завершение при значении None", LOW,
      "Обрабатывать Option и Result без unwrap()" },
    { "Rust", "called `result::unwrap()`", "CWE-248", "Uncaught Exception", "Аварийное завершение при ошибке", LOW,
      "Обрабатывать Option и Result без unwrap()" },
    { "Delphi", "strcopy", "CWE-120", "Buffer Copy without Checking Size of Input", "Переполнение буфера", HIGH,
      "Заменить StrCopy на StrLCopy или строки string" },
    { "Delphi", "strcat", "CWE-120", "Buffer Copy without Checking Size of Input", "Переполнение буфера", HIGH,
      "Заменить StrCat на StrLCat или строки string" },
    { "Python", "pickle", "CWE-502", "Deserialization of Untrusted Data", "Выполнение кода при загрузке данных pickle", HIGH,
      "Не загружать pickle из недоверенных источников" },
    { "Python", "subprocess", "CWE-78", "OS Command Injection", "Запуск команд с данными пользователя", MEDIUM,
      "Вызывать subprocess без shell=True, со списком аргументов" },
};

Finding languageFinding(const string& lang, const string& signature, const string& cwe, const string& cweName,
                        const string& incident, Severity sev, const string& recommendation, const string& source)
{
    return { BLOCK_LANG, "Ошибка языка " + lang, signature, cwe, cweName, "", incident, sev, sev, "", 0,
             recommendation, "", source, 1, {} };
}

struct IssueKind
{
    const char* cwe;
    const char* title;
    const char* cweName;
    const char* incident;
    Severity severity;
    const char* recommendation;
};

const vector<IssueKind> ISSUE_KINDS = {
    { "CWE-120", "Копирование строки в буфер стека без проверки размера", "Buffer Copy without Checking Size of Input",
      "Переполнение буфера стека: сбой или выполнение постороннего кода", HIGH,
      "Заменить на функции с указанием размера (strcpy_s, StringCchCopy) или std::string" },
    { "CWE-252", "Не проверяется результат вызова", "Unchecked Return Value",
      "Работа с недействительным описателем, потеря данных при сбое незаметна", MEDIUM,
      "Проверять результат каждого вызова и обрабатывать ошибку" },
    { "CWE-835", "Цикл без условия выхода", "Loop with Unreachable Exit Condition",
      "Бесконечная работа: постоянная нагрузка на процессор и диск", MEDIUM,
      "Добавить условие завершения и паузу между проходами" },
    { "CWE-674", "Рекурсия без ограничения глубины", "Uncontrolled Recursion",
      "Переполнение стека на глубокой вложенности данных", LOW,
      "Ограничить глубину рекурсии или заменить её циклом со стеком" },
};

vector<Finding> languageFindings(const LanguageInfo& lang, const PeInfo& pe, const vector<string>& data, const CodeMap& code)
{
    vector<Finding> found;

    // 1. Ошибки, найденные в машинном коде: сгруппированы по CWE, с адресами
    for (const IssueKind& kind : ISSUE_KINDS)
    {
        Finding f = languageFinding(lang.language, kind.title, kind.cwe, kind.cweName, kind.incident, kind.severity,
                                    kind.recommendation, "машинный код");
        f.hits = 0;
        for (const FunctionInfo& fn : code.functions)
            for (const CodeIssue& issue : fn.issues)
                if (issue.cwe == kind.cwe)
                {
                    f.hits++;
                    if (f.examples.size() < 6)
                        f.examples.push_back(hexVa(issue.addr) + "  " + issue.text);
                }
        if (f.hits > f.examples.size())
            f.note = "показано " + to_string(f.examples.size()) + " из " + to_string(f.hits) + ", часть может относиться к библиотеке CRT";
        if (f.hits > 0)
            found.push_back(f);
    }

    // 2. Типичные ошибки конкретного языка — по строкам
    for (const LanguageRule& rule : LANGUAGE_RULES)
    {
        string family = rule.language;
        bool applies = family == ".NET" ? lang.dotnet : lang.language.find(family) != NPOS;
        string line;
        if (applies && hasString(data, rule.pattern, &line))
        {
            Finding f = languageFinding(lang.language, rule.pattern, rule.cwe, rule.cweName, rule.incident, rule.severity,
                                        rule.recommendation, "строки");
            f.examples.push_back(line.substr(0, 100));
            found.push_back(f);
        }
    }

    // 3. Защиты компилятора и устаревшая среда
    bool nativeCpp = lang.language.rfind("C", 0) == 0 && lang.language != "C#" && !pe.isDotNet;
    if (pe.valid && nativeCpp)
    {
        if (!pe.stackCookie)
            found.push_back(languageFinding(lang.language, "Нет защиты стека /GS", "CWE-693", "Protection Mechanism Failure",
                                            "Переполнение буфера стека не обнаруживается при выполнении", LOW,
                                            "Собирать с ключом /GS", "заголовки PE"));
        if (!pe.is64 && !pe.safeSeh)
            found.push_back(languageFinding(lang.language, "Нет таблицы обработчиков /SAFESEH", "CWE-693", "Protection Mechanism Failure",
                                            "Перехват управления через цепочку обработчиков исключений", LOW,
                                            "Собирать с ключом /SAFESEH", "заголовки PE"));
    }
    if (lang.legacy)
        found.push_back(languageFinding(lang.language, "Устаревшая среда сборки: " + lang.toolchain, "CWE-1104",
                                        "Use of Unmaintained Third Party Components",
                                        "Ошибки среды не исправляются, современные защиты недоступны", lang.language == "Visual Basic 6" ? MEDIUM : LOW,
                                        "Пересобрать современным компилятором или перенести на поддерживаемую платформу", "заголовки PE"));
    return found;
}
