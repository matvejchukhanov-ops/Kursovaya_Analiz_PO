// Курсовая работа «Анализ взаимодействия вредоносной программы с файловой системой»
// Информационно-аналитическая система (ИАС) безопасности анализа исполняемых файлов
// (ТЗ практической работы №8, на основе IncidentMap из ПР №7)
//
// Вход:  путь к исполняемому файлу (.exe, .dll, .bin); «-» — читать файл из стандартного ввода,
//        чтобы образец ВПО не распаковывать на диск (tar -xOf архив.rar файл.exe | ExeIAS.exe -)
// Выход: report_<имя>.txt  — аналитический отчёт (Объект анализа, Признаки уязвимостей,
//                            Индикаторы компрометации, Взаимодействие с ФС, Оценка риска, Рекомендации)
//        report_<имя>.csv  — все находки таблицей
//        strings_<имя>.txt — извлечённые строки (как file3.txt в ПР №3)
//
// Файл НИКОГДА не запускается: анализ чисто статический — заголовки PE, таблица импорта,
// строки и разбор машинного кода с восстановлением аргументов вызовов WinAPI.
//
// Модули:
//   input       — приём файла, хэши, извлечение и нормализация строк (раздел 2.1)
//   pe          — разбор заголовков PE и таблицы импорта
//   disasm      — декодер инструкций x86 / x64
//   fsanalysis  — анализ взаимодействия с файловой системой по машинному коду
//   signatures  — расширенная матрица сигнатур, CWE / CVE / ATT&CK (раздел 2.2)
//   report      — оценка риска и отчёт (раздел 2.3)

// windows.h — до common.h: там using namespace std, а в SDK есть свой тип byte
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#endif

#include "common.h"
#include "fsanalysis.h"
#include "input.h"
#include "pe.h"
#include "report.h"
#include "signatures.h"

#include <filesystem>
#include <fstream>
#include <iostream>

namespace fs = std::filesystem;

void printUsage()
{
    cout << "Использование: ExeIAS.exe <путь к файлу .exe/.dll/.bin> [--name имя] [--internal]\n"
         << "  -           читать файл из стандартного ввода (образец не распаковывается на диск)\n"
         << "  --name      имя объекта в отчёте (для стандартного ввода)\n"
         << "  --internal  не вызывать strings.exe, извлекать строки встроенным методом\n";
}

int main(int argc, char* argv[])
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    if (argc < 2)
    {
        printUsage();
        return 1;
    }

    Analysis a;
    a.inputPath = argv[1];
    bool internalOnly = false;
    for (int i = 2; i < argc; i++)
    {
        string arg = argv[i];
        if (arg == "--internal")
            internalOnly = true;
        else if (arg == "--name" && i + 1 < argc)
            a.name = argv[++i];
    }
    bool fromStdin = a.inputPath == "-";

    // 1. Приём входных данных
    vector<unsigned char> bytes;
    string error;
    if (!readInput(a.inputPath, bytes, error))
    {
        cout << "ОШИБКА: " << error << endl;
        return 1;
    }
    if (fromStdin)
    {
        if (a.name.empty())
            a.name = "stdin";
        a.inputPath = a.name + " (стандартный ввод)";
    }
    else
    {
        string ext = toLower(fs::path(a.inputPath).extension().string());
        if (ext != ".exe" && ext != ".dll" && ext != ".bin")
            cout << "Предупреждение: расширение " << ext << " не входит в список .exe/.dll/.bin, анализ продолжается" << endl;
        if (a.name.empty())
            a.name = fs::path(a.inputPath).filename().string();
    }
    a.fileSize = bytes.size();
#ifdef _WIN32
    a.md5 = hashOf(bytes, BCRYPT_MD5_ALGORITHM);
    a.sha1 = hashOf(bytes, BCRYPT_SHA1_ALGORITHM);
    a.sha256 = hashOf(bytes, BCRYPT_SHA256_ALGORITHM);
#endif

    // 2. Разбор PE и извлечение строк (strings.exe, если есть, иначе встроенный метод)
    a.pe = parsePe(bytes);
    vector<FoundString> found = extractStrings(bytes, MIN_LENGTH);
    vector<string> raw;
    string utility = (internalOnly || fromStdin) ? "" : findStringsUtility(argv[0]);
    if (!utility.empty())
        raw = runStringsUtility(utility, a.inputPath);
    if (!raw.empty())
        a.stringsSource = "утилита " + fs::path(utility).filename().string();
    else
    {
        for (const FoundString& s : found)
            raw.push_back(s.text);
        a.stringsSource = "встроенный метод (ASCII + UTF-16LE, от 4 символов)";
    }
    a.rawCount = raw.size();

    string safeName = a.name;
    for (char& c : safeName)
        if (c == ' ' || c == ':' || c == '\\' || c == '/')
            c = '_';
    string stringsFile = "strings_" + safeName + ".txt";
    {
        ofstream txt(stringsFile, ios::binary);
        for (const string& s : raw)
            txt << s << "\n";
    }

    // 3. Нормализация
    a.data = normalizeStrings(raw, a.meaningful);

    // 4. Многоуровневая классификация
    a.meta = collectMetadata(a.data);
    a.errors = collectErrors(a.data);

    a.findings = matchCve(detectLibraries(a.data));
    set<string> confirmedCves;
    for (const Finding& f : a.findings)
        confirmedCves.insert(f.cve);
    auto append = [&](const vector<Finding>& more) { a.findings.insert(a.findings.end(), more.begin(), more.end()); };
    append(matchRules(a.data, a.pe, confirmedCves));
    append(matchNetwork(a.data));
    append(matchPaths(found));
    append(checkPeStructure(a.pe));

    // 5. Взаимодействие с файловой системой: разбор машинного кода
    //    (строки от 1 символа — для аргументов вроде fopen(..., "w"))
    a.code = analyzeCode(bytes, a.pe, extractStrings(bytes, 1));
    a.behaviors = detectBehaviors(a.code);
    append(behaviorFindings(a.behaviors));
    append(importOnlyFsFindings(a.pe, !a.behaviors.empty()));

    // 6. Контекст происхождения и оценка риска
    a.context = applyContext(a.data, a.findings);
    stable_sort(a.findings.begin(), a.findings.end(),
                [](const Finding& x, const Finding& y) { return x.severity > y.severity; });
    assessRisk(a);

    // 7. Отчёт
    string reportFile = "report_" + safeName + ".txt";
    string csvFile = "report_" + safeName + ".csv";
    writeReport(reportFile, a);
    writeCsv(csvFile, a.findings);

    cout << "Объект: " << a.inputPath << " (" << a.fileSize << " байт)" << endl;
    cout << "SHA-256: " << a.sha256 << endl;
    cout << "Строк: " << a.rawCount << " (" << a.stringsSource << "), уникальных после нормализации: " << a.data.size() << endl;
    if (a.code.done)
        cout << "Код: функций " << a.code.functions.size() << ", вызовов с аргументами " << a.code.resolvedCalls
             << ", цепочек поведения " << a.behaviors.size() << endl;
    cout << "Находок: " << a.findings.size() << ", риск: " << severityName(a.overall) << ", балл " << a.score
         << "/100, вероятность инцидента: " << a.probability << endl;
    cout << "Вывод: " << a.verdict << endl;
    cout << "Отчёт: " << reportFile << ", таблица: " << csvFile << ", строки: " << stringsFile << endl;
    return 0;
}
