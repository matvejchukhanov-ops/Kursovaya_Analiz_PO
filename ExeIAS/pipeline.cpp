// windows.h — до common.h: там using namespace std, а в SDK есть свой тип byte
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#endif

#include "pipeline.h"
#include "economics.h"
#include "fsanalysis.h"
#include "input.h"
#include "language.h"
#include "pe.h"
#include "report.h"
#include "signatures.h"

#include <fstream>

void runAnalysis(const vector<unsigned char>& bytes, const RunOptions& options, Analysis& a, RunFiles& files)
{
    a = Analysis();
    a.inputPath = options.displayPath;
    a.name = options.name;
    a.fileSize = bytes.size();
#ifdef _WIN32
    a.md5 = hashOf(bytes, BCRYPT_MD5_ALGORITHM);
    a.sha1 = hashOf(bytes, BCRYPT_SHA1_ALGORITHM);
    a.sha256 = hashOf(bytes, BCRYPT_SHA256_ALGORITHM);
#endif

    // 1. Разбор PE и извлечение строк (strings.exe, если есть и файл лежит на диске, иначе встроенный метод)
    a.pe = parsePe(bytes);
    vector<FoundString> found = extractStrings(bytes, MIN_LENGTH);
    vector<string> raw;
    fs::path utility = options.internalOnly || options.sourcePath.empty() ? fs::path() : findStringsUtility(options.selfPath, options.sourcePath);
    if (!utility.empty())
        raw = runStringsUtility(utility, options.sourcePath);
    if (!raw.empty())
        a.stringsSource = "утилита " + pathToUtf8(utility.filename());
    else
    {
        for (const FoundString& s : found)
            raw.push_back(s.text);
        a.stringsSource = "встроенный метод (ASCII + UTF-16LE, от 4 символов)";
    }
    a.rawCount = raw.size();

    string safeName = a.name;
    for (char& c : safeName)
        if (c == ' ' || c == ':' || c == '\\' || c == '/' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|')
            c = '_';
    error_code ec;
    if (!options.outDir.empty())
        fs::create_directories(options.outDir, ec);
    files.strings = options.outDir / pathFromUtf8("strings_" + safeName + ".txt");
    files.report = options.outDir / pathFromUtf8("report_" + safeName + ".txt");
    files.csv = options.outDir / pathFromUtf8("report_" + safeName + ".csv");
    {
        ofstream txt(files.strings, ios::binary);
        for (const string& s : raw)
            txt << s << "\n";
    }

    // 2. Нормализация
    a.data = normalizeStrings(raw, a.meaningful);

    // 3. Многоуровневая классификация
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

    // 4. Взаимодействие с файловой системой: разбор машинного кода
    //    (строки от 1 символа — для аргументов вроде fopen(..., "w"))
    a.code = analyzeCode(bytes, a.pe, extractStrings(bytes, 1));
    a.behaviors = detectBehaviors(a.code);
    append(behaviorFindings(a.behaviors));
    append(importOnlyFsFindings(a.pe, !a.behaviors.empty()));

    // 5. Язык программирования и ошибки в коде
    a.lang = detectLanguage(a.pe, a.data);
    append(languageFindings(a.lang, a.pe, a.data, a.code));

    // 6. Контекст происхождения, оценка риска и экономической опасности
    a.context = applyContext(a.data, a.findings);
    stable_sort(a.findings.begin(), a.findings.end(),
                [](const Finding& x, const Finding& y) { return x.severity > y.severity; });
    assessRisk(a);
    if (!options.selfPath.empty())
        a.profile = loadProfile(options.selfPath.parent_path() / L"economics.ini");
    assessEconomics(a);

    // 7. Отчёт
    writeReport(files.report, a);
    writeCsv(files.csv, a.findings);
}
