#include "report.h"
#include "fsanalysis.h"
#include "pe.h"
#include "signatures.h"

#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>

// ================================================================ оценка риска

// Вес находки в балле риска; поведение, подтверждённое машинным кодом, весит вдвое больше
// находок по строкам и импорту — функции двойного назначения есть и в легитимных программах
int weightOf(Severity s)
{
    switch (s)
    {
    case CRITICAL: return 20;
    case HIGH:     return 8;
    case MEDIUM:   return 3;
    case LOW:      return 1;
    default:       return 0;
    }
}

void assessRisk(Analysis& a)
{
    int score = 0;
    bool destroys = false;
    Severity confirmed = NONE;     // максимальная критичность, подтверждённая анализом кода
    set<string> counted;           // однотипная цепочка в нескольких функциях учитывается один раз
    for (const Finding& f : a.findings)
    {
        bool byCode = f.source == "машинный код";
        if (!byCode || counted.insert(f.incident).second)
            score += weightOf(f.severity) * (byCode ? 2 : 1);
        a.overall = max(a.overall, f.severity);
        if (byCode)
            confirmed = max(confirmed, f.severity);
    }
    for (const Behavior& b : a.behaviors)
        if (b.code == "DESTROY")
            destroys = true;
    if (!a.context.empty() && a.behaviors.empty())
        score /= 2;               // признаки легитимного загрузчика .NET
    a.score = min(score, 100);

    a.probability = a.score == 0 ? "минимальная" : a.score < 20 ? "низкая" : a.score < 45 ? "средняя"
                  : a.score < 70 ? "высокая" : "очень высокая";

    if (a.findings.empty())
        a.verdict = "признаков инцидентов ИБ не обнаружено";
    else if (destroys)
        a.verdict = "файл содержит код уничтожения данных — вредоносная программа деструктивного типа (троян-вайпер); запуск недопустим";
    else if (confirmed >= HIGH || (a.overall >= HIGH && a.score >= 45))
        a.verdict = "обнаружены признаки опасных инцидентов, файл требует углублённого (динамического) анализа в изолированной среде";
    else if (a.overall >= HIGH && a.context.empty())
        a.verdict = "обнаружены функции двойного назначения (запуск процессов, реестр и т.п.), но в коде опасные цепочки "
                    "не подтверждены — вредоносность не установлена, рекомендуется проверка";
    else if (!a.context.empty())
        a.verdict = "обнаружены потенциальные слабые места, но по мета-данным это стандартное приложение .NET, а не вредоносное ПО";
    else
        a.verdict = "обнаружены потенциальные слабые места, рекомендуется проверка";
}

// ================================================================ отчёт

string formatCvss(double cvss)
{
    if (cvss <= 0)
        return "-";
    ostringstream ss;
    ss << fixed << setprecision(1) << cvss;
    return ss.str();
}

// Поле CSV: в кавычках, кавычки удваиваются. Строки из исследуемого файла вида «=HYPERLINK(...)»
// получают апостроф, чтобы Excel не выполнил их как формулу
string csvField(string s)
{
    for (size_t i = 0; i < s.length(); i++)
        if (s[i] == '\n' || s[i] == '\r')
            s[i] = ' ';
    if (!s.empty() && strchr("=+-@\t", s[0]))
        s = "'" + s;
    string out = "\"";
    for (char c : s)
        out += c == '"' ? string("\"\"") : string(1, c);
    return out + "\"";
}

void writeList(ofstream& out, const string& title, const vector<string>& items, size_t limit = 15)
{
    out << title << " (" << items.size() << "):\n";
    for (size_t i = 0; i < items.size() && i < limit; i++)
        out << "  - " << items[i] << "\n";
    if (items.size() > limit)
        out << "  ... ещё " << items.size() - limit << "\n";
    if (items.empty())
        out << "  нет\n";
}

void writeFinding(ofstream& out, size_t n, const Finding& f)
{
    out << "[" << n << "] " << f.signature << "\n";
    out << "    Категория:       " << f.category << "  (источник: " << f.source << ")\n";
    if (!f.cwe.empty())
        out << "    CWE:             " << f.cwe << (f.cweName.empty() ? "" : " (" + f.cweName + ")") << "\n";
    if (!f.attack.empty())
        out << "    MITRE ATT&CK:    " << f.attack << "\n";
    out << "    Тип инцидента:   " << f.incident << "\n";
    out << "    Критичность:     " << severityName(f.severity);
    if (f.severity != f.baseSeverity)
        out << " (базовая " << severityName(f.baseSeverity) << ")";
    out << "\n";
    if (!f.cve.empty())
        out << "    CVE:             " << f.cve << ", CVSS " << formatCvss(f.cvss) << "\n";
    if (f.hits > 1)
        out << "    Совпадений:      " << f.hits << "\n";
    for (const string& e : f.examples)
        out << "    Признак:         " << e << "\n";
    if (!f.note.empty())
        out << "    Пояснение:       " << f.note << "\n";
    out << "\n";
}

// Функция стоит показа в карте: у неё есть роль или вызовы ФС / реестра / запуска
bool isInteresting(const FunctionInfo& f, const map<uint64_t, vector<string>>& roles)
{
    if (roles.count(f.start))
        return true;
    auto relevant = [](const string& api)
    {
        bool lowLevel = false;
        return (!fsOpOf(api, lowLevel).empty() && !lowLevel) || api.rfind("Reg", 0) == 0;
    };
    for (const CodeRef& r : f.refs)
        if (r.isApi && relevant(r.text))
            return true;
    for (const CallSite& c : f.calls)
        if (c.isApi && relevant(c.target))
            return true;
    return false;
}

// Строка карты функции: адрес, вызов с аргументами или ссылка на строку
struct MapLine
{
    uint64_t addr;
    string text;
};

vector<MapLine> functionLines(const FunctionInfo& f, const set<uint64_t>& shown)
{
    vector<MapLine> lines;
    if (f.decoded)
    {
        for (const CallSite& c : f.calls)
        {
            bool showInternal = false;
            if (!c.isApi)
            {
                showInternal = shown.count(c.targetVa) > 0;
                for (const Value& v : c.args)
                    if (v.kind == V_STRING || (v.kind == V_LOCAL && !v.content.empty()))
                        showInternal = true;
            }
            if (!c.isApi && !showInternal)
                continue;
            string text = "CALL   " + formatCall(c);
            bool lowLevel = false;
            string op = c.isApi ? fsOpOf(c.target, lowLevel) : "";
            if (!op.empty())
                text += "   <- " + op;
            string note = callNote(c);
            if (!note.empty())
                text += "\n                       // " + note;
            lines.push_back({ c.addr, text });
        }
        for (const CodeRef& r : f.refs)
            if (!r.isApi)
                lines.push_back({ r.addr, "строка \"" + r.text + "\"" });
    }
    else
        for (const CodeRef& r : f.refs)
        {
            bool lowLevel = false;
            string op = r.isApi ? fsOpOf(r.text, lowLevel) : "";
            lines.push_back({ r.addr, (r.isApi ? "API    " + r.text : "строка \"" + r.text + "\"")
                                      + (op.empty() ? "" : "   <- " + op) });
        }
    stable_sort(lines.begin(), lines.end(), [](const MapLine& x, const MapLine& y) { return x.addr < y.addr; });
    return lines;
}

void writeFsBlock(ofstream& out, const Analysis& a)
{
    out << "================ 4. ВЗАИМОДЕЙСТВИЕ С ФАЙЛОВОЙ СИСТЕМОЙ ================\n";

    // 4.1 Операции по таблице импорта и количество мест вызова в коде
    out << "4.1 Операции с ФС (таблица импорта -> места вызова в коде)\n";
    for (int op = 0; op < FS_OP_COUNT; op++)
    {
        vector<string> items;
        for (const ImportDll& d : a.pe.imports)
            for (const ImportFunc& f : d.funcs)
                for (const FsApi& api : FS_APIS)
                    if (api.op == op && apiMatches(f.name, api.stem))
                    {
                        size_t sites = 0;
                        for (const FunctionInfo& fn : a.code.functions)
                        {
                            size_t byCalls = 0, byRefs = 0;
                            for (const CallSite& c : fn.calls)
                                if (c.isApi && c.target == f.name)
                                    byCalls++;
                            for (const CodeRef& r : fn.refs)
                                if (r.isApi && r.text == f.name)
                                    byRefs++;
                            sites += max(byCalls, byRefs);
                        }
                        items.push_back(f.name + " x" + to_string(sites) + (api.lowLevel ? " (используется и CRT)" : ""));
                    }
        if (items.empty())
            continue;
        out << "  " << FS_OP_NAMES[op] << ":\n";
        for (const string& s : items)
            out << "      " << s << "\n";
    }
    out << "\n";

    if (!a.code.done)
    {
        out << "Анализ машинного кода не выполнялся: " << a.code.note << "\n\n";
        return;
    }
    if (!a.code.note.empty())
        out << "Примечание: " << a.code.note << "\n";
    out << "Найдено функций: " << a.code.functions.size() << ", разобрано декодером: " << a.code.decodedFunctions
        << ", вызовов с восстановленными аргументами: " << a.code.resolvedCalls << "\n";
    out << "Обозначения: var_N — буфер в стеке функции, arg_N — её аргумент, sub_N — внутренняя функция,\n"
        << "             <...> — значение, известное по смыслу (результат API), ? — не удалось восстановить\n\n";

    map<uint64_t, vector<string>> roles;
    for (const Behavior& b : a.behaviors)
        addUnique(roles[b.func], b.title);

    set<uint64_t> shown;
    for (const FunctionInfo& f : a.code.functions)
        if (isInteresting(f, roles))
            shown.insert(f.start);

    // 4.2 Карта функций с восстановленными вызовами
    out << "4.2 Карта функций (адрес -> вызов с аргументами или ссылка на строку)\n";
    for (const FunctionInfo& f : a.code.functions)
    {
        if (!shown.count(f.start))
            continue;
        out << "  Функция sub_" << hexPlain(f.start);
        if (f.recursive)
            out << "  [рекурсивная]";
        out << "\n";
        if (roles.count(f.start))
            for (const string& r : roles[f.start])
                out << "    роль: " << r << "\n";
        for (const MapLine& line : functionLines(f, shown))
            out << "    " << hexVa(line.addr) << "  " << line.text << "\n";
        out << "\n";
    }
    if (shown.empty())
        out << "  функций, работающих с файловой системой, не найдено\n\n";

    // 4.3 Восстановленный сценарий: дерево вызовов между найденными функциями
    out << "4.3 Восстановленный сценарий (граф вызовов)\n";
    set<uint64_t> called;
    for (const FunctionInfo& f : a.code.functions)
        if (shown.count(f.start))
            for (uint64_t c : f.callees)
                if (c != f.start && shown.count(c))
                    called.insert(c);
    auto label = [&](uint64_t start)
    {
        string s = "sub_" + hexPlain(start);
        if (roles.count(start))
        {
            s += "  [";
            for (size_t i = 0; i < roles.at(start).size(); i++)
                s += (i ? "; " : "") + roles.at(start)[i];
            s += "]";
        }
        return s;
    };
    for (const FunctionInfo& f : a.code.functions)
    {
        if (!shown.count(f.start) || called.count(f.start))
            continue;
        out << "  " << label(f.start) << "\n";
        for (uint64_t c : f.callees)
            if (c != f.start && shown.count(c))
            {
                bool recursive = false;
                for (const FunctionInfo& g : a.code.functions)
                    if (g.start == c)
                        recursive = g.recursive;
                out << "    └─ " << label(c) << (recursive ? "  (вызывает сама себя)" : "") << "\n";
            }
    }
    if (shown.empty())
        out << "  нет\n";
    out << "\n";

    // 4.4 Цепочки поведения
    size_t n = 0;
    out << "4.4 Цепочки поведения (" << a.behaviors.size() << ")\n\n";
    for (const Finding& f : a.findings)
        if (f.block == BLOCK_FS)
            writeFinding(out, ++n, f);
    if (n == 0)
        out << "  нет\n\n";
}

vector<string> collectIocs(const Analysis& a)
{
    vector<string> iocs;
    if (a.overall < HIGH)
        return iocs;
    iocs.push_back("SHA-256 " + a.sha256);
    for (const Behavior& b : a.behaviors)
        for (const string& i : b.iocs)
            addUnique(iocs, i);
    for (const Finding& f : a.findings)
        if (f.signature == "Файл в корне диска")
            for (const string& e : f.examples)
            {
                bool known = false;
                for (const string& i : iocs)
                    if (i.find("\"" + e + "\"") != NPOS)
                        known = true;
                if (!known)
                    iocs.push_back("файл \"" + e + "\"");
            }
    return iocs;
}

void writeReport(const fs::path& path, const Analysis& a)
{
    ofstream out(path, ios::binary);
    out << "\xEF\xBB\xBF";   // UTF-8 BOM, чтобы Блокнот и Word показали кириллицу

    out << "ОТЧЁТ ИАС БЕЗОПАСНОСТИ: АНАЛИЗ ИСПОЛНЯЕМОГО ФАЙЛА\n";
    out << "======================================================================\n\n";

    // ---------- 1. Объект анализа
    const PeInfo& pe = a.pe;
    out << "================ 1. ОБЪЕКТ АНАЛИЗА ================\n";
    out << "Файл:                 " << a.inputPath << "\n";
    out << "Размер:               " << a.fileSize << " байт\n";
    out << "MD5:                  " << a.md5 << "\n";
    out << "SHA-1:                " << a.sha1 << "\n";
    out << "SHA-256:              " << a.sha256 << "\n";
    if (pe.valid)
    {
        out << "Формат:               " << (pe.is64 ? "PE32+" : "PE32") << (pe.isDll ? ", библиотека DLL" : ", программа EXE")
            << (pe.isDotNet ? ", сборка .NET" : ", машинный код") << "\n";
        out << "Архитектура:          " << machineName(pe.machine) << "\n";
        out << "Подсистема:           " << subsystemName(pe.subsystem) << "\n";
        out << "Дата компиляции:      " << formatTime(pe.timestamp) << "\n";
        out << "Версия компоновщика:  " << pe.linker << "\n";
        out << "База образа:          " << hexVa(pe.imageBase) << "\n";
        out << "Точка входа:          " << hexVa(pe.imageBase + pe.entryRva) << " (RVA " << hexVa(pe.entryRva) << ")\n";
        out << "Оверлей:              " << (pe.overlay ? to_string(pe.overlay) + " байт" : string("нет")) << "\n\n";

        out << "Секции:\n";
        out << "  Имя        VirtAddr    VirtSize    RawSize     Права  Энтропия\n";
        for (const Section& s : pe.sections)
        {
            string rights;
            rights += (s.chars & 0x40000000) ? 'R' : '-';
            rights += (s.chars & 0x80000000) ? 'W' : '-';
            rights += (s.chars & 0x20000000) ? 'X' : '-';
            out << "  " << left << setw(10) << s.name << " " << setw(11) << hexVa(s.va) << " " << setw(11) << hexVa(s.vsize)
                << " " << setw(11) << hexVa(s.rawSize) << " " << setw(6) << rights << " " << right << fixed
                << setprecision(2) << s.entropy << "\n";
        }
        out << "\nИмпорт:\n";
        for (const ImportDll& d : pe.imports)
            out << "  " << d.name << ": " << d.funcs.size() << " функций\n";
        if (pe.imports.empty())
            out << "  таблица импорта пуста\n";
    }
    else
        out << "Формат:               " << pe.error << "\n";
    out << "\nСтроки: " << a.stringsSource << "; прочитано " << a.rawCount << ", после нормализации "
        << a.meaningful << ", уникальных " << a.data.size() << "\n\n";

    out << "Мета-данные:\n";
    writeList(out, "  Имена DLL", a.meta.dlls);
    writeList(out, "  Имена файлов", a.meta.files);
    writeList(out, "  Пути", a.meta.paths);
    writeList(out, "  Строки с номерами версий", a.meta.versions, 8);
    writeList(out, "  Разработчик / компилятор", a.meta.developers, 8);
    out << "Контекст происхождения:\n";
    for (const string& c : a.context)
        out << "  + " << c << "\n";
    if (a.context.empty())
        out << "  признаков легитимного загрузчика (.NET apphost) не найдено\n";
    out << "\n";

    // ---------- 2. Признаки уязвимостей
    out << "================ 2. ПРИЗНАКИ УЯЗВИМОСТЕЙ (CWE / CVE) ================\n";
    writeList(out, "Ошибки и исключения в строках", a.errors, 12);
    out << "\n";
    size_t n = 0;
    for (const Finding& f : a.findings)
        if (f.block == BLOCK_VULN)
            writeFinding(out, ++n, f);
    if (n == 0)
        out << "  нет\n\n";

    // ---------- 3. Индикаторы компрометации
    out << "================ 3. ИНДИКАТОРЫ КОМПРОМЕТАЦИИ (IOC) ================\n";
    n = 0;
    for (const Finding& f : a.findings)
        if (f.block == BLOCK_IOC)
            writeFinding(out, ++n, f);
    if (n == 0)
        out << "  нет\n\n";

    // ---------- 4. Файловая система
    writeFsBlock(out, a);

    // ---------- 5. Оценка риска
    size_t bySeverity[5] = { 0 };
    for (const Finding& f : a.findings)
        bySeverity[f.severity]++;
    out << "================ 5. ОЦЕНКА РИСКА ================\n";
    out << "CRITICAL: " << bySeverity[CRITICAL] << "   HIGH: " << bySeverity[HIGH] << "   MEDIUM: " << bySeverity[MEDIUM]
        << "   LOW: " << bySeverity[LOW] << "\n";
    out << "Общий уровень риска:              " << severityName(a.overall) << "\n";
    out << "Балл риска:                       " << a.score << " / 100\n";
    out << "Вероятность инцидента ИБ:         " << a.probability << "\n";
    out << "Вывод: " << a.verdict << "\n\n";

    // ---------- 6. Рекомендации
    out << "================ 6. РЕКОМЕНДАЦИИ ================\n";
    vector<string> recs;
    for (int s = CRITICAL; s >= LOW; s--)
        for (const Finding& f : a.findings)
            if (f.severity == s && !f.recommendation.empty())
                addUnique(recs, "[" + severityName(f.severity) + "] " + f.recommendation);
    for (size_t i = 0; i < recs.size(); i++)
        out << i + 1 << ". " << recs[i] << "\n";
    if (recs.empty())
        out << "Специальных мер не требуется\n";

    vector<string> iocs = collectIocs(a);
    if (!iocs.empty())
    {
        out << "\nИндикаторы для блокировки и поиска на других узлах:\n";
        for (const string& s : iocs)
            out << "  - " << s << "\n";
    }
}

bool writeCsv(const fs::path& path, const vector<Finding>& findings)
{
    ofstream csv(path, ios::binary);
    if (!csv.is_open())
        return false;
    csv << "\xEF\xBB\xBF";   // BOM — Excel откроет кириллицу без перекодировки
    csv << "№;Блок;Категория;Сигнатура;CWE;MITRE ATT&CK;Тип инцидента;Критичность;CVE;CVSS;Источник;Признак;Рекомендация\n";
    for (size_t i = 0; i < findings.size(); i++)
    {
        const Finding& f = findings[i];
        auto orDash = [](const string& s) { return s.empty() ? string("-") : csvField(s); };
        csv << i + 1 << ";" << csvField(f.block) << ";" << csvField(f.category) << ";" << csvField(f.signature) << ";"
            << orDash(f.cwe) << ";" << orDash(f.attack) << ";"
            << csvField(f.incident) << ";" << severityName(f.severity) << ";" << orDash(f.cve) << ";"
            << formatCvss(f.cvss) << ";" << csvField(f.source) << ";" << csvField(f.examples.empty() ? "" : f.examples[0]) << ";"
            << csvField(f.recommendation) << "\n";
    }
    return true;
}
