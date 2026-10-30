// windows.h — до common.h: там using namespace std, а в SDK есть свой тип byte
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#endif

#include "console.h"
#include "input.h"
#include "pe.h"
#include "pipeline.h"
#include "report.h"
#include "signatures.h"

#include <iostream>

// ---------------------------------------------------------------- вывод с цветом

enum Color { GRAY = 7, WHITE = 15, CYAN = 11, GREEN = 10, YELLOW = 14, RED = 12, DARK_YELLOW = 6, MAGENTA = 13 };

void setColor(int c)
{
#ifdef _WIN32
    cout.flush();
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), (WORD)c);
#endif
}

void say(const string& text, int c = GRAY)
{
    setColor(c);
    cout << text;
    setColor(GRAY);
}

int severityColor(Severity s)
{
    switch (s)
    {
    case CRITICAL: return RED;
    case HIGH:     return MAGENTA;
    case MEDIUM:   return YELLOW;
    case LOW:      return GREEN;
    default:       return GRAY;
    }
}

void rule()
{
    say("────────────────────────────────────────────────────────────────────────────\n", DARK_YELLOW);
}

string withSpaces(size_t n)
{
    string s = to_string(n), out;
    for (size_t i = 0; i < s.length(); i++)
    {
        if (i && (s.length() - i) % 3 == 0)
            out += ' ';
        out += s[i];
    }
    return out;
}

void printSummary(const Analysis& a, const fs::path& reportFile)
{
    size_t vuln = 0, ioc = 0, fsCount = 0;
    for (const Finding& f : a.findings)
        (f.block == BLOCK_VULN ? vuln : f.block == BLOCK_IOC ? ioc : fsCount)++;

    cout << "\n";
    rule();
    say(" Объект:     ", CYAN); cout << a.inputPath << "  (" << withSpaces(a.fileSize) << " байт";
    if (a.pe.valid)
        cout << ", " << (a.pe.is64 ? "PE32+ " : "PE32 ") << machineName(a.pe.machine)
             << (a.pe.isDotNet ? ", .NET" : "") << (a.pe.isDll ? ", DLL" : ", EXE");
    cout << ")\n";
    say(" SHA-256:    ", CYAN); cout << a.sha256 << "\n";
    say(" Строки:     ", CYAN); cout << a.rawCount << " -> " << a.data.size() << " уникальных после нормализации\n";
    if (a.code.done)
    {
        say(" Код:        ", CYAN);
        cout << "функций " << a.code.functions.size() << ", вызовов с восстановленными аргументами "
             << a.code.resolvedCalls << "\n";
    }
    say(" Находки:    ", CYAN);
    cout << "уязвимости " << vuln << "  ·  индикаторы компрометации " << ioc << "  ·  файловая система " << fsCount << "\n";
    say(" РИСК:       ", CYAN);
    say(severityName(a.overall) + "   " + to_string(a.score) + "/100", severityColor(a.overall));
    cout << "   вероятность инцидента: ";
    say(a.probability + "\n", severityColor(a.overall));
    say(" Вывод:      ", CYAN); say(a.verdict + "\n", WHITE);

    if (!a.behaviors.empty())
    {
        say("\n Цепочки поведения (по машинному коду):\n", CYAN);
        vector<const Behavior*> sorted;
        for (const Behavior& b : a.behaviors)
            sorted.push_back(&b);
        stable_sort(sorted.begin(), sorted.end(), [](const Behavior* x, const Behavior* y) { return x->severity > y->severity; });
        for (const Behavior* b : sorted)
        {
            cout << "   ";
            string sev = severityName(b->severity);
            say(sev + string(9 - sev.length(), ' '), severityColor(b->severity));
            cout << b->title << "  (" << b->attack << ", sub_" << hexPlain(b->func) << ")\n";
        }

        // доказательства самой опасной цепочки — восстановленные вызовы
        const Behavior* top = sorted.front();
        if (!top->evidence.empty())
        {
            say("\n Доказательства «" + top->title + "»:\n", CYAN);
            for (size_t i = 0; i < top->evidence.size() && i < 6; i++)
                cout << "   " << top->evidence[i] << "\n";
        }
    }

    vector<string> iocs = collectIocs(a);
    if (!iocs.empty())
    {
        say("\n Индикаторы для блокировки:\n", CYAN);
        for (const string& i : iocs)
            cout << "   - " << i << "\n";
    }
    say("\n Полный отчёт: ", CYAN); cout << pathToUtf8(reportFile) << "\n";
    rule();
}

#ifdef _WIN32

// ---------------------------------------------------------------- ввод

// Строка из консоли в UTF-8 (ReadConsoleW: пути с кириллицей читаются без искажений)
string readLine()
{
    cout.flush();
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    string line;
    if (GetConsoleMode(in, &mode))
    {
        wchar_t buf[2048];
        DWORD n = 0;
        if (ReadConsoleW(in, buf, 2047, &n, nullptr))
            line = toUtf8(wstring(buf, n));
    }
    else
        getline(cin, line);
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' '))
        line.pop_back();
    size_t first = line.find_first_not_of(' ');
    line = first == NPOS ? "" : line.substr(first);
    // файл, перетащенный в окно, приходит в кавычках
    if (line.length() >= 2 && line.front() == '"' && line.back() == '"')
        line = line.substr(1, line.length() - 2);
    return line;
}

fs::path chooseFileDialog()
{
    wchar_t file[MAX_PATH * 4] = L"";
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = GetConsoleWindow();
    ofn.lpstrFilter = L"Исполняемые файлы и архивы (*.exe;*.dll;*.bin;*.rar;*.zip;*.7z)\0*.exe;*.dll;*.bin;*.rar;*.zip;*.7z\0"
                      L"Исполняемые файлы (*.exe;*.dll;*.bin)\0*.exe;*.dll;*.bin\0"
                      L"Архивы с образцами (*.rar;*.zip;*.7z)\0*.rar;*.zip;*.7z\0"
                      L"Все файлы (*.*)\0*.*\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH * 4;
    ofn.lpstrTitle = L"ExeIAS — выберите файл для проверки";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    return GetOpenFileNameW(&ofn) ? fs::path(file) : fs::path();
}

// Выбор файла внутри архива: один — сразу, несколько — по номеру
bool pickFromArchive(const fs::path& archive, string& member)
{
    string error;
    vector<string> names = listArchive(archive, error);
    if (names.empty())
    {
        say(" Ошибка: " + error + "\n", RED);
        return false;
    }
    if (names.size() == 1)
    {
        member = names[0];
        return true;
    }
    say(" В архиве несколько файлов:\n", CYAN);
    for (size_t i = 0; i < names.size(); i++)
        cout << "   " << i + 1 << ") " << names[i] << "\n";
    say(" Номер файла: ", WHITE);
    string answer = readLine();
    size_t k = 0;
    for (char c : answer)
        if (c >= '0' && c <= '9')
            k = k * 10 + (c - '0');
    if (k < 1 || k > names.size())
    {
        say(" Неверный номер\n", RED);
        return false;
    }
    member = names[k - 1];
    return true;
}

// ---------------------------------------------------------------- проверка одного объекта

void checkPath(const fs::path& path, const fs::path& selfPath)
{
    vector<unsigned char> bytes;
    string error;
    RunOptions options;
    options.selfPath = selfPath;
    options.outDir = selfPath.parent_path() / L"reports";

    if (isArchive(path))
    {
        string member;
        if (!pickFromArchive(path, member))
            return;
        say(" Чтение «" + member + "» из архива в память (на диск не распаковывается)...\n", GRAY);
        if (!readFromArchive(path, member, bytes, error))
        {
            say(" Ошибка: " + error + "\n", RED);
            return;
        }
        options.displayPath = member + " (из архива " + pathToUtf8(path.filename()) + ")";
        options.name = pathToUtf8(pathFromUtf8(member).filename());
    }
    else
    {
        if (!readFile(path, bytes, error))
        {
            say(" Ошибка: " + error + "\n", RED);
            return;
        }
        options.displayPath = pathToUtf8(path);
        options.name = pathToUtf8(path.filename());
        options.sourcePath = path;
    }

    say(" Анализ...\n", GRAY);
    Analysis a;
    RunFiles files;
    runAnalysis(bytes, options, a, files);
    printSummary(a, files.report);

    say(" [1] открыть отчёт в Блокноте   [2] открыть папку с отчётами   [Enter] вернуться в меню: ", WHITE);
    string choice = readLine();
    if (choice == "1")
        ShellExecuteW(nullptr, L"open", L"notepad.exe", files.report.c_str(), nullptr, SW_SHOWNORMAL);
    else if (choice == "2")
    {
        wstring args = L"/select,\"" + files.report.wstring() + L"\"";
        ShellExecuteW(nullptr, L"open", L"explorer.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
    }
}

int runInteractive(const fs::path& selfPath)
{
    SetConsoleTitleW(L"ExeIAS — окно проверки исполняемых файлов");
    say("\n  ИАС безопасности анализа исполняемых файлов — ExeIAS\n", WHITE);
    say("  Курсовая работа «Анализ взаимодействия вредоносной программы с файловой системой»\n", GRAY);
    say("  Файл никогда не запускается: анализ статический (заголовки PE, строки, машинный код)\n", GRAY);

    while (true)
    {
        cout << "\n";
        rule();
        say("  1", YELLOW); cout << " — выбрать файл в окне проводника (.exe, .dll, .bin или архив с образцом)\n";
        say("  2", YELLOW); cout << " — ввести путь вручную (можно перетащить файл в это окно)\n";
        say("  0", YELLOW); cout << " — выход\n";
        say("  Образец ВПО проверяйте из архива (.rar / .zip): он читается в память без распаковки.\n", GRAY);
        rule();
        say(" Выбор: ", WHITE);
        string choice = readLine();

        fs::path path;
        if (choice == "0" || choice == "q" || choice == "й")
            return 0;
        if (choice == "1")
        {
            path = chooseFileDialog();
            if (path.empty())
                continue;
        }
        else if (choice == "2")
        {
            say(" Путь к файлу: ", WHITE);
            string typed = readLine();
            if (typed.empty())
                continue;
            path = pathFromUtf8(typed);
        }
        else if (choice.length() > 2)
            path = pathFromUtf8(choice);     // сразу перетащили файл в окно вместо номера пункта
        else
            continue;

        say(" Файл: " + pathToUtf8(path) + "\n", GRAY);
        checkPath(path, selfPath);
    }
}

#else

int runInteractive(const fs::path&)
{
    cout << "Окно проверки доступно только в Windows\n";
    return 1;
}

#endif
