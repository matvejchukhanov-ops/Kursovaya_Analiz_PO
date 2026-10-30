// Курсовая работа «Анализ взаимодействия вредоносной программы с файловой системой»
// Информационно-аналитическая система (ИАС) безопасности анализа исполняемых файлов
// (ТЗ практической работы №8, на основе IncidentMap из ПР №7)
//
// Запуск без аргументов (из Visual Studio или двойным щелчком) — окно проверки с меню.
// Запуск с аргументами:
//   ExeIAS.exe файл.exe                       — файл на диске (.exe, .dll, .bin)
//   ExeIAS.exe образец.rar [--member имя]      — файл из архива, читается в память без распаковки
//   tar -xOf образец.rar файл.exe | ExeIAS.exe - --name файл.exe   — стандартный ввод (cmd)
// Выход: report_<имя>.txt  — аналитический отчёт (Объект анализа, Признаки уязвимостей,
//                            Индикаторы компрометации, Взаимодействие с ФС, Оценка риска, Рекомендации)
//        report_<имя>.csv  — все находки таблицей
//        strings_<имя>.txt — извлечённые строки (как file3.txt в ПР №3)
//
// Файл НИКОГДА не запускается: анализ чисто статический — заголовки PE, таблица импорта,
// строки и разбор машинного кода с восстановлением аргументов вызовов WinAPI.
//
// Модули:
//   input       — приём файла (диск, архив, стандартный ввод), хэши, строки, нормализация (раздел 2.1)
//   pe          — разбор заголовков PE и таблицы импорта
//   disasm      — декодер инструкций x86 / x64
//   fsanalysis  — анализ взаимодействия с файловой системой по машинному коду
//   signatures  — расширенная матрица сигнатур, CWE / CVE / ATT&CK (раздел 2.2)
//   report      — оценка риска и отчёт (раздел 2.3)
//   pipeline    — порядок работы модулей
//   console     — окно проверки

// windows.h — до common.h: там using namespace std, а в SDK есть свой тип byte
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include "common.h"
#include "console.h"
#include "input.h"
#include "pipeline.h"

#include <iostream>

void printUsage()
{
    cout << "Использование: ExeIAS.exe [<файл .exe/.dll/.bin или архив .rar/.zip>] [--member имя] [--name имя] [--internal]\n"
         << "  без аргументов  окно проверки с меню\n"
         << "  архив           файл из архива читается в память, на диск не распаковывается\n"
         << "  --member        какой файл взять из архива (если в нём несколько)\n"
         << "  -               читать файл из стандартного ввода (tar -xOf архив файл | ExeIAS.exe -)\n"
         << "  --name          имя объекта в отчёте (для стандартного ввода)\n"
         << "  --internal      не вызывать strings.exe, извлекать строки встроенным методом\n";
}

fs::path selfPath()
{
#ifdef _WIN32
    wchar_t buf[MAX_PATH * 4];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH * 4);
    return fs::path(wstring(buf, n));
#else
    return fs::path();
#endif
}

#ifdef _WIN32
int wmain(int argc, wchar_t* argv[])
#else
int main(int argc, char* argv[])
#endif
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    fs::path self = selfPath();
    if (argc < 2)
        return runInteractive(self);

    vector<string> args;
    for (int i = 1; i < argc; i++)
#ifdef _WIN32
        args.push_back(toUtf8(argv[i]));
#else
        args.push_back(argv[i]);
#endif
    if (args[0] == "-h" || args[0] == "--help" || args[0] == "/?")
    {
        printUsage();
        return 0;
    }

    RunOptions options;
    options.selfPath = self;
    options.outDir = fs::current_path();
    string member;
    for (size_t i = 1; i < args.size(); i++)
    {
        if (args[i] == "--internal")
            options.internalOnly = true;
        else if (args[i] == "--name" && i + 1 < args.size())
            options.name = args[++i];
        else if (args[i] == "--member" && i + 1 < args.size())
            member = args[++i];
    }

    // 1. Приём входных данных: стандартный ввод, архив или файл на диске
    vector<unsigned char> bytes;
    string error;
    fs::path input = pathFromUtf8(args[0]);
    bool ok;
    if (args[0] == "-")
    {
        ok = readStdin(bytes, error);
        if (options.name.empty())
            options.name = "stdin";
        options.displayPath = options.name + " (стандартный ввод)";
    }
    else if (isArchive(input))
    {
        if (member.empty())
        {
            vector<string> names = listArchive(input, error);
            if (names.size() > 1)
            {
                cout << "В архиве несколько файлов, укажите нужный ключом --member:\n";
                for (const string& n : names)
                    cout << "  " << n << "\n";
                return 1;
            }
            if (!names.empty())
                member = names[0];
        }
        ok = !member.empty() && readFromArchive(input, member, bytes, error);
        if (options.name.empty())
            options.name = pathToUtf8(pathFromUtf8(member).filename());
        options.displayPath = member + " (из архива " + pathToUtf8(input.filename()) + ")";
    }
    else
    {
        ok = readFile(input, bytes, error);
        string ext = toLower(pathToUtf8(input.extension()));
        if (ok && ext != ".exe" && ext != ".dll" && ext != ".bin")
            cout << "Предупреждение: расширение " << ext << " не входит в список .exe/.dll/.bin, анализ продолжается" << endl;
        if (options.name.empty())
            options.name = pathToUtf8(input.filename());
        options.displayPath = args[0];
        options.sourcePath = input;
    }
    if (!ok)
    {
        cout << "ОШИБКА: " << error << endl;
        return 1;
    }

    // 2–6. Разбор, классификация, анализ кода, оценка риска, отчёт
    Analysis a;
    RunFiles files;
    runAnalysis(bytes, options, a, files);

    printSummary(a, files.report);
    cout << "Таблица: " << pathToUtf8(files.csv) << ", строки: " << pathToUtf8(files.strings) << endl;
    return 0;
}
