// Самотест окна: собирается только с EXEIAS_SELFTEST (tests\gui_selftest.bat).
// Работает внутри процесса: шлёт окну настоящие сообщения мыши и клавиатуры и проверяет состояние.
// Аргументы: журнал, архив с Whiter.a, временная папка. Внешние программы не запускаются, образец на диск не пишется.

#include <random>

struct SelfTest
{
    ofstream log;
    int passed = 0, failed = 0;

    void check(const string& name, bool ok, const string& detail = "")
    {
        (ok ? passed : failed)++;
        log << (ok ? "PASS " : "FAIL ") << name << (detail.empty() ? "" : "  [" + detail + "]") << "\n";
        log.flush();
    }
} T;

void pump(int ms)
{
    DWORD end = GetTickCount() + ms;
    MSG m;
    do
    {
        while (PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
        Sleep(5);
    } while ((int)(end - GetTickCount()) > 0);
}

void paintNow()
{
    InvalidateRect(app.hwnd, nullptr, FALSE);
    UpdateWindow(app.hwnd);
}

bool waitJob(int seconds = 90)
{
    DWORD end = GetTickCount() + seconds * 1000;
    while (app.screen == S_BUSY && (int)(end - GetTickCount()) > 0)
        pump(20);
    paintNow();
    return app.screen != S_BUSY;
}

bool hasHit(int id)
{
    paintNow();
    for (const Hit& h : app.hits)
        if (h.id == id)
            return true;
    return false;
}

LPARAM pointOf(const Hit& h)
{
    int x = (int)((h.r.left + h.r.right) / 2 * app.dpi / 96), y = (int)((h.r.top + h.r.bottom) / 2 * app.dpi / 96);
    return MAKELPARAM(x, y);
}

bool click(int id)
{
    paintNow();
    for (const Hit& h : app.hits)
        if (h.id == id)
        {
            LPARAM p = pointOf(h);
            SendMessageW(app.hwnd, WM_MOUSEMOVE, 0, p);
            SendMessageW(app.hwnd, WM_LBUTTONDOWN, MK_LBUTTON, p);
            SendMessageW(app.hwnd, WM_LBUTTONUP, 0, p);
            paintNow();
            return true;
        }
    return false;
}

void key(WPARAM vk)
{
    SendMessageW(app.hwnd, WM_KEYDOWN, vk, 0);
    paintNow();
}

void wheel(int notches)
{
    SendMessageW(app.hwnd, WM_MOUSEWHEEL, MAKEWPARAM(0, (short)(notches * 120)), 0);
    paintNow();
}

void resizeClient(int w, int h)
{
    SetWindowPos(app.hwnd, nullptr, 0, 0, w, h, SWP_NOMOVE | SWP_NOZORDER);
    pump(30);
    paintNow();
}

void drop(const fs::path& path)
{
    wstring p = path.wstring();
    size_t bytes = sizeof(DROPFILES) + (p.length() + 2) * sizeof(wchar_t);
    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, bytes);
    DROPFILES* d = (DROPFILES*)GlobalLock(mem);
    d->pFiles = sizeof(DROPFILES);
    d->fWide = TRUE;
    memcpy((char*)d + sizeof(DROPFILES), p.c_str(), p.length() * sizeof(wchar_t));
    GlobalUnlock(mem);
    SendMessageW(app.hwnd, WM_DROPFILES, (WPARAM)mem, 0);
}

wstring readClipboard()
{
    wstring out;
    // буфер может быть на мгновение занят журналом буфера обмена Windows
    bool opened = false;
    for (int attempt = 0; attempt < 40 && !opened; attempt++)
    {
        opened = OpenClipboard(app.hwnd) != FALSE;
        if (!opened)
            Sleep(50);
    }
    if (opened)
    {
        HANDLE h = GetClipboardData(CF_UNICODETEXT);
        if (h)
        {
            const wchar_t* s = (const wchar_t*)GlobalLock(h);
            if (s)
                out = s;
            GlobalUnlock(h);
        }
        CloseClipboard();
    }
    return out;
}

// Все разделы и страницы рисуются без сбоев и дают ненулевое содержимое или понятную заглушку
void walkAllTabs(const string& what)
{
    bool ok = true;
    for (int t = 0; t < T_COUNT; t++)
    {
        key('1' + t);
        ok = ok && app.tab == t && !app.items.empty() && std::isfinite(app.pageH);
        wheel(-3);
        ok = ok && app.scroll >= 0 && app.scroll <= max(0.0f, app.pageH - viewH()) + 0.5f;
        key(VK_END);
        key(VK_HOME);
    }
    T.check("все разделы: " + what, ok);
}

// Подпись разработчика видна на всех экранах
bool everyItemInsideWidth()
{
    for (const Item& it : app.items)
        if (it.x + it.w > bodyW() + 20 || it.x < -20)
            return false;
    return true;
}

int runSelfTest(int argc, LPWSTR* argv)
{
    if (argc < 4)
        return 99;
    T.log.open(fs::path(argv[1]), ios::binary);
    T.log << "\xEF\xBB\xBF";
    fs::path sampleRar = argv[2], tmp = argv[3];
    error_code ec;
    fs::create_directories(tmp, ec);

    // ---- стартовый экран
    pump(50);
    paintNow();
    T.check("старт: кнопка «Выбрать файл»", hasHit(H_CHOOSE));
    T.check("старт: 4 пункта меню", hasHit(H_NAV0) && hasHit(H_NAV0 + 1) && hasHit(H_NAV0 + 2) && hasHit(H_NAV0 + 3));
    click(H_CHOOSE);
    T.check("старт: кнопка вызывает выбор файла", app.lastShell == L"choose");
    app.lastShell.clear();
    SendMessageW(app.hwnd, WM_KEYDOWN, 'O', 0);
    T.check("Ctrl+O без Ctrl не срабатывает", app.lastShell.empty());

    // ---- страницы меню
    click(H_NAV0 + 1);
    T.check("меню: Отчёты", app.page == P_REPORTS && !app.items.empty());
    click(H_OPEN_REPORTS);
    T.check("Отчёты: кнопка открывает папку", app.lastShell.find(L"explorer.exe") == 0, toUtf8(app.lastShell));
    click(H_NAV0 + 2);
    T.check("меню: Модель ущерба", app.page == P_MODEL && !app.items.empty());
    T.check("Модель ущерба: вмещается по ширине", everyItemInsideWidth());
    click(H_NAV0 + 3);
    T.check("меню: О программе", app.page == P_ABOUT && !app.items.empty());
    click(H_NAV0);
    T.check("меню: назад к проверке", app.page == P_CHECK && app.screen == S_IDLE);
    key(VK_TAB);
    T.check("Tab: фокус на кнопке", app.focus == H_CHOOSE);
    app.focus = H_NONE;

    // ---- плохие входные данные
    startJob(tmp / L"нет_такого_файла.exe", "");
    T.check("нет файла: задание завершается", waitJob());
    T.check("нет файла: понятная ошибка на старте", app.screen == S_IDLE && !app.errorText.empty(), toUtf8(app.errorText));
    {
        ofstream(tmp / L"empty.bin", ios::binary).close();
        startJob(tmp / L"empty.bin", "");
        waitJob();
        T.check("пустой файл: ошибка или итог без сбоя", app.screen == S_IDLE || app.screen == S_RESULT);
        vector<char> junk(4096);
        mt19937 gen(7);
        for (char& c : junk)
            c = (char)gen();
        ofstream(tmp / L"rand.bin", ios::binary).write(junk.data(), junk.size());
        startJob(tmp / L"rand.bin", "");
        waitJob();
        T.check("случайные байты: итог", app.screen == S_RESULT && app.a && !app.a->pe.valid);
        walkAllTabs("не PE-файл");
    }

    // ---- образец из архива: перетаскивание в окно
    drop(sampleRar);
    T.check("перетаскивание: начат разбор", app.screen == S_BUSY);
    paintNow();
    T.check("разбор: задание завершается", waitJob());
    T.check("Whiter.a: итог получен", app.screen == S_RESULT && app.a);
    if (app.a)
    {
        const Analysis& a = *app.a;
        T.check("Whiter.a: балл 100", a.score == 100, to_string(a.score));
        T.check("Whiter.a: 12 цепочек", a.behaviors.size() == 12);
        T.check("Whiter.a: заголовок", headline(a) == L"Уничтожает данные");
        T.check("Whiter.a: ущерб 1 228 000", (long long)a.economy.lossExpected == 1228000);
        T.check("Whiter.a: язык C", a.lang.language == "C", a.lang.language);
        T.check("формат рублей", rub(1228000) == L"1 228 000 ₽", toUtf8(rub(1228000)));
        walkAllTabs("Whiter.a");

        // раскрытие строк щелчком
        key('1');
        size_t before = app.items.size();
        int firstOpen = *app.expanded.begin();
        T.check("Поведение: щелчок сворачивает", click(H_TOGGLE0 + firstOpen) && app.items.size() < before);
        T.check("Поведение: щелчок раскрывает", click(H_TOGGLE0 + firstOpen) && app.items.size() == before);

        // «Показать все»
        key('3');
        int index = -1;
        for (size_t i = 0; i < a.findings.size(); i++)
            if (a.findings[i].cwe == "CWE-252" && a.findings[i].block == BLOCK_LANG)
                index = (int)i;
        T.check("Уязвимости: есть CWE-252", index >= 0);
        if (index >= 0)
        {
            T.check("все примеры CWE-252: 10", allExamples(a, a.findings[index]).size() == 10, to_string(allExamples(a, a.findings[index]).size()));
            before = app.items.size();
            bool found = false;
            for (int i = 0; i < 40 && !found; i++)
            {
                found = hasHit(H_SHOWALL0 + index);
                if (!found)
                    wheel(-2);
            }
            T.check("«Показать все» доступна прокруткой", found);
            if (found)
                T.check("«Показать все» раскрывает", click(H_SHOWALL0 + index) && app.items.size() > before);
        }

        // ссылка на CWE и внешние действия
        key(VK_HOME);
        app.lastShell.clear();
        bool cwe = false;
        for (int i = 0; i < 40 && !cwe; i++)
        {
            cwe = click(H_CWE0 + 426);
            if (!cwe)
                wheel(-2);
        }
        T.check("CWE: ссылка на сайт MITRE", cwe && app.lastShell.find(L"https://cwe.mitre.org/data/definitions/426.html") == 0, toUtf8(app.lastShell));
        key(VK_HOME);
        click(H_REPORT);
        T.check("кнопка «Отчёт»", app.lastShell.find(L"notepad.exe") == 0 && fs::exists(app.files.report));
        click(H_FOLDER);
        T.check("кнопка «Папка»", app.lastShell.find(L"explorer.exe /select") == 0);

        // копирование хэша
        T.check("кнопка «Копировать»", click(H_COPY) && app.copied);
        T.check("буфер обмена: SHA-256", readClipboard() == fromUtf8(a.sha256));
        pump(2100);
        T.check("надпись «Скопировано» снимается", !app.copied);

        // прокрутка и закреплённые разделы
        key('2');
        key(VK_END);
        float end = app.scroll;
        T.check("Вызовы: длинный раздел прокручивается", end > 0);
        T.check("разделы видны и при прокрутке", hasHit(H_TAB0 + 5));
        click(H_TAB0 + 4);
        T.check("щелчок по разделу при прокрутке", app.tab == T_DAMAGE);
        wheel(50);
        T.check("прокрутка не уходит выше начала", app.scroll == 0);
        wheel(-500);
        T.check("прокрутка не уходит ниже конца", app.scroll <= max(0.0f, app.pageH - viewH()) + 0.5f);

        // размеры окна
        for (auto size : { make_pair(1080, 640), make_pair(1366, 728), make_pair(1920, 1080), make_pair(1280, 900) })
        {
            resizeClient(size.first, size.second);
            walkAllTabs("окно " + to_string(size.first) + "x" + to_string(size.second));
        }

        // переход по меню не теряет итог
        click(H_NAV0 + 1);
        T.check("Отчёты: появился отчёт об образце", !app.reports.empty());
        click(H_REPORTFILE0);
        T.check("Отчёты: щелчок открывает файл", app.lastShell.find(L"notepad.exe") == 0);
        click(H_NAV0);
        T.check("назад: итог на месте", app.screen == S_RESULT && app.a);
        click(H_LOGO);
        T.check("логотип: на старт", app.screen == S_IDLE);
    }

    // ---- архив с несколькими файлами: создаётся из системных файлов
    {
        fs::path zip = tmp / L"two.zip";
        fs::remove(zip, ec);
        wstring cmd = L"cmd /c tar -a -c -f \"" + zip.wstring() + L"\" -C C:\\Windows\\SysWOW64 xcopy.exe where.exe";
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        if (CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        {
            WaitForSingleObject(pi.hProcess, 20000);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        startJob(zip, "");
        waitJob();
        T.check("архив из двух файлов: выбор", app.screen == S_PICK && app.members.size() == 2);
        T.check("выбор: отмена доступна", hasHit(H_CANCEL));
        T.check("выбор: щелчок запускает разбор", click(H_MEMBER0));
        waitJob();
        T.check("выбор: итог по выбранному файлу", app.screen == S_RESULT && app.a && !app.a->name.empty());
    }

    // ---- двойной запуск: действует только последнее задание
    startJob(fs::path(L"C:\\Windows\\SysWOW64\\xcopy.exe"), "");
    startJob(fs::path(L"C:\\Windows\\System32\\notepad.exe"), "");
    waitJob();
    pump(1500);
    T.check("двойной запуск: итог последнего файла", app.a && app.a->name == "notepad.exe" && app.a->score == 32, app.a ? app.a->name : "");

    // ---- результаты совпадают с эталоном
    const struct { const wchar_t* path; int score; } expected[] = {
        { L"C:\\Windows\\System32\\cmd.exe", 53 }, { L"C:\\Windows\\SysWOW64\\xcopy.exe", 2 },
        { L"C:\\Claude pr\\pr7\\samples\\sample_clean.exe", 10 },
    };
    for (const auto& e : expected)
        if (fs::exists(e.path))
        {
            startJob(e.path, "");
            waitJob();
            T.check("эталон " + pathToUtf8(fs::path(e.path).filename()), app.a && app.a->score == e.score, app.a ? to_string(app.a->score) : "нет итога");
            walkAllTabs(pathToUtf8(fs::path(e.path).filename()));
        }

    // ---- данные из файла не искажают экран
    wstring tricky = safeText("a\xE2\x80\xAE" "b\x01" "c");
    T.check("символы смены направления убираются", tricky.find((wchar_t)0x202E) == wstring::npos && tricky.find((wchar_t)1) == wstring::npos);
    T.check("заглавная кириллица", capFirst(L"файл") == L"Файл");
    T.check("ссылка CWE только из цифр", cweAction("CWE-12x") == -1 && cweAction("evil") == -1 && cweAction("CWE-252") == H_CWE0 + 252);

    // ---- испорченные файлы: итог должен рисоваться во всех разделах
    {
        vector<unsigned char> base;
        string error;
        bool loaded = readFile(L"C:\\Windows\\SysWOW64\\xcopy.exe", base, error);
        T.check("фаззинг: исходный файл прочитан", loaded);
        mt19937 gen(20261101);
        int rendered = 0;
        for (int i = 0; loaded && i < FUZZ_DEFAULT; i++)
        {
            vector<unsigned char> bytes = base;
            int mode = i % 4;
            if (mode == 0)
                for (int k = 0; k < 40; k++)
                    bytes[gen() % min<size_t>(bytes.size(), 1024)] = (unsigned char)gen();
            else if (mode == 1)
                bytes.resize(gen() % bytes.size());
            else if (mode == 2)
                for (int k = 0; k < 300; k++)
                    bytes[gen() % bytes.size()] = (unsigned char)gen();
            else
                memset(bytes.data() + 0x100, 0xFF, min<size_t>(bytes.size() - 0x100, 0x400));
            RunOptions options;
            options.selfPath = app.self;
            options.outDir = tmp;
            options.name = "fuzz";
            options.displayPath = "fuzz";
            options.internalOnly = true;
            auto analysis = make_unique<Analysis>();
            RunFiles files;
            runAnalysis(bytes, options, *analysis, files);
            showAnalysis(move(analysis), files);
            for (int t = 0; t < T_COUNT; t++)
                key('1' + t);
            rendered++;
        }
        T.check("фаззинг: все варианты разобраны и нарисованы", rendered == FUZZ_DEFAULT, to_string(rendered));
    }

    T.log << "Итого: пройдено " << T.passed << ", не пройдено " << T.failed << "\n";
    T.log.close();
    return T.failed;
}
