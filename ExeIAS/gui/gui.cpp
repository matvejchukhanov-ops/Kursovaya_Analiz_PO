// Графический интерфейс ExeIAS: родное окно Windows, отрисовка Direct2D и DirectWrite.
// Использует те же модули анализа, что и консольная версия, внешних библиотек нет.
// Запуск: ExeIAS_GUI.exe [файл или архив]. Клавиши: 1–6 — разделы, Ctrl+O — выбрать файл, Tab и Enter — кнопки.

// windows.h — до common.h: там using namespace std, а в SDK есть свой тип byte
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>
#include <d2d1.h>
#include <dwrite.h>
#include <wrl/client.h>
#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dwrite.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "bcrypt.lib")

#include "../economics.h"
#include "../fsanalysis.h"
#include "../input.h"
#include "../pe.h"
#include "../pipeline.h"
#include "../report.h"
#include "../signatures.h"

#include <cmath>
#include <map>
#include <memory>
#include <thread>

using Microsoft::WRL::ComPtr;

// ---------------------------------------------------------------- оформление

D2D1_COLOR_F rgb(uint32_t c, float a = 1.0f)
{
    return { ((c >> 16) & 255) / 255.0f, ((c >> 8) & 255) / 255.0f, (c & 255) / 255.0f, a };
}

const uint32_t C_PAPER = 0xEDF1F5, C_INK = 0x12223B, C_DIM = 0x4E5E76, C_RULE = 0xCBD5DF, C_HOVER = 0xE0E7EE;
const uint32_t C_BLUE = 0x1C3F94, C_CRIT = 0xB3123F, C_HIGH = 0xB0500A, C_MED = 0x7F6400, C_LOW = 0x0F6E5C, C_WHITE = 0xFFFFFF;

const wchar_t* const FONT_UI = L"Bahnschrift";
const wchar_t* const FONT_CODE = L"Consolas";

uint32_t severityColor(Severity s)
{
    return s == CRITICAL ? C_CRIT : s == HIGH ? C_HIGH : s == MEDIUM ? C_MED : s == LOW ? C_LOW : C_DIM;
}

wstring severityWord(Severity s)
{
    return s == CRITICAL ? L"Критично" : s == HIGH ? L"Высокая" : s == MEDIUM ? L"Средняя" : s == LOW ? L"Низкая" : L"Нет";
}

// Текст из исследуемого файла показывается как данные: без управляющих символов
// и символов смены направления письма, которыми можно исказить строку на экране
wstring safeText(const string& utf8, size_t limit = 700)
{
    wstring w = fromUtf8(utf8);
    if (w.length() > limit)
        w = w.substr(0, limit) + L"…";
    for (wchar_t& c : w)
        if ((c < 32 && c != L'\n') || c == 0x7F || (c >= 0x202A && c <= 0x202E) || (c >= 0x2066 && c <= 0x2069) || c == 0x200E || c == 0x200F)
            c = L' ';
    return w;
}

wstring capFirst(wstring s)
{
    if (!s.empty())
        CharUpperBuffW(&s[0], 1);    // towupper в локали «C» не меняет регистр кириллицы
    return s;
}

// ---------------------------------------------------------------- состояние

enum Screen { S_IDLE, S_BUSY, S_PICK, S_RESULT };
enum Tab { T_BEHAVIOR, T_CALLS, T_VULN, T_IOC, T_DAMAGE, T_TODO, T_COUNT };
enum HitId { H_NONE, H_CHOOSE, H_REPORT, H_FOLDER, H_THUMB, H_TAB0 = 100, H_MEMBER0 = 200, H_TOGGLE0 = 1000 };

struct Hit
{
    D2D1_RECT_F r;
    int id;
};

// Элемент прокручиваемой области: текст, прямоугольник или строка, раскрываемая щелчком
struct Item
{
    float x, y, w, h;
    ComPtr<IDWriteTextLayout> layout;
    D2D1_COLOR_F color;
    int toggle = -1;
};

struct Job
{
    int generation;
    unique_ptr<Analysis> analysis;
    RunFiles files;
    vector<string> members;
    fs::path archive;
    string error;
};

const UINT WM_JOB_DONE = WM_APP + 1;

struct App
{
    HWND hwnd = nullptr;
    ComPtr<ID2D1Factory> d2d;
    ComPtr<IDWriteFactory> dw;
    ComPtr<ID2D1HwndRenderTarget> rt;
    ComPtr<ID2D1SolidColorBrush> brush;
    map<wstring, ComPtr<IDWriteTextFormat>> formats;

    float dpi = 96, W = 1280, H = 800;
    fs::path self;

    Screen screen = S_IDLE;
    int generation = 0;
    wstring busyName, errorText;
    fs::path pickArchive;
    vector<string> members;

    unique_ptr<Analysis> a;
    RunFiles files;
    int tab = T_BEHAVIOR;
    set<int> expanded;

    vector<Item> items;
    float contentHeight = 0, scroll = 0;
    bool itemsValid = false;

    vector<Hit> hits;
    int hot = H_NONE, focus = H_NONE;
    bool draggingThumb = false;
    float dragStartY = 0, dragStartScroll = 0;
    float animPhase = 0;
    bool animate = true;
} app;

// ---------------------------------------------------------------- текст

IDWriteTextFormat* fmt(const wchar_t* family, float size, DWRITE_FONT_WEIGHT weight = DWRITE_FONT_WEIGHT_NORMAL,
                       DWRITE_FONT_STRETCH stretch = DWRITE_FONT_STRETCH_NORMAL)
{
    wstring key = wstring(family) + L"|" + to_wstring(size) + L"|" + to_wstring((int)weight) + L"|" + to_wstring((int)stretch);
    auto it = app.formats.find(key);
    if (it != app.formats.end())
        return it->second.Get();
    ComPtr<IDWriteTextFormat> f;
    app.dw->CreateTextFormat(family, nullptr, weight, DWRITE_FONT_STYLE_NORMAL, stretch, size, L"ru-ru", &f);
    f->SetWordWrapping(DWRITE_WORD_WRAPPING_EMERGENCY_BREAK);
    app.formats[key] = f;
    return f.Get();
}

IDWriteTextFormat* body() { return fmt(FONT_UI, 16); }
IDWriteTextFormat* note() { return fmt(FONT_UI, 14); }
IDWriteTextFormat* strong() { return fmt(FONT_UI, 18, DWRITE_FONT_WEIGHT_SEMI_BOLD); }
IDWriteTextFormat* code() { return fmt(FONT_CODE, 14); }

ComPtr<IDWriteTextLayout> makeLayout(const wstring& text, IDWriteTextFormat* f, float width)
{
    ComPtr<IDWriteTextLayout> l;
    app.dw->CreateTextLayout(text.c_str(), (UINT32)text.length(), f, max(width, 1.0f), 10000.0f, &l);
    return l;
}

float layoutHeight(IDWriteTextLayout* l)
{
    DWRITE_TEXT_METRICS m = {};
    l->GetMetrics(&m);
    return m.height;
}

float layoutWidth(IDWriteTextLayout* l)
{
    DWRITE_TEXT_METRICS m = {};
    l->GetMetrics(&m);
    return m.widthIncludingTrailingWhitespace;
}

void fillRect(float x, float y, float w, float h, D2D1_COLOR_F c)
{
    app.brush->SetColor(c);
    app.rt->FillRectangle(D2D1::RectF(x, y, x + w, y + h), app.brush.Get());
}

// Рисует текст и возвращает его высоту
float drawText(const wstring& text, IDWriteTextFormat* f, float x, float y, float width, D2D1_COLOR_F c)
{
    auto l = makeLayout(text, f, width);
    app.brush->SetColor(c);
    app.rt->DrawTextLayout(D2D1::Point2F(x, y), l.Get(), app.brush.Get());
    return layoutHeight(l.Get());
}

// ---------------------------------------------------------------- геометрия

float panelWidth() { return min(max(app.W * 0.34f, 360.0f), 470.0f); }
const float MAP_H = 158, TABS_H = 50, GUTTER = 36;
float contentX() { return panelWidth() + GUTTER; }
float contentW() { return min(app.W - contentX() - GUTTER - 10, 880.0f); }
float contentTop() { return MAP_H + TABS_H; }
float viewH() { return app.H - contentTop(); }

// ---------------------------------------------------------------- итог для левой панели

bool hasDestroy(const Analysis& a)
{
    for (const Behavior& b : a.behaviors)
        if (b.code == "DESTROY")
            return true;
    return false;
}

uint32_t panelColor()
{
    if (app.screen != S_RESULT || !app.a)
        return C_BLUE;
    const Analysis& a = *app.a;
    if (a.verdict.find("двойного назначения") != NPOS)
        return C_MED;
    if (hasDestroy(a) || a.overall == CRITICAL)
        return C_CRIT;
    if (a.overall == HIGH)
        return C_HIGH;
    if (a.overall == MEDIUM)
        return C_MED;
    return C_LOW;
}

wstring headline(const Analysis& a)
{
    if (hasDestroy(a))
        return L"Уничтожает данные";
    if (a.verdict.find("не обнаружено") != NPOS)
        return L"Угроз не найдено";
    if (a.verdict.find("углублённого") != NPOS)
        return L"Опасные признаки";
    if (a.verdict.find("двойного назначения") != NPOS)
        return L"Вредоносность не установлена";
    if (a.verdict.find(".NET") != NPOS)
        return L"Обычное приложение .NET";
    return L"Только слабые места";
}

// ---------------------------------------------------------------- содержимое разделов

struct Builder
{
    float y = 8, width;
    vector<Item>& items;

    float add(const wstring& text, IDWriteTextFormat* f, uint32_t color, float indent = 0, float after = 6, bool advance = true)
    {
        auto l = makeLayout(text, f, width - indent);
        float h = layoutHeight(l.Get());
        items.push_back({ indent, y, width - indent, h, l, rgb(color) });
        if (advance)
            y += h + after;
        return h;
    }

    void rect(float x, float yy, float w, float h, uint32_t color, float alpha = 1.0f)
    {
        items.push_back({ x, yy, w, h, nullptr, rgb(color, alpha) });
    }

    void rule()
    {
        y += 8;
        rect(0, y, width, 1, C_RULE);
        y += 13;
    }

    void gap(float g) { y += g; }
};

// Отметка критичности в левой колонке: цветной квадрат и слово, чтобы цвет не был единственным признаком
const float SEV_COL = 104;

void severityMark(Builder& b, Severity s)
{
    b.rect(0, b.y + 7, 10, 10, severityColor(s));
    b.add(severityWord(s), note(), severityColor(s), 16, 0, false);
}

void buildBehavior(Builder& b, const Analysis& a)
{
    if (a.behaviors.empty())
    {
        b.add(a.code.done ? L"В машинном коде нет связанных цепочек операций с файлами, реестром и запуском программ."
                          : L"Машинный код не разобран: " + safeText(a.code.note), body(), C_INK);
        b.add(L"Находки по строкам и импорту смотрите в разделах «Уязвимости» и «Индикаторы».", body(), C_DIM);
        return;
    }
    vector<int> order;
    for (int i = 0; i < (int)a.behaviors.size(); i++)
        order.push_back(i);
    stable_sort(order.begin(), order.end(), [&](int x, int y) { return a.behaviors[x].severity > a.behaviors[y].severity; });

    for (int i : order)
    {
        const Behavior& bh = a.behaviors[i];
        float top = b.y;
        size_t hitIndex = b.items.size();
        b.items.push_back({ -10, top - 7, b.width + 20, 0, nullptr, rgb(C_HOVER), i });

        severityMark(b, bh.severity);
        b.add(safeText(bh.title), strong(), C_INK, SEV_COL, 2);
        bool open = app.expanded.count(i) > 0;
        wstring sub = fromUtf8(bh.attack + " " + bh.attackName + ", функция sub_" + hexPlain(bh.func));
        if (!bh.evidence.empty())
            sub += open ? L". Скрыть вызовы" : L". Показать вызовы: " + to_wstring(bh.evidence.size());
        b.add(sub, note(), C_DIM, SEV_COL, 4);
        if (open)
        {
            if (!bh.details.empty())
                b.add(capFirst(safeText(bh.details)), body(), C_INK, SEV_COL, 8);
            for (const string& e : bh.evidence)
                b.add(safeText(e), code(), C_INK, SEV_COL, 7);
        }
        b.items[hitIndex].h = b.y - top + 8;
        b.rule();
    }
}

void buildCalls(Builder& b, const Analysis& a)
{
    if (!a.code.done)
    {
        b.add(L"Машинный код не разобран: " + safeText(a.code.note), body(), C_INK);
        return;
    }
    b.add(L"Найдено функций: " + to_wstring(a.code.functions.size()) + L". Аргументы восстановлены у "
          + to_wstring(a.code.resolvedCalls) + L" вызовов, файл при этом не запускался. var_N — буфер в стеке функции, "
          L"arg_N — её аргумент, ? — значение восстановить не удалось.", body(), C_DIM, 0, 14);

    map<uint64_t, vector<string>> roles;
    for (const Behavior& bh : a.behaviors)
        addUnique(roles[bh.func], bh.title);

    size_t shownLines = 0, shownFunctions = 0;
    for (const FunctionInfo& f : a.code.functions)
    {
        vector<const CallSite*> calls;
        bool relevant = roles.count(f.start) > 0;
        for (const CallSite& c : f.calls)
        {
            if (!c.isApi)
                continue;
            bool lowLevel = false;
            bool fsCall = !fsOpOf(c.target, lowLevel).empty() || c.target.rfind("Reg", 0) == 0;
            if (fsCall && !lowLevel)
                relevant = true;
            calls.push_back(&c);
        }
        if (!relevant || calls.empty() || shownLines > 400)
            continue;
        shownFunctions++;
        b.add(fromUtf8("Функция sub_" + hexPlain(f.start)) + (f.recursive ? L", вызывает сама себя" : L""), strong(), C_INK, 0, 2);
        if (roles.count(f.start))
        {
            wstring text;
            for (const string& r : roles[f.start])
                text += (text.empty() ? L"" : L"; ") + safeText(r);
            b.add(text, note(), C_DIM, 0, 6);
        }
        for (const CallSite* c : calls)
        {
            shownLines++;
            b.add(fromUtf8(hexVa(c->addr) + "  ") + safeText(formatCall(*c)), code(), C_INK, 0, 2);
            string meaning = callNote(*c);
            if (!meaning.empty())
                b.add(safeText(meaning), note(), C_DIM, 26, 2);
            b.gap(4);
        }
        b.rule();
    }
    if (shownFunctions == 0)
        b.add(L"Функций, работающих с файлами и реестром, не найдено.", body(), C_INK);
}

void buildFinding(Builder& b, const Finding& f)
{
    severityMark(b, f.severity);
    b.add(safeText(f.signature), strong(), C_INK, SEV_COL, 2);
    wstring meta;
    if (!f.cwe.empty())
        meta += fromUtf8(f.cwe + (f.cweName.empty() ? "" : " " + f.cweName));
    if (!f.cve.empty())
        meta += (meta.empty() ? L"" : L", ") + fromUtf8(f.cve);
    if (!f.attack.empty())
        meta += (meta.empty() ? L"" : L", ") + fromUtf8(f.attack);
    if (f.hits > 1)
        meta += (meta.empty() ? L"" : L", ") + wstring(L"совпадений: ") + to_wstring(f.hits);
    if (!meta.empty())
        b.add(meta, note(), C_DIM, SEV_COL, 3);
    b.add(safeText(f.incident), body(), C_INK, SEV_COL, 4);
    for (size_t i = 0; i < f.examples.size() && i < 3; i++)
        b.add(safeText(f.examples[i]), code(), C_INK, SEV_COL, 3);
    if (!f.note.empty())
        b.add(safeText(f.note), note(), C_DIM, SEV_COL, 3);
    b.rule();
}

void buildVuln(Builder& b, const Analysis& a)
{
    size_t n = 0;
    for (const Finding& f : a.findings)
        if (f.block == BLOCK_VULN && n++ < 100)
            buildFinding(b, f);
    if (n == 0)
        b.add(L"Признаков уязвимостей не найдено.", body(), C_INK, 0, 14);

    b.gap(10);
    b.add(L"Ошибки в коде", fmt(FONT_UI, 24, DWRITE_FONT_WEIGHT_SEMI_BOLD), C_INK, 0, 4);
    b.add(L"Язык: " + safeText(a.lang.language) + L". Эти ошибки говорят о качестве кода, а не о вредоносности, поэтому на балл риска не влияют.",
          body(), C_DIM, 0, 14);
    n = 0;
    for (const Finding& f : a.findings)
        if (f.block == BLOCK_LANG && n++ < 100)
            buildFinding(b, f);
    if (n == 0)
        b.add(L"Таких ошибок не найдено.", body(), C_INK);
}

void buildIoc(Builder& b, const Analysis& a)
{
    vector<string> iocs = collectIocs(a);
    if (!iocs.empty())
    {
        b.add(L"Что искать на других компьютерах и блокировать", strong(), C_INK, 0, 8);
        for (const string& s : iocs)
            b.add(safeText(s), code(), C_INK, 0, 5);
        b.rule();
    }
    size_t n = 0;
    for (const Finding& f : a.findings)
        if (f.block == BLOCK_IOC && n++ < 100)
            buildFinding(b, f);
    if (n == 0 && iocs.empty())
        b.add(L"Индикаторов компрометации не найдено.", body(), C_INK);
}

void buildDamage(Builder& b, const Analysis& a)
{
    const EconomicSummary& e = a.economy;
    if (e.lossExpected <= 0)
    {
        b.add(L"Ущерб не начислен: нет находок уровня «Высокая» и выше.", body(), C_INK, 0, 10);
    }
    else
    {
        b.add(safeText(formatRub(e.lossExpected)), fmt(FONT_UI, 44, DWRITE_FONT_WEIGHT_SEMI_BOLD, DWRITE_FONT_STRETCH_CONDENSED), C_INK, 0, 0);
        b.add(L"Ожидаемый ущерб за один инцидент, опасность " + safeText(e.level) + L". Возможный диапазон: от "
              + safeText(formatRub(e.lossMin)) + L" до " + safeText(formatRub(e.lossMax)), body(), C_DIM, 0, 22);

        double top = 1;
        for (const EconomicLine& l : e.lines)
            top = max(top, l.hi);
        for (const EconomicLine& l : e.lines)
        {
            b.add(capFirst(safeText(l.name)), strong(), C_INK, 0, 6);
            float scale = (float)(b.width / top), barY = b.y;
            b.rect(0, barY + 6, b.width, 2, C_RULE);
            b.rect((float)l.lo * scale, barY, max((float)(l.hi - l.lo) * scale, 2.0f), 14, panelColor(), 0.3f);
            b.rect((float)l.expected * scale - 2, barY - 3, 4, 20, panelColor());
            b.y += 24;
            b.add(L"ожидаемо " + safeText(formatRub(l.expected)) + L", от " + safeText(formatRub(l.lo)) + L" до " + safeText(formatRub(l.hi)),
                  note(), C_DIM, 0, 18);
        }
        b.add(L"Светлая полоса показывает диапазон, тёмная отметка — ожидаемое значение.", note(), C_DIM, 0, 4);
    }
    b.rule();
    b.add(L"Профиль: " + safeText(a.profile.name) + L" (" + safeText(a.profile.source) + L"). Рабочих мест: "
          + to_wstring((int)a.profile.workstations) + L", час простоя " + safeText(formatRub(a.profile.hourCost))
          + L", час специалиста " + safeText(formatRub(a.profile.specialistHour)), body(), C_INK);
    b.add(L"Это модель для сравнения файлов, а не прогноз потерь. Параметры меняются в economics.ini рядом с программой.", body(), C_DIM);
}

void buildTodo(Builder& b, const Analysis& a)
{
    vector<pair<Severity, string>> recs;
    set<string> seen;
    for (int s = CRITICAL; s >= LOW; s--)
        for (const Finding& f : a.findings)
            if (f.severity == s && f.block != BLOCK_LANG && !f.recommendation.empty() && seen.insert(f.recommendation).second)
                recs.push_back({ (Severity)s, f.recommendation });
    if (recs.empty())
        b.add(L"Специальных мер не требуется.", body(), C_INK);
    for (const auto& r : recs)
    {
        severityMark(b, r.first);
        b.add(safeText(r.second), body(), C_INK, SEV_COL, 4);
        b.rule();
    }
}

void rebuildItems()
{
    app.items.clear();
    app.itemsValid = true;
    app.contentHeight = 0;
    if (app.screen != S_RESULT || !app.a)
        return;
    Builder b{ 8, contentW(), app.items };
    switch (app.tab)
    {
    case T_BEHAVIOR: buildBehavior(b, *app.a); break;
    case T_CALLS:    buildCalls(b, *app.a); break;
    case T_VULN:     buildVuln(b, *app.a); break;
    case T_IOC:      buildIoc(b, *app.a); break;
    case T_DAMAGE:   buildDamage(b, *app.a); break;
    default:         buildTodo(b, *app.a); break;
    }
    app.contentHeight = b.y + 24;
    app.scroll = max(0.0f, min(app.scroll, app.contentHeight - viewH()));
}

// ---------------------------------------------------------------- рисование

void addHit(float x, float y, float w, float h, int id)
{
    app.hits.push_back({ D2D1::RectF(x, y, x + w, y + h), id });
}

// Кнопка на цветной панели: первая залита белым, остальные — контур
float panelButton(const wstring& text, float x, float y, float w, int id, bool primary)
{
    const float h = 42;
    bool hot = app.hot == id;
    app.brush->SetColor(rgb(C_WHITE, primary ? (hot ? 0.88f : 1.0f) : (hot ? 0.18f : 0.0f)));
    app.rt->FillRectangle(D2D1::RectF(x, y, x + w, y + h), app.brush.Get());
    if (!primary)
    {
        app.brush->SetColor(rgb(C_WHITE, 0.75f));
        app.rt->DrawRectangle(D2D1::RectF(x + 0.5f, y + 0.5f, x + w - 0.5f, y + h - 0.5f), app.brush.Get());
    }
    if (app.focus == id)
    {
        app.brush->SetColor(rgb(C_WHITE));
        app.rt->DrawRectangle(D2D1::RectF(x - 3, y - 3, x + w + 3, y + h + 3), app.brush.Get(), 2);
    }
    auto l = makeLayout(text, fmt(FONT_UI, 16, DWRITE_FONT_WEIGHT_SEMI_BOLD), w);
    l->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
    app.brush->SetColor(primary ? rgb(panelColor()) : rgb(C_WHITE));
    app.rt->DrawTextLayout(D2D1::Point2F(x, y + (h - layoutHeight(l.Get())) / 2), l.Get(), app.brush.Get());
    addHit(x, y, w, h, id);
    return h;
}

void drawScoreRuler(const Analysis& a, float x, float y, float w)
{
    const D2D1_COLOR_F white = rgb(C_WHITE), soft = rgb(C_WHITE, 0.32f);
    fillRect(x, y + 6, w, 6, soft);
    fillRect(x, y + 6, w * a.score / 100.0f, 6, white);
    struct Zone { int from, to; const wchar_t* name; };
    const Zone zones[] = { { 0, 20, L"низкая" }, { 20, 45, L"средняя" }, { 45, 70, L"высокая" }, { 70, 100, L"очень высокая" } };
    for (const Zone& z : zones)
    {
        if (z.from)
            fillRect(x + w * z.from / 100.0f, y + 2, 1.5f, 14, white);
        drawText(z.name, fmt(FONT_UI, 12.5f), x + w * z.from / 100.0f + (z.from ? 4 : 0), y + 20, w * (z.to - z.from) / 100.0f, rgb(C_WHITE, 0.92f));
    }
}

void drawMark(float x, float w)
{
    const D2D1_COLOR_F soft = rgb(C_WHITE, 0.88f);
    float y = app.H - 92;
    fillRect(x, y, w, 1, rgb(C_WHITE, 0.45f));
    drawText(L"Разработка РТУ МИРЭА", fmt(FONT_UI, 18, DWRITE_FONT_WEIGHT_SEMI_BOLD), x, y + 11, w, rgb(C_WHITE));
    drawText(L"Кафедра КБ-2, 2026 год", fmt(FONT_UI, 14), x, y + 38, w, soft);
}

void drawPanel()
{
    float pw = panelWidth(), x = 32, w = pw - 64;
    fillRect(0, 0, pw, app.H, rgb(panelColor()));
    const D2D1_COLOR_F white = rgb(C_WHITE), soft = rgb(C_WHITE, 0.88f);
    float y = 30;

    if (app.screen == S_RESULT && app.a)
    {
        const Analysis& a = *app.a;
        y += drawText(safeText(a.name, 60), fmt(FONT_UI, 16), x, y, w, soft) + 6;
        y += drawText(headline(a), fmt(FONT_UI, w > 360 ? 46.0f : 40.0f, DWRITE_FONT_WEIGHT_SEMI_BOLD, DWRITE_FONT_STRETCH_CONDENSED), x, y, w, white) + 10;
        y += drawText(capFirst(safeText(a.verdict)), fmt(FONT_UI, 15), x, y, w, soft) + 18;

        y += drawText(L"Балл риска " + to_wstring(a.score) + L" из 100, вероятность инцидента " + safeText(a.probability),
                      fmt(FONT_UI, 15, DWRITE_FONT_WEIGHT_SEMI_BOLD), x, y, w, white) + 6;
        drawScoreRuler(a, x, y, w);
        y += 54;

        if (a.pe.valid)
        {
            wstring lang = L"Язык: " + safeText(a.lang.language);
            if (!a.lang.toolchain.empty())
                lang += L", " + safeText(a.lang.toolchain);
            y += drawText(lang, fmt(FONT_UI, 14), x, y, w, soft) + 6;
        }
        y += drawText(L"SHA-256 " + fromUtf8(a.sha256), fmt(FONT_CODE, 12.5f), x, y, w, soft) + 14;

        float bottom = app.H - 92 - 16;
        float halfW = (w - 10) / 2;
        panelButton(L"Открыть отчёт", x, bottom - 42, halfW, H_REPORT, false);
        panelButton(L"Папка отчётов", x + halfW + 10, bottom - 42, halfW, H_FOLDER, false);
        panelButton(L"Проверить другой файл", x, bottom - 94, w, H_CHOOSE, true);
    }
    else
    {
        y += drawText(L"ExeIAS", fmt(FONT_UI, 64, DWRITE_FONT_WEIGHT_SEMI_BOLD, DWRITE_FONT_STRETCH_CONDENSED), x, y - 6, w, white) + 8;
        y += drawText(L"Читает исполняемый файл и показывает, что он сделает с вашими файлами. Сам файл при этом не запускается.",
                      fmt(FONT_UI, 20), x, y, w, white) + 30;
        panelButton(L"Выбрать файл", x, y, w, H_CHOOSE, true);
    }
    drawMark(x, w);
}

void drawFileMap(const Analysis& a)
{
    float x = contentX(), w = contentW(), y = 24;
    if (!a.pe.valid)
    {
        drawText(L"Карта файла недоступна", strong(), x, y, w, rgb(C_INK));
        drawText(safeText(a.pe.error), body(), x, y + 28, w, rgb(C_DIM));
        return;
    }
    // Ширина секции пропорциональна размеру, но не меньше ширины её имени
    struct Cell { const Section* s; float x, w; };
    vector<Cell> cells;
    double total = 0;
    size_t count = min<size_t>(a.pe.sections.size(), 16);
    for (size_t i = 0; i < count; i++)
        total += max(a.pe.sections[i].vsize, a.pe.sections[i].rawSize) + 1.0;
    const float minCell = 54;
    float flexible = max(w - minCell * count - 2 * (float)count, 0.0f), cx = x;
    for (size_t i = 0; i < count; i++)
    {
        const Section& s = a.pe.sections[i];
        float cw = minCell + flexible * (float)((max(s.vsize, s.rawSize) + 1.0) / max(total, 1.0));
        cells.push_back({ &s, cx, cw });
        cx += cw + 2;
    }

    wstring title = L"Карта файла: " + to_wstring(a.pe.sections.size()) + L" секц., " + (a.pe.is64 ? L"PE32+" : L"PE32")
                  + (a.pe.isDotNet ? L", .NET" : L"");
    y += drawText(title, strong(), x, y, w, rgb(C_INK)) + 8;

    const float tickH = 12, stripY = y + tickH, stripH = 34;
    for (const Cell& c : cells)
    {
        // чем выше энтропия секции, тем темнее цвет
        float t = (float)min(c.s->entropy / 8.0, 1.0);
        D2D1_COLOR_F light = rgb(0xC6D3E4), dark = rgb(C_INK);
        D2D1_COLOR_F mix = { light.r + (dark.r - light.r) * t, light.g + (dark.g - light.g) * t, light.b + (dark.b - light.b) * t, 1 };
        fillRect(c.x, stripY, c.w, stripH, mix);
        drawText(safeText(c.s->name, 8), fmt(FONT_CODE, 13), c.x + 12, stripY + 8, c.w - 13, t > 0.45f ? rgb(C_WHITE) : rgb(C_INK));
    }

    // Отметки над секциями: опасные функции
    set<uint64_t> danger;
    for (const Behavior& b : a.behaviors)
        if (b.severity >= MEDIUM)
            danger.insert(b.func);
    wstring names;
    for (uint64_t va : danger)
    {
        uint64_t rva = va >= a.pe.imageBase ? va - a.pe.imageBase : 0;
        for (const Cell& c : cells)
        {
            uint32_t size = max(max(c.s->vsize, c.s->rawSize), 1u);
            if (rva >= c.s->va && rva < (uint64_t)c.s->va + size)
                fillRect(c.x + c.w * (float)(rva - c.s->va) / size, stripY - tickH, 2.5f, tickH + stripH, rgb(C_CRIT));
        }
        if (names.length() < 90)
            names += (names.empty() ? L"" : L", ") + fromUtf8("sub_" + hexPlain(va));
    }
    wstring caption = danger.empty() ? L"Опасных функций не найдено. Чем темнее секция, тем выше энтропия данных."
                                     : L"Красные отметки: опасный код в " + names + L". Чем темнее секция, тем выше энтропия.";
    drawText(caption, note(), x, stripY + stripH + 8, w, rgb(C_DIM));
}

void drawTabs(const Analysis& a)
{
    size_t vuln = 0, ioc = 0;
    for (const Finding& f : a.findings)
    {
        vuln += f.block == BLOCK_VULN || f.block == BLOCK_LANG;
        ioc += f.block == BLOCK_IOC;
    }
    const wstring names[T_COUNT] = {
        L"Поведение " + to_wstring(a.behaviors.size()), L"Вызовы в коде", L"Уязвимости " + to_wstring(vuln),
        L"Индикаторы " + to_wstring(ioc), L"Ущерб", L"Что делать"
    };
    float x = contentX(), y = MAP_H;
    fillRect(contentX(), y + TABS_H - 1, app.W - contentX(), 1, rgb(C_RULE));
    for (int i = 0; i < T_COUNT; i++)
    {
        bool active = app.tab == i;
        auto l = makeLayout(names[i], fmt(FONT_UI, 16, active ? DWRITE_FONT_WEIGHT_SEMI_BOLD : DWRITE_FONT_WEIGHT_NORMAL), 400);
        float tw = layoutWidth(l.Get());
        app.brush->SetColor(rgb(active || app.hot == H_TAB0 + i ? C_INK : C_DIM));
        app.rt->DrawTextLayout(D2D1::Point2F(x, y + 13), l.Get(), app.brush.Get());
        if (active)
            fillRect(x, y + TABS_H - 4, tw, 4, rgb(panelColor()));
        addHit(x - 6, y, tw + 12, TABS_H, H_TAB0 + i);
        x += tw + 26;
    }
}

void drawContent()
{
    float top = contentTop(), x = contentX(), clipH = viewH();
    if (!app.itemsValid)
        rebuildItems();
    app.rt->PushAxisAlignedClip(D2D1::RectF(panelWidth(), top, app.W, app.H), D2D1_ANTIALIAS_MODE_ALIASED);
    for (const Item& it : app.items)
    {
        float y = top + it.y - app.scroll;
        if (y > app.H || y + it.h < top)
            continue;
        if (it.toggle >= 0)
        {
            int id = H_TOGGLE0 + it.toggle;
            if (app.hot == id)
                fillRect(x + it.x, y, it.w, it.h, it.color);
            float hy = max(y, top), hb = min(y + it.h, app.H);
            if (hb > hy)
                addHit(x + it.x, hy, it.w, hb - hy, id);
        }
        else if (it.layout)
        {
            app.brush->SetColor(it.color);
            app.rt->DrawTextLayout(D2D1::Point2F(x + it.x, y), it.layout.Get(), app.brush.Get());
        }
        else
            fillRect(x + it.x, y, it.w, it.h, it.color);
    }
    app.rt->PopAxisAlignedClip();

    if (app.contentHeight > clipH)
    {
        float thumbH = max(clipH * clipH / app.contentHeight, 40.0f);
        float thumbY = top + (clipH - thumbH) * app.scroll / (app.contentHeight - clipH);
        fillRect(app.W - 10, thumbY, 6, thumbH, rgb(C_DIM, app.hot == H_THUMB || app.draggingThumb ? 0.85f : 0.45f));
        addHit(app.W - 14, thumbY, 14, thumbH, H_THUMB);
    }
}

void drawIdle()
{
    float x = contentX(), w = contentW(), y = max(app.H * 0.13f, 60.0f);
    y += drawText(L"Перетащите файл в это окно", fmt(FONT_UI, 40, DWRITE_FONT_WEIGHT_SEMI_BOLD, DWRITE_FONT_STRETCH_CONDENSED), x, y, w, rgb(C_INK)) + 8;
    y += drawText(L"Подойдёт .exe, .dll, .bin или архив .rar, .zip, .7z. Образец из архива читается в память и на диск не попадает.",
                  fmt(FONT_UI, 18), x, y, min(w, 680.0f), rgb(C_DIM)) + 16;
    if (!app.errorText.empty())
    {
        fillRect(x, y + 4, 4, 52, rgb(C_CRIT));
        y += max(drawText(app.errorText, body(), x + 16, y + 4, w - 16, rgb(C_CRIT)), 52.0f) + 12;
    }
    y += 26;
    drawText(L"Как идёт проверка", strong(), x, y, w, rgb(C_INK));
    y += 38;
    const pair<const wchar_t*, const wchar_t*> steps[] = {
        { L"Заголовки файла", L"формат, секции, энтропия, таблица импорта" },
        { L"Строки и сигнатуры", L"55 правил с привязкой к CWE, CVE и MITRE ATT&CK" },
        { L"Машинный код", L"свой декодер x86 и x64 восстанавливает аргументы вызовов" },
        { L"Цепочки поведения", L"какие операции с файлами и реестром связаны в коде" },
        { L"Итог", L"балл риска, ошибки в коде, ущерб в рублях и рекомендации" },
    };
    int n = 1;
    const float stepH = 58;
    fillRect(x + 15, y + 8, 2, stepH * 4, rgb(C_RULE));
    for (const auto& s : steps)
    {
        app.brush->SetColor(rgb(C_BLUE));
        app.rt->FillEllipse(D2D1::Ellipse(D2D1::Point2F(x + 16, y + 16), 16, 16), app.brush.Get());
        auto num = makeLayout(to_wstring(n++), fmt(FONT_UI, 15, DWRITE_FONT_WEIGHT_SEMI_BOLD), 32);
        num->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
        app.brush->SetColor(rgb(C_WHITE));
        app.rt->DrawTextLayout(D2D1::Point2F(x, y + 16 - layoutHeight(num.Get()) / 2), num.Get(), app.brush.Get());
        drawText(s.first, fmt(FONT_UI, 17, DWRITE_FONT_WEIGHT_SEMI_BOLD), x + 46, y - 2, w - 46, rgb(C_INK));
        drawText(s.second, note(), x + 46, y + 22, w - 46, rgb(C_DIM));
        y += stepH;
    }
}

void drawBusy()
{
    float x = contentX(), w = contentW(), y = app.H * 0.36f;
    y += drawText(L"Идёт разбор файла", fmt(FONT_UI, 40, DWRITE_FONT_WEIGHT_SEMI_BOLD, DWRITE_FONT_STRETCH_CONDENSED), x, y, w, rgb(C_INK)) + 6;
    y += drawText(app.busyName, fmt(FONT_UI, 18), x, y, w, rgb(C_DIM)) + 22;
    fillRect(x, y, w, 4, rgb(C_RULE));
    float segment = w * 0.22f, pos = (w + segment) * app.animPhase - segment;
    float left = max(pos, 0.0f), right = min(pos + segment, w);
    if (right > left)
        fillRect(x + left, y, right - left, 4, rgb(C_BLUE));
    drawText(L"Файл только читается и не запускается.", body(), x, y + 18, w, rgb(C_DIM));
}

void drawPick()
{
    float x = contentX(), w = contentW(), y = 70;
    y += drawText(L"Какой файл из архива проверить?", fmt(FONT_UI, 36, DWRITE_FONT_WEIGHT_SEMI_BOLD, DWRITE_FONT_STRETCH_CONDENSED), x, y, w, rgb(C_INK)) + 6;
    y += drawText(safeText(pathToUtf8(app.pickArchive.filename())), body(), x, y, w, rgb(C_DIM)) + 20;
    for (size_t i = 0; i < app.members.size() && y < app.H - 50; i++)
    {
        int id = H_MEMBER0 + (int)i;
        if (app.hot == id)
            fillRect(x - 10, y, w + 20, 40, rgb(C_HOVER));
        drawText(safeText(app.members[i], 120), body(), x, y + 9, w, rgb(C_INK));
        fillRect(x, y + 39, w, 1, rgb(C_RULE));
        addHit(x - 10, y, w + 20, 40, id);
        y += 40;
    }
}

void paint()
{
    if (!app.rt)
    {
        RECT rc;
        GetClientRect(app.hwnd, &rc);
        D2D1_RENDER_TARGET_PROPERTIES props = D2D1::RenderTargetProperties();
        props.dpiX = props.dpiY = app.dpi;
        app.d2d->CreateHwndRenderTarget(props, D2D1::HwndRenderTargetProperties(app.hwnd, D2D1::SizeU(rc.right, rc.bottom)), &app.rt);
        if (!app.rt)
            return;
        app.rt->CreateSolidColorBrush(rgb(C_INK), &app.brush);
    }
    app.hits.clear();
    app.rt->BeginDraw();
    app.rt->Clear(rgb(C_PAPER));
    drawPanel();
    switch (app.screen)
    {
    case S_IDLE: drawIdle(); break;
    case S_BUSY: drawBusy(); break;
    case S_PICK: drawPick(); break;
    default:
        if (app.a)
        {
            drawFileMap(*app.a);
            drawTabs(*app.a);
            drawContent();
        }
    }
    if (app.rt->EndDraw() == D2DERR_RECREATE_TARGET)
    {
        app.rt.Reset();
        app.brush.Reset();
        InvalidateRect(app.hwnd, nullptr, FALSE);
    }
}

// ---------------------------------------------------------------- действия

void redraw() { InvalidateRect(app.hwnd, nullptr, FALSE); }

void setTab(int t)
{
    if (app.screen != S_RESULT || t < 0 || t >= T_COUNT)
        return;
    app.tab = t;
    app.scroll = 0;
    app.itemsValid = false;
    redraw();
}

void scrollBy(float dy)
{
    if (app.screen != S_RESULT)
        return;
    app.scroll = max(0.0f, min(app.scroll + dy, max(0.0f, app.contentHeight - viewH())));
    redraw();
}

void startJob(const fs::path& path, const string& member)
{
    int generation = ++app.generation;
    app.screen = S_BUSY;
    app.errorText.clear();
    app.busyName = safeText(member.empty() ? pathToUtf8(path.filename()) : member, 100);
    app.a.reset();
    app.itemsValid = false;
    app.animPhase = 0;
    if (app.animate)
        SetTimer(app.hwnd, 1, 33, nullptr);
    redraw();

    HWND hwnd = app.hwnd;
    fs::path self = app.self;
    thread([=]()
    {
        auto job = make_unique<Job>();
        job->generation = generation;
        try
        {
            vector<unsigned char> bytes;
            RunOptions options;
            options.selfPath = self;
            options.outDir = self.parent_path() / L"reports";
            string error, chosen = member;
            bool ok = false;
            if (isArchive(path))
            {
                if (chosen.empty())
                {
                    vector<string> names = listArchive(path, error);
                    if (names.size() > 1)
                    {
                        job->members = names;
                        job->archive = path;
                    }
                    else if (names.size() == 1)
                        chosen = names[0];
                }
                if (job->members.empty() && !chosen.empty())
                {
                    ok = readFromArchive(path, chosen, bytes, error);
                    options.displayPath = chosen + " (из архива " + pathToUtf8(path.filename()) + ")";
                    options.name = pathToUtf8(pathFromUtf8(chosen).filename());
                }
            }
            else
            {
                ok = readFile(path, bytes, error);
                options.displayPath = pathToUtf8(path);
                options.name = pathToUtf8(path.filename());
                options.sourcePath = path;
            }
            if (ok)
            {
                job->analysis = make_unique<Analysis>();
                runAnalysis(bytes, options, *job->analysis, job->files);
            }
            else if (job->members.empty())
                job->error = error.empty() ? "файл не удалось прочитать" : error;
        }
        catch (const exception& e)
        {
            job->analysis.reset();
            job->error = string("анализ прерван: ") + e.what();
        }
        if (!PostMessageW(hwnd, WM_JOB_DONE, 0, (LPARAM)job.get()))
            return;
        job.release();
    }).detach();
}

void finishJob(unique_ptr<Job> job)
{
    if (job->generation != app.generation)
        return;
    KillTimer(app.hwnd, 1);
    if (job->analysis)
    {
        app.a = move(job->analysis);
        app.files = job->files;
        app.screen = S_RESULT;
        app.tab = T_BEHAVIOR;
        app.scroll = 0;
        app.expanded.clear();
        // первой раскрывается самая опасная цепочка
        int top = -1;
        for (int i = 0; i < (int)app.a->behaviors.size(); i++)
            if (top < 0 || app.a->behaviors[i].severity > app.a->behaviors[top].severity)
                top = i;
        if (top >= 0)
            app.expanded.insert(top);
        app.itemsValid = false;
    }
    else if (!job->members.empty())
    {
        app.members = job->members;
        app.pickArchive = job->archive;
        app.screen = S_PICK;
    }
    else
    {
        app.errorText = L"Файл не проверен: " + safeText(job->error) + L". Проверьте путь и выберите файл ещё раз.";
        app.screen = S_IDLE;
    }
    redraw();
}

void chooseFile()
{
    wchar_t file[MAX_PATH * 4] = L"";
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = app.hwnd;
    ofn.lpstrFilter = L"Исполняемые файлы и архивы\0*.exe;*.dll;*.bin;*.rar;*.zip;*.7z\0Все файлы\0*.*\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH * 4;
    ofn.lpstrTitle = L"ExeIAS: выберите файл для проверки";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetOpenFileNameW(&ofn))
        startJob(file, "");
}

void activate(int id)
{
    if (id == H_CHOOSE)
        chooseFile();
    else if (id == H_REPORT)
    {
        wstring arg = L"\"" + app.files.report.wstring() + L"\"";
        ShellExecuteW(app.hwnd, L"open", L"notepad.exe", arg.c_str(), nullptr, SW_SHOWNORMAL);
    }
    else if (id == H_FOLDER)
    {
        wstring args = L"/select,\"" + app.files.report.wstring() + L"\"";
        ShellExecuteW(app.hwnd, L"open", L"explorer.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
    }
    else if (id >= H_TOGGLE0)
    {
        int i = id - H_TOGGLE0;
        if (!app.expanded.erase(i))
            app.expanded.insert(i);
        app.itemsValid = false;
        redraw();
    }
    else if (id >= H_MEMBER0)
    {
        size_t i = id - H_MEMBER0;
        if (i < app.members.size())
            startJob(app.pickArchive, app.members[i]);
    }
    else if (id >= H_TAB0)
        setTab(id - H_TAB0);
}

int hitAt(float x, float y)
{
    for (auto it = app.hits.rbegin(); it != app.hits.rend(); ++it)
        if (x >= it->r.left && x < it->r.right && y >= it->r.top && y < it->r.bottom)
            return it->id;
    return H_NONE;
}

// ---------------------------------------------------------------- окно

float toDip(int px) { return px * 96.0f / app.dpi; }

LRESULT CALLBACK wndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        BeginPaint(hwnd, &ps);
        paint();
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_SIZE:
    {
        app.W = toDip(LOWORD(lp));
        app.H = toDip(HIWORD(lp));
        if (app.rt)
            app.rt->Resize(D2D1::SizeU(LOWORD(lp), HIWORD(lp)));
        app.itemsValid = false;
        redraw();
        return 0;
    }
    case WM_DPICHANGED:
    {
        app.dpi = (float)LOWORD(wp);
        if (app.rt)
            app.rt->SetDpi(app.dpi, app.dpi);
        const RECT* r = (const RECT*)lp;
        SetWindowPos(hwnd, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top, SWP_NOZORDER | SWP_NOACTIVATE);
        return 0;
    }
    case WM_GETMINMAXINFO:
    {
        MINMAXINFO* m = (MINMAXINFO*)lp;
        m->ptMinTrackSize.x = (LONG)(1080 * app.dpi / 96);
        m->ptMinTrackSize.y = (LONG)(690 * app.dpi / 96);
        return 0;
    }
    case WM_MOUSEMOVE:
    {
        float x = toDip((short)LOWORD(lp)), y = toDip((short)HIWORD(lp));
        if (app.draggingThumb)
        {
            float clipH = viewH(), thumbH = max(clipH * clipH / app.contentHeight, 40.0f);
            float travel = max(clipH - thumbH, 1.0f);
            app.scroll = app.dragStartScroll + (y - app.dragStartY) * (app.contentHeight - clipH) / travel;
            app.scroll = max(0.0f, min(app.scroll, app.contentHeight - clipH));
            redraw();
            return 0;
        }
        int h = hitAt(x, y);
        if (h != app.hot)
        {
            app.hot = h;
            redraw();
        }
        return 0;
    }
    case WM_SETCURSOR:
        if (LOWORD(lp) == HTCLIENT)
        {
            SetCursor(LoadCursorW(nullptr, app.hot != H_NONE ? IDC_HAND : IDC_ARROW));
            return TRUE;
        }
        break;
    case WM_LBUTTONDOWN:
    {
        float x = toDip((short)LOWORD(lp)), y = toDip((short)HIWORD(lp));
        int h = hitAt(x, y);
        if (h == H_THUMB)
        {
            app.draggingThumb = true;
            app.dragStartY = y;
            app.dragStartScroll = app.scroll;
            SetCapture(hwnd);
        }
        else if (h != H_NONE)
            activate(h);
        return 0;
    }
    case WM_LBUTTONUP:
        if (app.draggingThumb)
        {
            app.draggingThumb = false;
            ReleaseCapture();
            redraw();
        }
        return 0;
    case WM_MOUSEWHEEL:
        scrollBy(-GET_WHEEL_DELTA_WPARAM(wp) / 120.0f * 70);
        return 0;
    case WM_KEYDOWN:
    {
        bool ctrl = GetKeyState(VK_CONTROL) < 0;
        if (wp >= '1' && wp < '1' + T_COUNT)
            setTab((int)wp - '1');
        else if (wp == 'O' && ctrl)
            chooseFile();
        else if (wp == VK_DOWN) scrollBy(50);
        else if (wp == VK_UP) scrollBy(-50);
        else if (wp == VK_NEXT) scrollBy(viewH() * 0.85f);
        else if (wp == VK_PRIOR) scrollBy(-viewH() * 0.85f);
        else if (wp == VK_HOME) scrollBy(-app.contentHeight);
        else if (wp == VK_END) scrollBy(app.contentHeight);
        else if (wp == VK_TAB)
        {
            vector<int> order = { H_CHOOSE };
            if (app.screen == S_RESULT)
            {
                order.push_back(H_REPORT);
                order.push_back(H_FOLDER);
            }
            auto it = find(order.begin(), order.end(), app.focus);
            app.focus = it == order.end() || it + 1 == order.end() ? order[0] : *(it + 1);
            redraw();
        }
        else if ((wp == VK_RETURN || wp == VK_SPACE) && app.focus != H_NONE)
            activate(app.focus);
        return 0;
    }
    case WM_DROPFILES:
    {
        HDROP drop = (HDROP)wp;
        wchar_t file[MAX_PATH * 4];
        if (DragQueryFileW(drop, 0, file, MAX_PATH * 4))
            startJob(file, "");
        DragFinish(drop);
        return 0;
    }
    case WM_TIMER:
        app.animPhase += 0.015f;
        if (app.animPhase > 1)
            app.animPhase = 0;
        redraw();
        return 0;
    case WM_JOB_DONE:
        finishJob(unique_ptr<Job>((Job*)lp));
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show)
{
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    wchar_t selfBuf[MAX_PATH * 4];
    DWORD n = GetModuleFileNameW(nullptr, selfBuf, MAX_PATH * 4);
    app.self = fs::path(wstring(selfBuf, n));

    D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, app.d2d.GetAddressOf());
    DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory), (IUnknown**)app.dw.GetAddressOf());
    if (!app.d2d || !app.dw)
        return 1;

    BOOL anim = TRUE;
    SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, &anim, 0);
    app.animate = anim != FALSE;

    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = wndProc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(nullptr, IDI_SHIELD);
    wc.lpszClassName = L"ExeIASGui";
    RegisterClassExW(&wc);

    RECT work;
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    UINT dpi = GetDpiForSystem();
    int w = min(MulDiv(1320, dpi, 96), (int)(work.right - work.left));
    int h = min(MulDiv(840, dpi, 96), (int)(work.bottom - work.top));
    app.hwnd = CreateWindowExW(WS_EX_ACCEPTFILES, wc.lpszClassName, L"ExeIAS: анализ исполняемых файлов. Разработка РТУ МИРЭА",
                               WS_OVERLAPPEDWINDOW, work.left + (work.right - work.left - w) / 2, work.top + (work.bottom - work.top - h) / 2,
                               w, h, nullptr, nullptr, instance, nullptr);
    if (!app.hwnd)
        return 1;
    app.dpi = (float)GetDpiForWindow(app.hwnd);
    RECT rc;
    GetClientRect(app.hwnd, &rc);
    app.W = toDip(rc.right);
    app.H = toDip(rc.bottom);
    ShowWindow(app.hwnd, show);
    UpdateWindow(app.hwnd);

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv && argc > 1)
        startJob(argv[1], "");
    if (argv)
        LocalFree(argv);

    MSG m;
    while (GetMessageW(&m, nullptr, 0, 0))
    {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    return (int)m.wParam;
}
