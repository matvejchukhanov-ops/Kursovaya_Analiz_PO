// Графический интерфейс ExeIAS: родное окно Windows, отрисовка Direct2D и DirectWrite.
// Использует те же модули анализа, что и консольная версия, внешних библиотек нет.
// Запуск: ExeIAS_GUI.exe [файл или архив]. Клавиши: 1–6 — разделы итога, Ctrl+O — выбрать файл, Tab и Enter — кнопки.

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
#ifdef EXEIAS_SELFTEST
#include <shlobj.h>
#endif
#include <d2d1.h>
#include <dwrite_1.h>
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
#include <ctime>
#include <fstream>
#include <map>
#include <memory>
#include <thread>

using Microsoft::WRL::ComPtr;

// ---------------------------------------------------------------- оформление

D2D1_COLOR_F rgb(uint32_t c, float a = 1.0f)
{
    return { ((c >> 16) & 255) / 255.0f, ((c >> 8) & 255) / 255.0f, (c & 255) / 255.0f, a };
}

const uint32_t C_WHITE = 0xFFFFFF, C_INK = 0x0E1422, C_MUTED = 0x3D4657, C_DIM = 0x5A6378, C_RULE = 0xE2E5EB, C_SOFT = 0xF0F2F6;
const uint32_t C_ACCENT = 0x2456F0, C_ACCENT_HOT = 0x1A3FB8;
const uint32_t C_ON_DARK = 0xC5CCDA, C_ON_DARK_DIM = 0xA9B2C5, C_ON_DARK_FAINT = 0x8D97AC;
const uint32_t C_DARK_RULE = 0x2A3347, C_DARK_LINE = 0x3A4459, C_DARK_HOVER = 0x222B3D, C_DASH = 0x4A5570;
const uint32_t C_CODE = 0xE3E8F2, C_ADDR = 0x7F9BE8, C_DANGER = 0xE5484D;

// В макете Onest и JetBrains Mono; в системе их нет, поэтому берутся запасные шрифты, указанные в самом макете
const wchar_t* const FONT_UI = L"Segoe UI";
const wchar_t* const FONT_MONO = L"Consolas";

const DWRITE_FONT_WEIGHT W_NORMAL = DWRITE_FONT_WEIGHT_NORMAL, W_MEDIUM = DWRITE_FONT_WEIGHT_MEDIUM,
                         W_SEMI = DWRITE_FONT_WEIGHT_SEMI_BOLD, W_BOLD = DWRITE_FONT_WEIGHT_BOLD;

struct Pill
{
    uint32_t back, text;
    const wchar_t* word;
};

Pill pillOf(Severity s)
{
    switch (s)
    {
    case CRITICAL: return { 0xFFE0E0, 0x9B1C1C, L"Критическая" };
    case HIGH:     return { 0xFFE3D1, 0x9A3B00, L"Высокая" };
    case MEDIUM:   return { 0xFFF1D6, 0x7A4B00, L"Средняя" };
    case LOW:      return { 0xDDF3E6, 0x17603A, L"Низкая" };
    default:       return { C_SOFT, C_DIM, L"Нет" };
    }
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

// 1250000 -> «1 250 000 ₽»
wstring rub(double value)
{
    wstring s = safeText(formatRub(value));
    size_t p = s.rfind(L" руб.");
    return (p == wstring::npos ? s : s.substr(0, p)) + L" ₽";
}

// ---------------------------------------------------------------- состояние

enum Page { P_CHECK, P_REPORTS, P_MODEL, P_ABOUT, P_COUNT };
enum Screen { S_IDLE, S_BUSY, S_PICK, S_RESULT };
enum Tab { T_BEHAVIOR, T_CALLS, T_VULN, T_IOC, T_DAMAGE, T_TODO, T_COUNT };
enum HitId
{
    H_NONE, H_CHOOSE, H_REPORT, H_FOLDER, H_COPY, H_THUMB, H_LOGO, H_CANCEL, H_OPEN_REPORTS,
    H_NAV0 = 50, H_TAB0 = 100, H_MEMBER0 = 200, H_REPORTFILE0 = 2000, H_TOGGLE0 = 5000, H_SHOWALL0 = 7000, H_CWE0 = 10000
};

struct Hit
{
    D2D1_RECT_F r;
    int id;
};

// Элемент прокручиваемой области: текст или прямоугольник. action — что происходит по щелчку
struct Item
{
    float x = 0, y = 0, w = 0, h = 0;
    ComPtr<IDWriteTextLayout> layout;
    D2D1_COLOR_F color = {};
    float radius = 0;
    int action = -1;
    bool hoverOnly = false;     // подсветка строки: видна только под указателем
};

struct Job
{
    int generation = 0;
    unique_ptr<Analysis> analysis;
    RunFiles files;
    vector<string> members;
    fs::path archive;
    string error;
};

struct ReportFile
{
    fs::path path;
    wstring name, when;
};

const UINT WM_JOB_DONE = WM_APP + 1;
const UINT_PTR TIMER_ANIM = 1, TIMER_COPIED = 2;

struct App
{
    HWND hwnd = nullptr;
    ComPtr<ID2D1Factory> d2d;
    ComPtr<IDWriteFactory> dw;
    ComPtr<ID2D1HwndRenderTarget> rt;
    ComPtr<ID2D1SolidColorBrush> brush;
    ComPtr<ID2D1StrokeStyle> dashed, rounded;
    map<wstring, ComPtr<IDWriteTextFormat>> formats;

    float dpi = 96, W = 1280, H = 860;
    fs::path self;

    Page page = P_CHECK;
    Screen screen = S_IDLE;
    int generation = 0;
    wstring busyName, errorText;
    fs::path pickArchive;
    vector<string> members;
    vector<ReportFile> reports;

    unique_ptr<Analysis> a;
    RunFiles files;
    int tab = T_BEHAVIOR;
    set<int> expanded, showAll;
    bool copied = false;

    vector<Item> items;
    float itemsHeight = 0;
    bool itemsValid = false;

    float regionTop = 56, pageH = 0, scroll = 0;
    vector<Hit> hits;
    int hot = H_NONE, focus = H_NONE;
    bool draggingThumb = false;
    float dragStartY = 0, dragStartScroll = 0;
    float animPhase = 0;
    bool animate = true;
    wstring lastShell;
} app;

const float HEADER_H = 56, FOOTER_H = 32, PAD_X = 40;
const int FUZZ_DEFAULT = 40;

float bodyW() { return min(app.W - PAD_X * 2, 1400.0f); }
float regionBottom() { return app.H - FOOTER_H; }
float viewH() { return max(regionBottom() - app.regionTop, 1.0f); }

// ---------------------------------------------------------------- текст

IDWriteTextFormat* fmt(const wchar_t* family, float size, DWRITE_FONT_WEIGHT weight = W_NORMAL)
{
    wstring key = wstring(family) + L"|" + to_wstring(size) + L"|" + to_wstring((int)weight);
    auto it = app.formats.find(key);
    if (it != app.formats.end())
        return it->second.Get();
    ComPtr<IDWriteTextFormat> f;
    app.dw->CreateTextFormat(family, nullptr, weight, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, size, L"ru-ru", &f);
    f->SetWordWrapping(DWRITE_WORD_WRAPPING_EMERGENCY_BREAK);
    app.formats[key] = f;
    return f.Get();
}

IDWriteTextFormat* ui(float size, DWRITE_FONT_WEIGHT weight = W_NORMAL) { return fmt(FONT_UI, size, weight); }
IDWriteTextFormat* mono(float size, DWRITE_FONT_WEIGHT weight = W_NORMAL) { return fmt(FONT_MONO, size, weight); }

ComPtr<IDWriteTextLayout> makeLayout(const wstring& text, IDWriteTextFormat* f, float width, float tracking = 0)
{
    ComPtr<IDWriteTextLayout> l;
    app.dw->CreateTextLayout(text.c_str(), (UINT32)text.length(), f, max(width, 1.0f), 10000.0f, &l);
    if (tracking != 0)
    {
        ComPtr<IDWriteTextLayout1> l1;
        if (SUCCEEDED(l.As(&l1)))
            l1->SetCharacterSpacing(0, tracking, 0, { 0, (UINT32)text.length() });
    }
    return l;
}

float heightOf(IDWriteTextLayout* l)
{
    DWRITE_TEXT_METRICS m = {};
    l->GetMetrics(&m);
    return m.height;
}

float widthOf(IDWriteTextLayout* l)
{
    DWRITE_TEXT_METRICS m = {};
    l->GetMetrics(&m);
    return m.widthIncludingTrailingWhitespace;
}

float textWidth(const wstring& text, IDWriteTextFormat* f)
{
    auto l = makeLayout(text, f, 4000);
    return widthOf(l.Get());
}

// ---------------------------------------------------------------- рисование: примитивы

void fillRect(float x, float y, float w, float h, D2D1_COLOR_F c)
{
    app.brush->SetColor(c);
    app.rt->FillRectangle(D2D1::RectF(x, y, x + w, y + h), app.brush.Get());
}

void fillRound(float x, float y, float w, float h, float r, D2D1_COLOR_F c)
{
    app.brush->SetColor(c);
    app.rt->FillRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(x, y, x + w, y + h), r, r), app.brush.Get());
}

void strokeRound(float x, float y, float w, float h, float r, D2D1_COLOR_F c, float width = 1, ID2D1StrokeStyle* style = nullptr)
{
    app.brush->SetColor(c);
    app.rt->DrawRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(x, y, x + w, y + h), r, r), app.brush.Get(), width, style);
}

void drawLayout(IDWriteTextLayout* l, float x, float y, D2D1_COLOR_F c)
{
    app.brush->SetColor(c);
    app.rt->DrawTextLayout(D2D1::Point2F(x, y), l, app.brush.Get());
}

float drawText(const wstring& text, IDWriteTextFormat* f, float x, float y, float width, D2D1_COLOR_F c, float tracking = 0)
{
    auto l = makeLayout(text, f, width, tracking);
    drawLayout(l.Get(), x, y, c);
    return heightOf(l.Get());
}

void drawCentered(const wstring& text, IDWriteTextFormat* f, float x, float y, float w, float h, D2D1_COLOR_F c)
{
    auto l = makeLayout(text, f, w);
    l->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
    drawLayout(l.Get(), x, y + (h - heightOf(l.Get())) / 2, c);
}

// Зона щелчка обрезается по текущей видимой области
void addHit(float x, float y, float w, float h, int id, float clipTop = 0, float clipBottom = 100000)
{
    float top = max(y, clipTop), bottom = min(y + h, clipBottom);
    if (bottom > top)
        app.hits.push_back({ D2D1::RectF(x, top, x + w, bottom), id });
}

enum ButtonKind { B_ACCENT, B_OUTLINE_DARK };

void button(const wstring& text, float x, float y, float w, float h, int id, ButtonKind kind, IDWriteTextFormat* f,
            float clipTop = 0, float clipBottom = 100000)
{
    bool hot = app.hot == id;
    if (kind == B_ACCENT)
        fillRound(x, y, w, h, 6, rgb(hot ? C_ACCENT_HOT : C_ACCENT));
    else
    {
        if (hot)
            fillRound(x, y, w, h, 6, rgb(C_DARK_HOVER));
        strokeRound(x + 0.5f, y + 0.5f, w - 1, h - 1, 6, rgb(C_DARK_LINE));
    }
    drawCentered(text, f, x, y, w, h, rgb(C_WHITE));
    if (app.focus == id)
        strokeRound(x - 3, y - 3, w + 6, h + 6, 8, rgb(kind == B_ACCENT ? C_ACCENT : C_WHITE), 2);
    addHit(x, y, w, h, id, clipTop, clipBottom);
}

// ---------------------------------------------------------------- итог: вывод и балл

bool hasDestroy(const Analysis& a)
{
    for (const Behavior& b : a.behaviors)
        if (b.code == "DESTROY")
            return true;
    return false;
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

int scoreZone(int score) { return score < 20 ? 0 : score < 45 ? 1 : score < 70 ? 2 : 3; }

uint32_t zoneColor(int zone)
{
    const uint32_t colors[] = { 0x3DDC84, 0xFFC24A, 0xFF8A3D, 0xFF5C5C };
    return colors[zone];
}

size_t countVuln(const Analysis& a)
{
    size_t n = 0;
    for (const Finding& f : a.findings)
        n += f.block == BLOCK_VULN || f.block == BLOCK_LANG;
    return n;
}

size_t countIoc(const Analysis& a)
{
    size_t n = 0;
    for (const Finding& f : a.findings)
        n += f.block == BLOCK_IOC;
    return n;
}

// ---------------------------------------------------------------- содержимое прокручиваемой области

struct Builder
{
    float y = 0, width = 0;

    Item& add(Item it)
    {
        app.items.push_back(move(it));
        return app.items.back();
    }

    // Текст без сдвига строки вниз; возвращает высоту
    float textAt(const wstring& text, IDWriteTextFormat* f, uint32_t color, float x, float yy, float w, int action = -1, float tracking = 0)
    {
        auto l = makeLayout(text, f, w, tracking);
        float h = heightOf(l.Get());
        Item it;
        it.x = x; it.y = yy; it.w = action >= 0 ? min(widthOf(l.Get()), w) : w; it.h = h;
        it.layout = l; it.color = rgb(color); it.action = action;
        add(move(it));
        return h;
    }

    float text(const wstring& s, IDWriteTextFormat* f, uint32_t color, float after = 6, float x = 0, int action = -1)
    {
        float h = textAt(s, f, color, x, y, width - x, action);
        y += h + after;
        return h;
    }

    void box(float x, float yy, float w, float h, uint32_t color, float alpha = 1, float radius = 0)
    {
        Item it;
        it.x = x; it.y = yy; it.w = w; it.h = h; it.color = rgb(color, alpha); it.radius = radius;
        add(move(it));
    }

    void buttonItem(const wstring& s, float x, float yy, int action)
    {
        auto f = ui(14, W_SEMI);
        float w = textWidth(s, f) + 36;
        Item bg;
        bg.x = x; bg.y = yy; bg.w = w; bg.h = 40; bg.color = rgb(C_ACCENT); bg.radius = 6; bg.action = action;
        add(move(bg));
        auto l = makeLayout(s, f, w);
        l->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
        Item t;
        t.x = x; t.y = yy + (40 - heightOf(l.Get())) / 2; t.w = w; t.h = 20; t.layout = l; t.color = rgb(C_WHITE);
        add(move(t));
    }

    void rule(uint32_t color = C_RULE, float thickness = 1) { box(0, y, width, thickness, color); y += thickness; }
};

// Размеры колонок таблицы находок из макета
const float COL_LEVEL = 130, COL_TAG = 110, COL_COUNT = 60;

void tableHeader(Builder& b, const wstring& main, const wstring& tag, const wstring& count)
{
    auto f = mono(11.5f, W_MEDIUM);
    float xTag = b.width - COL_TAG - COL_COUNT, h = 0;
    b.textAt(L"уровень", f, C_DIM, 0, b.y + 8, COL_LEVEL);
    h = b.textAt(main, f, C_DIM, COL_LEVEL, b.y + 8, xTag - COL_LEVEL);
    b.textAt(tag, f, C_DIM, xTag, b.y + 8, COL_TAG);
    auto l = makeLayout(count, f, COL_COUNT);
    l->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_TRAILING);
    Item it;
    it.x = b.width - COL_COUNT; it.y = b.y + 8; it.w = COL_COUNT; it.h = h; it.layout = l; it.color = rgb(C_DIM);
    b.add(move(it));
    b.y += h + 16;
    b.rule(C_INK, 2);
}

void pillItem(Builder& b, Severity s, float x, float yy)
{
    Pill p = pillOf(s);
    auto f = ui(12, W_SEMI);
    auto l = makeLayout(p.word, f, 200);
    float w = widthOf(l.Get()) + 16, h = heightOf(l.Get()) + 6;
    b.box(x, yy, w, h, p.back, 1, 4);
    Item it;
    it.x = x + 8; it.y = yy + 3; it.w = w; it.h = h; it.layout = l; it.color = rgb(p.text);
    b.add(move(it));
}

// Тёмный блок машинного кода: адреса отдельным цветом, строки «//» — пояснения к вызову выше
void codeBlock(Builder& b, const vector<wstring>& lines, float x, float width)
{
    if (lines.empty())
        return;
    size_t bgIndex = app.items.size();
    b.box(x, b.y, width, 0, C_INK, 1, 6);
    float top = b.y;
    b.y += 10;
    auto f = mono(12);
    float inner = width - 24;
    for (const wstring& line : lines)
    {
        size_t cut = line.rfind(L"0x", 0) == 0 ? line.find(L' ') : wstring::npos;
        if (cut != wstring::npos)
        {
            wstring addr = line.substr(0, cut);
            size_t next = line.find_first_not_of(L' ', cut);
            wstring rest = next == wstring::npos ? L"" : line.substr(next);
            float addrW = textWidth(addr, f) + 14;
            b.textAt(addr, f, C_ADDR, x + 12, b.y, addrW);
            b.y += b.textAt(rest, f, C_CODE, x + 12 + addrW, b.y, inner - addrW) + 5;
        }
        else if (line.rfind(L"//", 0) == 0)
            b.y += b.textAt(line.substr(2), f, C_ON_DARK_DIM, x + 26, b.y, inner - 14) + 5;
        else
            b.y += b.textAt(line, f, C_CODE, x + 12, b.y, inner) + 5;
    }
    b.y += 5;
    app.items[bgIndex].h = b.y - top;
}

struct Row
{
    Severity severity = NONE;
    wstring title, desc, descCode, details;
    vector<wstring> code;
    wstring moreText;
    int moreAction = -1;
    wstring tag;
    int tagAction = -1;
    wstring count = L"—";
    int rowAction = -1;
    bool last = false;
};

void addRow(Builder& b, const Row& r)
{
    float top = b.y, xTag = b.width - COL_TAG - COL_COUNT, mainW = xTag - COL_LEVEL - 16;
    size_t hoverIndex = app.items.size();
    if (r.rowAction >= 0)
    {
        Item hv;
        hv.x = -8; hv.y = top; hv.w = b.width + 16; hv.color = rgb(C_SOFT); hv.action = r.rowAction; hv.hoverOnly = true;
        b.add(move(hv));
    }
    pillItem(b, r.severity, 0, top + 12);
    b.y = top + 12;
    b.y += b.textAt(r.title, ui(14.5f, W_SEMI), C_INK, COL_LEVEL, b.y, mainW);
    if (!r.desc.empty() || !r.descCode.empty())
    {
        b.y += 3;
        wstring both = r.desc;
        if (!r.descCode.empty())
        {
            float descH = 0;
            if (!r.desc.empty())
            {
                descH = b.textAt(r.desc, ui(13.5f), C_MUTED, COL_LEVEL, b.y, mainW);
                b.y += descH + 2;
            }
            b.y += b.textAt(r.descCode, mono(12.5f), C_MUTED, COL_LEVEL, b.y, mainW);
        }
        else
            b.y += b.textAt(both, ui(13.5f), C_MUTED, COL_LEVEL, b.y, mainW);
    }
    if (!r.details.empty())
    {
        b.y += 8;
        b.y += b.textAt(r.details, ui(13.5f), C_INK, COL_LEVEL, b.y, mainW);
    }
    if (!r.code.empty())
    {
        b.y += 10;
        codeBlock(b, r.code, COL_LEVEL, mainW);
    }
    if (r.moreAction >= 0)
    {
        b.y += 8;
        b.y += b.textAt(r.moreText, ui(12.5f, W_MEDIUM), C_ACCENT, COL_LEVEL, b.y, mainW, r.moreAction);
    }
    b.textAt(r.tag, mono(12.5f, W_MEDIUM), r.tagAction >= 0 ? C_ACCENT : C_INK, xTag, top + 12, COL_TAG, r.tagAction);
    auto l = makeLayout(r.count, mono(13.5f), COL_COUNT);
    l->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_TRAILING);
    Item cnt;
    cnt.x = b.width - COL_COUNT; cnt.y = top + 12; cnt.w = COL_COUNT; cnt.h = 20; cnt.layout = l; cnt.color = rgb(C_INK);
    b.add(move(cnt));
    b.y += 12;
    if (r.rowAction >= 0)
        app.items[hoverIndex].h = b.y - top;
    if (!r.last)
        b.rule();
}

int cweAction(const string& cwe)
{
    if (cwe.rfind("CWE-", 0) != 0 || cwe.length() > 9)
        return -1;
    int n = 0;
    for (size_t i = 4; i < cwe.length(); i++)
    {
        if (cwe[i] < '0' || cwe[i] > '9')
            return -1;
        n = n * 10 + (cwe[i] - '0');
    }
    return H_CWE0 + n;
}

wstring trimToolchain(const string& toolchain)
{
    size_t p = toolchain.find(" (версия компоновщика");
    return safeText(p == NPOS ? toolchain : toolchain.substr(0, p));
}

// Все строки-примеры находки: для ошибок в коде берутся из карты кода, в находке их только шесть
vector<string> allExamples(const Analysis& a, const Finding& f)
{
    if (f.block != BLOCK_LANG || f.source != "машинный код")
        return f.examples;
    vector<string> all;
    for (const FunctionInfo& fn : a.code.functions)
        for (const CodeIssue& issue : fn.issues)
            if (issue.cwe == f.cwe)
                all.push_back(hexVa(issue.addr) + "  " + issue.text);
    return all.empty() ? f.examples : all;
}

void addFindingRow(Builder& b, const Analysis& a, const Finding& f, int index)
{
    Row r;
    r.severity = f.severity;
    bool lang = f.block == BLOCK_LANG;
    r.title = safeText(lang ? f.signature : f.incident);
    if (lang)
        r.desc = safeText(f.incident);
    else
    {
        r.desc = safeText(f.cweName);
        r.descCode = safeText(f.signature, 160);
    }
    vector<string> examples = allExamples(a, f);
    bool open = app.showAll.count(index) > 0;
    size_t limit = open ? 200 : 3;
    bool codeLike = lang && f.source == "машинный код";
    if (codeLike || !lang)
        for (size_t i = 0; i < examples.size() && i < limit; i++)
        {
            wstring line = safeText(examples[i]);
            if (CompareStringOrdinal(line.c_str(), -1, r.descCode.c_str(), -1, TRUE) != CSTR_EQUAL)
                r.code.push_back(line);
        }
    if (examples.size() > 3)
    {
        r.moreAction = H_SHOWALL0 + index;
        r.moreText = open ? L"Свернуть" : L"Показать все " + to_wstring(examples.size());
    }
    r.tag = f.cwe.empty() ? L"—" : safeText(f.cwe);
    r.tagAction = cweAction(f.cwe);
    if (f.hits > 1)
        r.count = to_wstring(f.hits);
    addRow(b, r);
}

void buildBehavior(Builder& b, const Analysis& a)
{
    if (a.behaviors.empty())
    {
        b.text(a.code.done ? L"В машинном коде нет связанных цепочек операций с файлами, реестром и запуском программ."
                           : L"Машинный код не разобран: " + safeText(a.code.note), ui(15), C_INK);
        b.text(L"Находки по строкам и импорту смотрите в разделах «Уязвимости» и «Индикаторы».", ui(14), C_MUTED);
        return;
    }
    vector<int> order;
    for (int i = 0; i < (int)a.behaviors.size(); i++)
        order.push_back(i);
    stable_sort(order.begin(), order.end(), [&](int x, int y) { return a.behaviors[x].severity > a.behaviors[y].severity; });

    tableHeader(b, L"цепочка поведения", L"att&ck", L"вызовы");
    for (size_t k = 0; k < order.size(); k++)
    {
        const Behavior& bh = a.behaviors[order[k]];
        bool open = app.expanded.count(order[k]) > 0;
        Row r;
        r.severity = bh.severity;
        r.title = safeText(bh.title);
        r.desc = fromUtf8("Функция sub_" + hexPlain(bh.func) + ". " + bh.attackName + ". ")
               + (open ? L"Свернуть" : L"Показать подробности");
        if (open)
        {
            r.details = capFirst(safeText(bh.details));
            for (const string& e : bh.evidence)
                r.code.push_back(safeText(e));
        }
        r.tag = safeText(bh.attack);
        r.count = to_wstring(bh.evidence.size());
        r.rowAction = H_TOGGLE0 + order[k];
        r.last = k + 1 == order.size();
        addRow(b, r);
    }
}

void buildCalls(Builder& b, const Analysis& a)
{
    if (!a.code.done)
    {
        b.text(L"Машинный код не разобран: " + safeText(a.code.note), ui(15), C_INK);
        return;
    }
    b.text(L"Найдено функций: " + to_wstring(a.code.functions.size()) + L". Аргументы восстановлены у "
           + to_wstring(a.code.resolvedCalls) + L" вызовов, файл при этом не запускался. var_N — буфер в стеке функции, "
           L"arg_N — её аргумент, ? — значение восстановить не удалось.", ui(13.5f), C_MUTED, 18);

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
        b.text(fromUtf8("Функция sub_" + hexPlain(f.start)) + (f.recursive ? L", вызывает сама себя" : L""), ui(15, W_SEMI), C_INK, 3);
        if (roles.count(f.start))
        {
            wstring text;
            for (const string& r : roles[f.start])
                text += (text.empty() ? L"" : L"; ") + safeText(r);
            b.text(text, ui(13), C_MUTED, 4);
        }
        b.y += 6;
        vector<wstring> lines;
        for (const CallSite* c : calls)
        {
            shownLines++;
            lines.push_back(fromUtf8(hexVa(c->addr)) + L"  " + safeText(formatCall(*c)));
            string meaning = callNote(*c);
            if (!meaning.empty())
                lines.push_back(L"//" + capFirst(safeText(meaning)));
        }
        codeBlock(b, lines, 0, b.width);
        b.y += 22;
    }
    if (shownFunctions == 0)
        b.text(L"Функций, работающих с файлами и реестром, не найдено.", ui(15), C_INK);
}

void buildVuln(Builder& b, const Analysis& a)
{
    tableHeader(b, L"находка", L"cwe", L"кол-во");
    size_t n = 0;
    for (size_t i = 0; i < a.findings.size(); i++)
        if (a.findings[i].block == BLOCK_VULN && n++ < 100)
            addFindingRow(b, a, a.findings[i], (int)i);
    if (n == 0)
    {
        b.y += 12;
        b.text(L"Признаков уязвимостей не найдено.", ui(14), C_MUTED, 12);
        b.rule();
    }
    b.y += 16;
    float h = b.textAt(L"Ошибки в коде", ui(14, W_SEMI), C_INK, 0, b.y, 120);
    b.textAt(L"· на балл риска не влияют. Язык: " + safeText(a.lang.language), ui(12.5f), C_DIM, 112, b.y + 1, b.width - 112);
    b.y += h + 6;
    b.rule();
    n = 0;
    for (size_t i = 0; i < a.findings.size(); i++)
        if (a.findings[i].block == BLOCK_LANG && n++ < 100)
            addFindingRow(b, a, a.findings[i], (int)i);
    if (n == 0)
    {
        b.y += 12;
        b.text(L"Таких ошибок не найдено.", ui(14), C_MUTED);
    }
}

void buildIoc(Builder& b, const Analysis& a)
{
    vector<string> iocs = collectIocs(a);
    if (!iocs.empty())
    {
        b.text(L"Что искать на других компьютерах и блокировать", ui(15, W_SEMI), C_INK, 8);
        vector<wstring> lines;
        for (const string& s : iocs)
            lines.push_back(safeText(s));
        codeBlock(b, lines, 0, b.width);
        b.y += 24;
    }
    size_t n = 0;
    for (const Finding& f : a.findings)
        n += f.block == BLOCK_IOC;
    if (n == 0)
    {
        if (iocs.empty())
            b.text(L"Индикаторов компрометации не найдено.", ui(15), C_INK);
        return;
    }
    tableHeader(b, L"находка", L"cwe", L"кол-во");
    size_t shown = 0;
    for (size_t i = 0; i < a.findings.size(); i++)
        if (a.findings[i].block == BLOCK_IOC && shown++ < 100)
            addFindingRow(b, a, a.findings[i], (int)i);
}

void buildDamage(Builder& b, const Analysis& a)
{
    const EconomicSummary& e = a.economy;
    if (e.lossExpected <= 0)
        b.text(L"Ущерб не начислен: нет находок уровня «Высокая» и выше.", ui(15), C_INK, 14);
    else
    {
        b.y += b.textAt(rub(e.lossExpected), ui(44, W_BOLD), C_INK, 0, b.y, b.width, -1, -1.3f);
        b.text(L"Ожидаемый ущерб за один инцидент, опасность " + safeText(e.level) + L". Возможный диапазон: от "
               + rub(e.lossMin) + L" до " + rub(e.lossMax) + L".", ui(14), C_MUTED, 22);

        double top = 1;
        for (const EconomicLine& l : e.lines)
            top = max(top, l.hi);
        for (const EconomicLine& l : e.lines)
        {
            b.text(capFirst(safeText(l.name)), ui(14.5f, W_SEMI), C_INK, 6);
            float scale = (float)(b.width / top), barY = b.y;
            b.box(0, barY + 6, b.width, 2, C_RULE);
            b.box((float)l.lo * scale, barY, max((float)(l.hi - l.lo) * scale, 2.0f), 14, C_ACCENT, 0.25f, 2);
            b.box((float)l.expected * scale - 2, barY - 3, 4, 20, C_ACCENT, 1, 1);
            b.y += 24;
            b.text(L"Ожидаемо " + rub(l.expected) + L", от " + rub(l.lo) + L" до " + rub(l.hi), ui(13), C_MUTED, 18);
        }
        b.text(L"Светлая полоса показывает диапазон, тёмная отметка — ожидаемое значение.", ui(12.5f), C_DIM, 12);
    }
    b.rule();
    b.y += 14;
    b.text(L"Профиль: " + safeText(a.profile.name) + L" (" + safeText(a.profile.source) + L"). Это модель для сравнения файлов, "
           L"а не прогноз потерь. Параметры и формулы показаны в разделе «Модель ущерба».", ui(13.5f), C_MUTED);
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
    {
        b.text(L"Специальных мер не требуется.", ui(15), C_INK);
        return;
    }
    b.rule(C_INK, 2);
    for (size_t i = 0; i < recs.size(); i++)
    {
        float top = b.y;
        pillItem(b, recs[i].first, 0, top + 12);
        b.y = top + 12;
        b.y += b.textAt(safeText(recs[i].second), ui(14), C_INK, COL_LEVEL, b.y, b.width - COL_LEVEL) + 12;
        if (i + 1 < recs.size())
            b.rule();
    }
}

void buildPick(Builder& b)
{
    b.y += b.textAt(L"Какой файл из архива проверить?", ui(32, W_BOLD), C_INK, 0, b.y, b.width, -1, -0.8f) + 4;
    b.text(safeText(pathToUtf8(app.pickArchive.filename())) + L". Выбранный файл читается в память и на диск не попадает.", ui(14), C_MUTED, 18);
    b.rule(C_INK, 2);
    for (size_t i = 0; i < app.members.size() && i < 500; i++)
    {
        float top = b.y;
        Item hv;
        hv.x = -8; hv.y = top; hv.w = b.width + 16; hv.h = 42; hv.color = rgb(C_SOFT); hv.action = H_MEMBER0 + (int)i; hv.hoverOnly = true;
        b.add(move(hv));
        b.textAt(safeText(app.members[i], 200), ui(14.5f, W_MEDIUM), C_INK, 0, top + 11, b.width);
        b.y = top + 42;
        b.rule();
    }
    b.y += 18;
    b.textAt(L"Отменить", ui(14, W_MEDIUM), C_ACCENT, 0, b.y, 100, H_CANCEL);
    b.y += 24;
}

void pageTitle(Builder& b, const wstring& title, const wstring& lead)
{
    b.y += b.textAt(title, ui(32, W_BOLD), C_INK, 0, b.y, b.width, -1, -0.8f) + 6;
    b.text(lead, ui(15), C_MUTED, 22);
}

void loadReports()
{
    app.reports.clear();
    error_code ec;
    fs::path dir = app.self.parent_path() / L"reports";
    vector<pair<fs::file_time_type, fs::path>> found;
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec))
    {
        string name = pathToUtf8(it->path().filename());
        if (name.rfind("report_", 0) == 0 && name.length() > 11 && name.compare(name.length() - 4, 4, ".txt") == 0)
        {
            error_code timeError;
            found.push_back({ fs::last_write_time(it->path(), timeError), it->path() });
        }
    }
    stable_sort(found.begin(), found.end(), [](const auto& x, const auto& y) { return x.first > y.first; });
    for (const auto& f : found)
    {
        string name = pathToUtf8(f.second.filename());
        ReportFile r;
        r.path = f.second;
        r.name = safeText(name.substr(7, name.length() - 11), 120);
        WIN32_FILE_ATTRIBUTE_DATA data = {};
        SYSTEMTIME utc = {}, local = {};
        if (GetFileAttributesExW(f.second.c_str(), GetFileExInfoStandard, &data) && FileTimeToSystemTime(&data.ftLastWriteTime, &utc)
            && SystemTimeToTzSpecificLocalTime(nullptr, &utc, &local))
        {
            wchar_t text[40];
            swprintf(text, 40, L"%02d.%02d.%04d, %02d:%02d", local.wDay, local.wMonth, local.wYear, local.wHour, local.wMinute);
            r.when = text;
        }
        app.reports.push_back(r);
    }
}

void buildReportsPage(Builder& b)
{
    pageTitle(b, L"Отчёты", L"Отчёты о проверках из этого окна. Щелчок открывает текстовый отчёт в Блокноте.");
    b.buttonItem(L"Открыть папку с отчётами", 0, b.y, H_OPEN_REPORTS);
    b.y += 62;
    if (app.reports.empty())
    {
        b.text(L"Отчётов пока нет. Проверьте файл в разделе «Проверка», и отчёт появится здесь.", ui(15), C_INK);
        return;
    }
    b.rule(C_INK, 2);
    for (size_t i = 0; i < app.reports.size() && i < 500; i++)
    {
        float top = b.y;
        Item hv;
        hv.x = -8; hv.y = top; hv.w = b.width + 16; hv.h = 42; hv.color = rgb(C_SOFT); hv.action = H_REPORTFILE0 + (int)i; hv.hoverOnly = true;
        b.add(move(hv));
        b.textAt(app.reports[i].name, ui(14.5f, W_MEDIUM), C_INK, 0, top + 11, b.width - 170);
        b.textAt(app.reports[i].when, mono(12.5f), C_DIM, b.width - 150, top + 13, 150);
        b.y = top + 42;
        b.rule();
    }
}

void twoColumnRow(Builder& b, const wstring& left, const wstring& right, float rightW, bool code = false)
{
    float top = b.y + 10;
    float h1 = b.textAt(left, ui(14), C_INK, 0, top, b.width - rightW - 16);
    float h2 = b.textAt(right, code ? mono(13) : ui(14, W_SEMI), C_INK, b.width - rightW, top, rightW);
    b.y = top + max(h1, h2) + 10;
    b.rule();
}

wstring plainNumber(double v)
{
    wchar_t text[32];
    swprintf(text, 32, L"%g", v);
    return text;
}

void buildModelPage(Builder& b)
{
    EconomicProfile p = app.self.empty() ? EconomicProfile() : loadProfile(app.self.parent_path() / L"economics.ini");
    pageTitle(b, L"Модель ущерба", L"Как считается ущерб за один инцидент. Это модель для сравнения файлов, а не прогноз потерь.");
    b.text(L"Параметры: " + safeText(p.name) + L" (" + safeText(p.source) + L")", ui(15, W_SEMI), C_INK, 8);
    b.rule(C_INK, 2);
    twoColumnRow(b, L"Рабочих мест в организации, N", plainNumber(p.workstations), 180);
    twoColumnRow(b, L"Потери за час простоя одного рабочего места, Cₕ", rub(p.hourCost), 180);
    twoColumnRow(b, L"Час работы специалиста ИТ и ИБ, Cₛ", rub(p.specialistHour), 180);
    twoColumnRow(b, L"Восстановление одного узла, Tᵣ", plainNumber(p.hostRebuildHours) + L" ч", 180);
    twoColumnRow(b, L"Расследование инцидента, Tᵢ", plainNumber(p.investigationHours) + L" ч", 180);
    twoColumnRow(b, L"Данные одного узла, D₁", rub(p.dataValue), 180);
    twoColumnRow(b, L"Данные в сетевых папках, D₂", rub(p.sharedDataValue), 180);
    twoColumnRow(b, L"Доля данных, восстанавливаемых из резервных копий, b", plainNumber(p.backupShare), 180);
    twoColumnRow(b, L"Штраф за утечку персональных данных, ст. 13.11 КоАП РФ", rub(p.leakFineMin) + L" – " + rub(p.leakFineMax), 260);
    b.y += 28;
    b.text(L"Формулы: минимум, максимум, ожидаемое значение", ui(15, W_SEMI), C_INK, 8);
    b.rule(C_INK, 2);
    const float formulaW = min(b.width * 0.6f, 620.0f);
    twoColumnRow(b, L"Потеря данных (T1485, T1486, T1490, T1565)", L"D₁·(1−b);  D₁+D₂;  (D₁+D₂)·(1−b)", formulaW, true);
    twoColumnRow(b, L"Простой (T1485, T1486, T1490)", L"Tᵣ·Cₕ;  Tᵣ·Cₕ·N;  среднее", formulaW, true);
    twoColumnRow(b, L"Восстановление узлов (T1547, T1546, T1036, T1055, T1112)", L"Tᵣ·Cₛ;  Tᵣ·Cₛ·N;  среднее", formulaW, true);
    twoColumnRow(b, L"Утечка данных (T1074, T1071, T1095, T1105)", L"F_min;  F_max;  среднее", formulaW, true);
    twoColumnRow(b, L"Расследование (любая находка высокого уровня)", L"Tᵢ·Cₛ/2;  Tᵢ·Cₛ·2;  Tᵢ·Cₛ", formulaW, true);
    b.y += 18;
    b.text(L"Каждый вид ущерба считается один раз, по наихудшей находке. Если признак не подтверждён машинным кодом, "
           L"минимум равен нулю, а ожидаемое значение уменьшается вдвое. Параметры меняются в файле economics.ini рядом с программой.",
           ui(14), C_MUTED);
}

void buildAboutPage(Builder& b)
{
    pageTitle(b, L"О программе", L"ExeIAS — информационно-аналитическая система статического анализа исполняемых файлов Windows.");
    const float w = min(b.width, 760.0f);
    float keep = b.width;
    b.width = w;
    b.text(L"Разработка РТУ МИРЭА, кафедра КБ-2, 2026 год.", ui(15, W_SEMI), C_INK, 18);
    b.text(L"Что делает", ui(15, W_SEMI), C_INK, 4);
    b.text(L"Разбирает заголовки PE, строки и машинный код x86 и x64, восстанавливает аргументы вызовов WinAPI и по ним находит "
           L"цепочки поведения: уничтожение файлов, закрепление в автозапуске, самокопирование. Исследуемый файл никогда не запускается.",
           ui(14), C_MUTED, 18);
    b.text(L"Чего не умеет", ui(15, W_SEMI), C_INK, 4);
    b.text(L"Упакованные файлы анализируются только по заголовкам и импорту. Логика .NET на IL не разбирается. Код читается линейно, "
           L"поэтому запутанный код может нарушить разбор. Точность на большой размеченной выборке не измерялась, поэтому результат "
           L"служит основанием для дальнейшей проверки, а не окончательным приговором.", ui(14), C_MUTED, 18);
    b.text(L"Клавиши", ui(15, W_SEMI), C_INK, 4);
    b.text(L"1–6 переключают разделы итога, Ctrl+O выбирает файл, Tab и Enter работают с кнопками, колесо и PgUp, PgDn прокручивают.", ui(14), C_MUTED);
    b.width = keep;
}

void rebuildItems()
{
    app.items.clear();
    app.itemsValid = true;
    Builder b;
    b.width = bodyW();
    if (app.page == P_REPORTS)
        buildReportsPage(b);
    else if (app.page == P_MODEL)
        buildModelPage(b);
    else if (app.page == P_ABOUT)
        buildAboutPage(b);
    else if (app.screen == S_PICK)
        buildPick(b);
    else if (app.screen == S_RESULT && app.a)
    {
        const Analysis& a = *app.a;
        switch (app.tab)
        {
        case T_BEHAVIOR: buildBehavior(b, a); break;
        case T_CALLS:    buildCalls(b, a); break;
        case T_VULN:     buildVuln(b, a); break;
        case T_IOC:      buildIoc(b, a); break;
        case T_DAMAGE:   buildDamage(b, a); break;
        default:         buildTodo(b, a); break;
        }
    }
    app.itemsHeight = b.y;
}

void drawItems(float baseX, float baseY, float clipTop, float clipBottom)
{
    for (const Item& it : app.items)
    {
        float y = baseY + it.y;
        if (y > clipBottom || y + max(it.h, 1.0f) < clipTop)
            continue;
        if (it.action >= 0)
            addHit(baseX + it.x, y, it.w, it.h, it.action, clipTop, clipBottom);
        if (it.hoverOnly)
        {
            if (app.hot == it.action)
                fillRound(baseX + it.x, y, it.w, it.h, 4, it.color);
        }
        else if (it.layout)
        {
            D2D1_COLOR_F c = it.color;
            if (it.action >= 0 && app.hot == it.action)
                c = rgb(C_ACCENT_HOT);
            drawLayout(it.layout.Get(), baseX + it.x, y, c);
        }
        else if (it.radius > 0)
        {
            D2D1_COLOR_F c = it.color;
            if (it.action >= 0 && app.hot == it.action)
                c = rgb(C_ACCENT_HOT);
            fillRound(baseX + it.x, y, it.w, it.h, it.radius, c);
        }
        else
            fillRect(baseX + it.x, y, it.w, it.h, it.color);
    }
}

// ---------------------------------------------------------------- рамка окна

void drawHeader(bool dark)
{
    fillRect(0, 0, app.W, HEADER_H, rgb(dark ? C_INK : C_WHITE));
    fillRect(0, HEADER_H - 1, app.W, 1, rgb(dark ? C_DARK_HOVER : C_RULE));

    fillRound(PAD_X, 17, 22, 22, 5, rgb(C_ACCENT));
    drawCentered(L"E", mono(12, W_BOLD), PAD_X, 17, 22, 22, rgb(C_WHITE));
    drawText(L"ExeIAS", ui(17, W_BOLD), PAD_X + 32, 16, 120, rgb(dark ? C_WHITE : C_INK), -0.17f);
    addHit(PAD_X, 10, 110, 36, H_LOGO);

    const wchar_t* names[P_COUNT] = { L"Проверка", L"Отчёты", L"Модель ущерба", L"О программе" };
    float widths[P_COUNT], total = 0;
    for (int i = 0; i < P_COUNT; i++)
    {
        widths[i] = textWidth(names[i], ui(14, app.page == i ? W_MEDIUM : W_NORMAL)) + 28;
        total += widths[i] + (i ? 4 : 0);
    }
    float x = app.W - PAD_X - total;
    for (int i = 0; i < P_COUNT; i++)
    {
        bool active = app.page == i;
        int id = H_NAV0 + i;
        if (active)
            fillRound(x, 10, widths[i], 36, 6, rgb(dark ? C_WHITE : C_INK));
        else if (app.hot == id)
            fillRound(x, 10, widths[i], 36, 6, rgb(dark ? C_DARK_HOVER : C_SOFT));
        uint32_t color = active ? (dark ? C_INK : C_WHITE) : (dark ? C_ON_DARK : C_MUTED);
        drawCentered(names[i], ui(14, active ? W_MEDIUM : W_NORMAL), x, 10, widths[i], 36, rgb(color));
        if (app.focus == id)
            strokeRound(x - 2, 8, widths[i] + 4, 40, 8, rgb(dark ? C_WHITE : C_ACCENT), 2);
        addHit(x, 10, widths[i], 36, id);
        x += widths[i] + 4;
    }
}

void drawFooter()
{
    float y = app.H - FOOTER_H;
    fillRect(0, y, app.W, FOOTER_H, rgb(C_WHITE));
    fillRect(0, y, app.W, 1, rgb(C_RULE));
    drawText(L"Разработка РТУ МИРЭА · кафедра КБ-2", ui(12), PAD_X, y + 8, 500, rgb(C_DIM));
    auto l = makeLayout(L"2026", mono(12), 100);
    l->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_TRAILING);
    drawLayout(l.Get(), app.W - PAD_X - 100, y + 9, rgb(C_DIM));
}

void clampScroll()
{
    app.scroll = max(0.0f, min(app.scroll, max(0.0f, app.pageH - viewH())));
}

void drawScrollbar()
{
    float view = viewH();
    if (app.pageH <= view + 0.5f)
        return;
    float thumbH = max(view * view / app.pageH, 40.0f);
    float thumbY = app.regionTop + (view - thumbH) * app.scroll / (app.pageH - view);
    fillRound(app.W - 9, thumbY, 5, thumbH, 2.5f, rgb(C_DIM, app.hot == H_THUMB || app.draggingThumb ? 0.8f : 0.4f));
    addHit(app.W - 14, thumbY, 14, thumbH, H_THUMB);
}

// ---------------------------------------------------------------- стартовый экран

void drawUploadIcon(float x, float y)
{
    // значок из макета, поле 24×24, масштаб до 36
    const float k = 1.5f, width = 2.4f;
    app.brush->SetColor(rgb(C_WHITE));
    auto seg = [&](float x1, float y1, float x2, float y2)
    {
        app.rt->DrawLine(D2D1::Point2F(x + x1 * k, y + y1 * k), D2D1::Point2F(x + x2 * k, y + y2 * k), app.brush.Get(), width, app.rounded.Get());
    };
    seg(12, 15, 12, 3);
    seg(7, 8, 12, 3);
    seg(17, 8, 12, 3);
    seg(4, 15, 4, 19);
    seg(4, 19, 6, 21);
    seg(6, 21, 18, 21);
    seg(18, 21, 20, 19);
    seg(20, 19, 20, 15);
}

void drawUploadCard(float x, float y, float w, float h, float clipTop, float clipBottom)
{
    fillRound(x, y, w, h, 12, rgb(C_INK));
    const float pad = 28, footH = 32;
    float ix = x + pad, iy = y + pad, iw = w - pad * 2, ih = h - pad * 2 - footH;
    strokeRound(ix, iy, iw, ih, 8, rgb(C_DASH), 1.5f, app.dashed.Get());

    if (app.screen == S_BUSY)
    {
        float cy = iy + ih / 2 - 44;
        cy += drawText(L"Идёт разбор файла", ui(20, W_SEMI), ix + 28, cy, iw - 56, rgb(C_WHITE)) + 6;
        cy += drawText(app.busyName, mono(13), ix + 28, cy, iw - 56, rgb(C_ON_DARK_DIM)) + 16;
        float barW = iw - 56;
        fillRect(ix + 28, cy, barW, 4, rgb(C_DARK_RULE));
        float segment = barW * 0.22f, pos = (barW + segment) * app.animPhase - segment;
        float left = max(pos, 0.0f), right = min(pos + segment, barW);
        if (right > left)
            fillRect(ix + 28 + left, cy, right - left, 4, rgb(C_ACCENT));
        drawText(L"Файл только читается и не запускается.", ui(13), ix + 28, cy + 14, barW, rgb(C_ON_DARK_DIM));
    }
    else
    {
        const float stack = 36 + 18 + 28 + 18 + 44;
        float cy = iy + (ih - stack) / 2;
        drawUploadIcon(ix + iw / 2 - 18, cy);
        cy += 36 + 18;
        drawCentered(L"Перетащите файл сюда", ui(20, W_SEMI), ix, cy, iw, 28, rgb(C_WHITE));
        cy += 28 + 18;
        auto f = ui(15, W_SEMI);
        float bw = textWidth(L"Выбрать файл", f) + 44;
        button(L"Выбрать файл", ix + (iw - bw) / 2, cy, bw, 44, H_CHOOSE, B_ACCENT, f, clipTop, clipBottom);
    }
    float fy = y + h - pad - 16;
    drawText(L".exe .dll .bin .zip .rar .7z", mono(12), ix, fy, iw / 2, rgb(C_ON_DARK_DIM));
    auto l = makeLayout(L"архив распаковывается в память", mono(12), iw);
    l->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_TRAILING);
    drawLayout(l.Get(), ix, fy, rgb(C_ON_DARK_DIM));
}

void drawStart()
{
    app.regionTop = HEADER_H;
    float clipTop = app.regionTop, clipBottom = regionBottom();
    app.rt->PushAxisAlignedClip(D2D1::RectF(0, clipTop, app.W, clipBottom), D2D1_ANTIALIAS_MODE_ALIASED);

    float x = PAD_X, w = bodyW(), top = clipTop + 48 - app.scroll;
    const float cardW = min(560.0f, w * 0.5f), gap = 48;
    float leftW = w - cardW - gap;

    auto eyebrow = makeLayout(L"статический анализ · x86 / x64", mono(12, W_MEDIUM), leftW);
    auto title = makeLayout(L"Узнайте, что файл сделает с данными, не запуская его", ui(46, W_BOLD), leftW, -1.38f);
    auto lead = makeLayout(L"ExeIAS разбирает заголовки, строки и машинный код и считает балл риска, вероятный ущерб в рублях и что делать дальше.",
                           ui(16), min(leftW, 520.0f));
    float textH = heightOf(eyebrow.Get()) + 16 + heightOf(title.Get()) + 16 + heightOf(lead.Get());
    ComPtr<IDWriteTextLayout> error;
    if (!app.errorText.empty())
    {
        error = makeLayout(app.errorText, ui(14, W_MEDIUM), leftW - 14);
        textH += 14 + max(heightOf(error.Get()), 22.0f);
    }
    const float statsH = 62;
    float rowH = max(380.0f, textH + 24 + statsH);

    float y = top;
    drawLayout(eyebrow.Get(), x, y, rgb(C_ACCENT));
    y += heightOf(eyebrow.Get()) + 16;
    drawLayout(title.Get(), x, y, rgb(C_INK));
    y += heightOf(title.Get()) + 16;
    drawLayout(lead.Get(), x, y, rgb(C_MUTED));
    y += heightOf(lead.Get());
    if (error)
    {
        y += 14;
        fillRect(x, y, 3, max(heightOf(error.Get()), 22.0f), rgb(C_DANGER));
        drawLayout(error.Get(), x + 14, y, rgb(0x9B1C1C));
    }

    struct Stat { const wchar_t* value; const wchar_t* label; };
    const Stat stats[] = { { L"55", L"правил CWE, CVE, ATT&CK" }, { L"0", L"запусков образца" }, { L"6", L"форматов на входе" } };
    float sx = x, sy = top + rowH - statsH;
    for (const Stat& s : stats)
    {
        auto value = makeLayout(s.value, ui(26, W_BOLD), 200);
        auto label = makeLayout(s.label, ui(13), 400);
        drawLayout(value.Get(), sx, sy, rgb(C_INK));
        drawLayout(label.Get(), sx, sy + heightOf(value.Get()) + 2, rgb(C_MUTED));
        sx += widthOf(label.Get()) + 32;
    }

    drawUploadCard(x + leftW + gap, top, cardW, rowH, clipTop, clipBottom);

    y = top + rowH + 36;
    y += drawText(L"Как идёт проверка", ui(15, W_SEMI), x, y, w, rgb(C_INK)) + 16;
    fillRect(x, y, w, 2, rgb(C_INK));
    y += 2;
    struct Step { const wchar_t* title; const wchar_t* text; };
    const Step steps[] = {
        { L"Заголовки файла", L"Формат, секции, энтропия, таблица импорта" },
        { L"Строки и сигнатуры", L"55 правил с привязкой к CWE, CVE и MITRE ATT&CK" },
        { L"Машинный код", L"Декодер x86 и x64 восстанавливает аргументы вызовов" },
        { L"Цепочки поведения", L"Какие операции с файлами и реестром связаны в коде" },
        { L"Итог", L"Балл риска, ошибки в коде, ущерб в рублях, рекомендации" },
    };
    float colW = w / 5, maxH = 0;
    for (int i = 0; i < 5; i++)
    {
        float cx = x + colW * i, cy = y + 14, tw = colW - (i < 4 ? 20 : 0);
        cy += drawText(to_wstring(i + 1), mono(12, W_MEDIUM), cx, cy, tw, rgb(C_ACCENT)) + 6;
        cy += drawText(steps[i].title, ui(15, W_SEMI), cx, cy, tw, rgb(C_INK)) + 6;
        cy += drawText(steps[i].text, ui(13), cx, cy, tw, rgb(C_MUTED));
        maxH = max(maxH, cy - y);
    }
    app.pageH = (y + maxH + 32) - (clipTop - app.scroll);
    app.rt->PopAxisAlignedClip();
}

// ---------------------------------------------------------------- экран результата

float drawSummary(const Analysis& a)
{
    float x = PAD_X, w = app.W - PAD_X * 2, top = HEADER_H + 28;
    const float scoreW = 300, actionsW = 220, gap = 40;
    float leftW = w - scoreW - actionsW - gap * 2;

    wstring meta = safeText(a.name, 60);
    if (a.pe.valid)
    {
        meta += a.pe.is64 ? L" · PE32+" : L" · PE32";
        meta += L" · " + safeText(a.lang.language);
        if (!a.lang.toolchain.empty())
            meta += L", " + trimToolchain(a.lang.toolchain);
        meta += L" · секций: " + to_wstring(a.pe.sections.size());
    }
    else
        meta += L" · не PE-файл";

    auto metaL = makeLayout(meta, mono(13), leftW);
    auto titleL = makeLayout(headline(a), ui(40, W_BOLD), leftW, -1.2f);
    auto verdictL = makeLayout(capFirst(safeText(a.verdict)), ui(15), leftW);
    float leftH = heightOf(metaL.Get()) + 10 + heightOf(titleL.Get()) + 10 + heightOf(verdictL.Get());
    const float scoreH = 136;
    float blockH = max(max(leftH, scoreH), 92.0f);
    const float statsH = 78;
    float bottom = top + blockH + 28 + statsH;

    fillRect(0, HEADER_H, app.W, bottom - HEADER_H, rgb(C_INK));

    float y = top;
    drawLayout(metaL.Get(), x, y, rgb(C_ON_DARK_DIM));
    y += heightOf(metaL.Get()) + 10;
    drawLayout(titleL.Get(), x, y, rgb(C_WHITE));
    y += heightOf(titleL.Get()) + 10;
    drawLayout(verdictL.Get(), x, y, rgb(C_ON_DARK));

    // балл риска и шкала вероятности
    float sx = x + leftW + gap;
    y = top;
    y += drawText(L"Балл риска", ui(13), sx, y, scoreW, rgb(C_ON_DARK_DIM)) + 6;
    int zone = scoreZone(a.score);
    auto scoreL = makeLayout(to_wstring(a.score), ui(64, W_BOLD), scoreW, -2.5f);
    drawLayout(scoreL.Get(), sx, y - 10, rgb(zoneColor(zone)));
    drawText(L"/ 100", ui(18), sx + widthOf(scoreL.Get()) + 6, y + 36, 80, rgb(C_ON_DARK_DIM));
    y += 76;
    float segW = (scoreW - 9) / 4;
    const wchar_t* zones[] = { L"низкая", L"средняя", L"высокая", L"очень выс." };
    for (int i = 0; i < 4; i++)
    {
        float cx = sx + (segW + 3) * i;
        fillRound(cx, y, segW, 6, 1, rgb(i <= zone ? zoneColor(zone) : C_DARK_RULE));
        drawText(zones[i], ui(11, i == zone ? W_MEDIUM : W_NORMAL), cx, y + 10, segW + 3, rgb(i == zone ? C_WHITE : C_ON_DARK_FAINT));
    }

    // кнопки
    float ax = x + w - actionsW;
    button(L"Проверить другой файл", ax, top, actionsW, 42, H_CHOOSE, B_ACCENT, ui(14, W_SEMI));
    float half = (actionsW - 8) / 2;
    button(L"Отчёт", ax, top + 50, half, 38, H_REPORT, B_OUTLINE_DARK, ui(13, W_MEDIUM));
    button(L"Папка", ax + half + 8, top + 50, half, 38, H_FOLDER, B_OUTLINE_DARK, ui(13, W_MEDIUM));

    // показатели
    float sy = top + blockH + 28;
    fillRect(x, sy, w, 1, rgb(C_DARK_RULE));
    struct Stat { wstring value; const wchar_t* label; };
    const Stat stats[] = {
        { to_wstring(a.behaviors.size()), L"цепочек поведения" },
        { to_wstring(countVuln(a)), L"уязвимости" },
        { a.economy.lossExpected > 0 ? rub(a.economy.lossExpected) : L"0 ₽", L"ожидаемый ущерб" },
    };
    float cx = x;
    for (int i = 0; i < 3; i++)
    {
        float colW = i == 2 ? 200.0f : 180.0f, pad = i ? 20.0f : 0.0f;
        if (i)
            fillRect(cx, sy, 1, statsH, rgb(C_DARK_RULE));
        float vy = sy + 14;
        vy += drawText(stats[i].value, ui(24, W_BOLD), cx + pad, vy - 3, colW - pad, rgb(C_WHITE)) - 3;
        drawText(stats[i].label, ui(12), cx + pad, vy + 2, colW - pad, rgb(C_ON_DARK_DIM));
        cx += colW;
    }
    fillRect(cx, sy, 1, statsH, rgb(C_DARK_RULE));
    const wstring copyText = app.copied ? L"Скопировано" : L"Копировать";
    float copyW = textWidth(copyText, ui(12, W_MEDIUM)) + 20;
    float copyX = x + w - copyW;
    button(copyText, copyX, sy + (statsH - 28) / 2, copyW, 28, H_COPY, B_OUTLINE_DARK, ui(12, W_MEDIUM));
    wstring sha = fromUtf8(a.sha256);
    if (sha.length() > 40)
        sha = sha.substr(0, 26) + L"…" + sha.substr(sha.length() - 10);
    auto shaL = makeLayout(L"sha256 " + sha, mono(12), max(copyX - cx - 30, 1.0f));
    shaL->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_TRAILING);
    drawLayout(shaL.Get(), cx + 20, sy + (statsH - heightOf(shaL.Get())) / 2, rgb(C_ON_DARK_DIM));

    return bottom;
}

uint32_t entropyColor(double e)
{
    return e < 2 ? 0xDCE3F3 : e < 4 ? 0xBCCAE8 : e < 5.5 ? 0x9DB0DB : e < 6.5 ? 0x5A78BF : e < 7.2 ? 0x34509A : 0x1E3470;
}

const float MAP_H = 100;

void drawFileMap(const Analysis& a, float x, float y, float w, float clipTop, float clipBottom)
{
    drawText(L"Карта файла", ui(15, W_SEMI), x, y, 200, rgb(C_INK));
    const uint32_t legend[] = { 0xDCE3F3, 0x9DB0DB, 0x5A78BF, 0x1E3470 };
    float lx = x + w - 62;
    drawText(L"высокая", ui(12), lx + 8, y + 2, 60, rgb(C_DIM));
    for (int i = 3; i >= 0; i--)
    {
        lx -= 16;
        fillRound(lx, y + 6, 14, 10, 2, rgb(legend[i]));
    }
    auto entropyWord = makeLayout(L"энтропия", ui(12), 80);
    drawLayout(entropyWord.Get(), lx - widthOf(entropyWord.Get()) - 8, y + 2, rgb(C_DIM));

    float stripY = y + 30;
    if (!a.pe.valid)
    {
        drawText(L"Карта недоступна: " + safeText(a.pe.error), ui(13), x, stripY, w, rgb(C_MUTED));
        return;
    }
    size_t total = a.pe.sections.size(), shown = total > 16 ? 15 : total;
    size_t cells = shown + (total > 16 ? 1 : 0);
    if (cells == 0)
    {
        drawText(L"В файле нет секций.", ui(13), x, stripY, w, rgb(C_MUTED));
        return;
    }
    float cw = (w - 3 * (float)(cells - 1)) / (float)cells;
    auto cellFont = mono(11, W_MEDIUM);
    for (size_t i = 0; i < cells; i++)
    {
        float cx = x + (cw + 3) * i;
        if (i >= shown)
        {
            strokeRound(cx + 0.5f, stripY + 0.5f, cw - 1, 39, 4, rgb(0x9DB0DB), 1, app.dashed.Get());
            drawCentered(L"+" + to_wstring(total - shown), cellFont, cx, stripY, cw, 40, rgb(0x34509A));
            continue;
        }
        const Section& s = a.pe.sections[i];
        uint32_t back = entropyColor(s.entropy);
        fillRound(cx, stripY, cw, 40, 4, rgb(back));
        bool lightText = back == 0x5A78BF || back == 0x34509A || back == 0x1E3470;
        drawCentered(safeText(s.name, 8), cellFont, cx, stripY, cw, 40, rgb(lightText ? C_WHITE : C_INK));
    }

    // Опасные функции: красные отметки в секциях, где они лежат
    set<uint64_t> danger;
    for (const Behavior& b : a.behaviors)
        if (b.severity >= MEDIUM)
            danger.insert(b.func);
    wstring names;
    for (uint64_t va : danger)
    {
        uint64_t rva = va >= a.pe.imageBase ? va - a.pe.imageBase : 0;
        for (size_t i = 0; i < shown; i++)
        {
            const Section& s = a.pe.sections[i];
            uint32_t size = max(max(s.vsize, s.rawSize), 1u);
            if (rva >= s.va && rva < (uint64_t)s.va + size)
                fillRect(x + (cw + 3) * i + cw * (float)(rva - s.va) / size, stripY - 4, 2.5f, 48, rgb(C_DANGER));
        }
        if (names.length() < 90)
            names += (names.empty() ? L"" : L", ") + fromUtf8("sub_" + hexPlain(va));
    }
    drawText(danger.empty() ? L"Опасных функций не найдено." : L"Красные отметки показывают опасные функции: " + names + L".",
             ui(12.5f), x, stripY + 48, w, rgb(C_DIM));
}

const float TABS_H = 40;

void drawTabs(const Analysis& a, float x, float y)
{
    const wstring names[T_COUNT] = { L"Поведение", L"Вызовы в коде", L"Уязвимости", L"Индикаторы", L"Ущерб", L"Что делать" };
    const wstring counts[T_COUNT] = { to_wstring(a.behaviors.size()), L"", to_wstring(countVuln(a)), to_wstring(countIoc(a)), L"", L"" };
    float total = 6;
    float widths[T_COUNT], nameW[T_COUNT];
    for (int i = 0; i < T_COUNT; i++)
    {
        nameW[i] = textWidth(names[i], ui(13.5f, app.tab == i ? W_SEMI : W_MEDIUM));
        float cw = counts[i].empty() ? 0 : textWidth(counts[i], mono(13.5f)) + 5;
        widths[i] = nameW[i] + cw + 24;
        total += widths[i] + (i ? 2 : 0);
    }
    fillRound(x, y, total, TABS_H, 8, rgb(C_SOFT));
    float cx = x + 3;
    for (int i = 0; i < T_COUNT; i++)
    {
        bool active = app.tab == i;
        if (active)
        {
            fillRound(cx, y + 3, widths[i], 34, 6, rgb(C_WHITE));
            strokeRound(cx, y + 3, widths[i], 34, 6, rgb(C_INK, 0.10f));
        }
        else if (app.hot == H_TAB0 + i)
            fillRound(cx, y + 3, widths[i], 34, 6, rgb(C_RULE));
        auto l = makeLayout(names[i], ui(13.5f, active ? W_SEMI : W_MEDIUM), 300);
        float ty = y + 3 + (34 - heightOf(l.Get())) / 2;
        drawLayout(l.Get(), cx + 12, ty, rgb(active ? C_INK : C_MUTED));
        if (!counts[i].empty())
        {
            auto c = makeLayout(counts[i], mono(13.5f), 80);
            drawLayout(c.Get(), cx + 12 + nameW[i] + 5, y + 3 + (34 - heightOf(c.Get())) / 2, rgb(active ? C_ACCENT : C_DIM));
        }
        addHit(cx, y + 3, widths[i], 34, H_TAB0 + i);
        cx += widths[i] + 2;
    }
}

void drawResult()
{
    const Analysis& a = *app.a;
    if (!app.itemsValid)
        rebuildItems();
    float bottom = drawSummary(a);
    app.regionTop = bottom;
    float clipTop = bottom, clipBottom = regionBottom();
    float x = PAD_X, w = bodyW();
    app.pageH = 26 + MAP_H + 26 + TABS_H + 14 + app.itemsHeight + 26;
    clampScroll();

    float mapY = clipTop + 26 - app.scroll;
    float tabsNatural = mapY + MAP_H + 26;
    float tabsY = max(tabsNatural, clipTop + 8);

    if (clipBottom <= clipTop)
        return;
    app.rt->PushAxisAlignedClip(D2D1::RectF(0, clipTop, app.W, clipBottom), D2D1_ANTIALIAS_MODE_ALIASED);
    drawFileMap(a, x, mapY, w, clipTop, clipBottom);
    float contentClip = tabsY + TABS_H + 6;
    app.rt->PushAxisAlignedClip(D2D1::RectF(0, contentClip, app.W, clipBottom), D2D1_ANTIALIAS_MODE_ALIASED);
    drawItems(x, tabsNatural + TABS_H + 14, contentClip, clipBottom);
    app.rt->PopAxisAlignedClip();
    drawTabs(a, x, tabsY);
    app.rt->PopAxisAlignedClip();
}

void drawItemsPage()
{
    app.regionTop = HEADER_H;
    if (!app.itemsValid)
        rebuildItems();
    float clipTop = app.regionTop, clipBottom = regionBottom();
    app.pageH = 40 + app.itemsHeight + 32;
    clampScroll();
    app.rt->PushAxisAlignedClip(D2D1::RectF(0, clipTop, app.W, clipBottom), D2D1_ANTIALIAS_MODE_ALIASED);
    drawItems(PAD_X, clipTop + 40 - app.scroll, clipTop, clipBottom);
    app.rt->PopAxisAlignedClip();
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
    if (!app.dashed)
    {
        float dashes[] = { 4, 3 };
        app.d2d->CreateStrokeStyle(D2D1::StrokeStyleProperties(D2D1_CAP_STYLE_FLAT, D2D1_CAP_STYLE_FLAT, D2D1_CAP_STYLE_FLAT,
                                   D2D1_LINE_JOIN_ROUND, 10.0f, D2D1_DASH_STYLE_CUSTOM), dashes, 2, &app.dashed);
        app.d2d->CreateStrokeStyle(D2D1::StrokeStyleProperties(D2D1_CAP_STYLE_ROUND, D2D1_CAP_STYLE_ROUND, D2D1_CAP_STYLE_ROUND,
                                   D2D1_LINE_JOIN_ROUND), nullptr, 0, &app.rounded);
    }
    app.hits.clear();
    app.rt->BeginDraw();
    app.rt->Clear(rgb(C_WHITE));

    bool result = app.page == P_CHECK && app.screen == S_RESULT && app.a;
    if (result)
        drawResult();
    else if (app.page == P_CHECK && app.screen != S_PICK)
    {
        drawStart();
        clampScroll();
    }
    else
        drawItemsPage();

    drawHeader(result);
    drawFooter();
    drawScrollbar();

    if (app.rt->EndDraw() == D2DERR_RECREATE_TARGET)
    {
        app.rt.Reset();
        app.brush.Reset();
        InvalidateRect(app.hwnd, nullptr, FALSE);
    }
}

// ---------------------------------------------------------------- действия

void redraw() { InvalidateRect(app.hwnd, nullptr, FALSE); }

void shellOpen(const wchar_t* file, const wstring& args)
{
#ifdef EXEIAS_SELFTEST
    app.lastShell = wstring(file) + L" " + args;
#else
    ShellExecuteW(app.hwnd, L"open", file, args.empty() ? nullptr : args.c_str(), nullptr, SW_SHOWNORMAL);
#endif
}

void setPage(Page p)
{
    app.page = p;
    app.scroll = 0;
    app.itemsValid = false;
    if (p == P_REPORTS)
        loadReports();
    redraw();
}

void setTab(int t)
{
    if (app.page != P_CHECK || app.screen != S_RESULT || t < 0 || t >= T_COUNT)
        return;
    // при смене раздела таблица начинается сразу под закреплёнными разделами
    float keep = min(app.scroll, 26 + MAP_H + 26 - 8);
    app.tab = t;
    app.scroll = keep;
    app.itemsValid = false;
    redraw();
}

void scrollBy(float dy)
{
    app.scroll = max(0.0f, min(app.scroll + dy, max(0.0f, app.pageH - viewH())));
    redraw();
}

void startJob(const fs::path& path, const string& member)
{
    int generation = ++app.generation;
    app.page = P_CHECK;
    app.screen = S_BUSY;
    app.errorText.clear();
    app.busyName = safeText(member.empty() ? pathToUtf8(path.filename()) : member, 100);
    app.a.reset();
    app.itemsValid = false;
    app.scroll = 0;
    app.animPhase = 0;
    app.hot = H_NONE;
    if (app.animate)
        SetTimer(app.hwnd, TIMER_ANIM, 33, nullptr);
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

void showAnalysis(unique_ptr<Analysis> analysis, const RunFiles& files)
{
    app.a = move(analysis);
    app.files = files;
    app.page = P_CHECK;
    app.screen = S_RESULT;
    app.tab = T_BEHAVIOR;
    app.scroll = 0;
    app.copied = false;
    app.expanded.clear();
    app.showAll.clear();
    // первой раскрывается самая опасная цепочка
    int top = -1;
    for (int i = 0; i < (int)app.a->behaviors.size(); i++)
        if (top < 0 || app.a->behaviors[i].severity > app.a->behaviors[top].severity)
            top = i;
    if (top >= 0)
        app.expanded.insert(top);
    app.itemsValid = false;
}

void finishJob(unique_ptr<Job> job)
{
    if (job->generation != app.generation)
        return;
    KillTimer(app.hwnd, TIMER_ANIM);
    if (job->analysis)
        showAnalysis(move(job->analysis), job->files);
    else if (!job->members.empty())
    {
        app.members = job->members;
        app.pickArchive = job->archive;
        app.screen = S_PICK;
        app.itemsValid = false;
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
#ifdef EXEIAS_SELFTEST
    app.lastShell = L"choose";
    return;
#endif
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

bool copyToClipboard(const wstring& text)
{
    for (int attempt = 0; attempt < 5; attempt++)
    {
        if (OpenClipboard(app.hwnd))
        {
            bool ok = false;
            EmptyClipboard();
            HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, (text.length() + 1) * sizeof(wchar_t));
            if (mem)
            {
                wchar_t* dst = (wchar_t*)GlobalLock(mem);
                memcpy(dst, text.c_str(), (text.length() + 1) * sizeof(wchar_t));
                GlobalUnlock(mem);
                ok = SetClipboardData(CF_UNICODETEXT, mem) != nullptr;
                if (!ok)
                    GlobalFree(mem);
            }
            CloseClipboard();
            return ok;
        }
        Sleep(30);
    }
    return false;
}

void activate(int id)
{
    if (id == H_CHOOSE)
        chooseFile();
    else if (id == H_LOGO)
    {
        app.generation++;
        KillTimer(app.hwnd, TIMER_ANIM);
        app.screen = S_IDLE;
        app.errorText.clear();
        setPage(P_CHECK);
    }
    else if (id == H_CANCEL)
    {
        app.screen = S_IDLE;
        setPage(P_CHECK);
    }
    else if (id == H_REPORT)
        shellOpen(L"notepad.exe", L"\"" + app.files.report.wstring() + L"\"");
    else if (id == H_FOLDER)
        shellOpen(L"explorer.exe", L"/select,\"" + app.files.report.wstring() + L"\"");
    else if (id == H_OPEN_REPORTS)
    {
        error_code ec;
        fs::path dir = app.self.parent_path() / L"reports";
        fs::create_directories(dir, ec);
        shellOpen(L"explorer.exe", L"\"" + dir.wstring() + L"\"");
    }
    else if (id == H_COPY && app.a)
    {
        if (copyToClipboard(fromUtf8(app.a->sha256)))
        {
            app.copied = true;
            SetTimer(app.hwnd, TIMER_COPIED, 2000, nullptr);
            redraw();
        }
    }
    else if (id >= H_CWE0)
        shellOpen((L"https://cwe.mitre.org/data/definitions/" + to_wstring(id - H_CWE0) + L".html").c_str(), L"");
    else if (id >= H_SHOWALL0)
    {
        int i = id - H_SHOWALL0;
        if (!app.showAll.erase(i))
            app.showAll.insert(i);
        app.itemsValid = false;
        redraw();
    }
    else if (id >= H_TOGGLE0)
    {
        int i = id - H_TOGGLE0;
        if (!app.expanded.erase(i))
            app.expanded.insert(i);
        app.itemsValid = false;
        redraw();
    }
    else if (id >= H_REPORTFILE0)
    {
        size_t i = id - H_REPORTFILE0;
        if (i < app.reports.size())
            shellOpen(L"notepad.exe", L"\"" + app.reports[i].path.wstring() + L"\"");
    }
    else if (id >= H_MEMBER0)
    {
        size_t i = id - H_MEMBER0;
        if (i < app.members.size())
            startJob(app.pickArchive, app.members[i]);
    }
    else if (id >= H_TAB0)
        setTab(id - H_TAB0);
    else if (id >= H_NAV0)
        setPage((Page)(id - H_NAV0));
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
        m->ptMinTrackSize.y = (LONG)(640 * app.dpi / 96);
        return 0;
    }
    case WM_MOUSEMOVE:
    {
        float x = toDip((short)LOWORD(lp)), y = toDip((short)HIWORD(lp));
        if (app.draggingThumb)
        {
            float view = viewH(), thumbH = max(view * view / max(app.pageH, 1.0f), 40.0f);
            float travel = max(view - thumbH, 1.0f);
            app.scroll = app.dragStartScroll + (y - app.dragStartY) * (app.pageH - view) / travel;
            clampScroll();
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
        else if (wp == VK_HOME) scrollBy(-app.pageH);
        else if (wp == VK_END) scrollBy(app.pageH);
        else if (wp == VK_TAB)
        {
            vector<int> order;
            if (app.page == P_CHECK && (app.screen == S_IDLE || app.screen == S_RESULT))
                order.push_back(H_CHOOSE);
            if (app.page == P_CHECK && app.screen == S_RESULT)
            {
                order.push_back(H_REPORT);
                order.push_back(H_FOLDER);
                order.push_back(H_COPY);
            }
            for (int i = 0; i < P_COUNT; i++)
                order.push_back(H_NAV0 + i);
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
        if (wp == TIMER_COPIED)
        {
            KillTimer(hwnd, TIMER_COPIED);
            app.copied = false;
        }
        else
        {
            app.animPhase += 0.015f;
            if (app.animPhase > 1)
                app.animPhase = 0;
        }
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

#ifdef EXEIAS_SELFTEST
#include "gui_selftest.inl"
#endif

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
    RECT want = { 0, 0, MulDiv(1280, dpi, 96), MulDiv(900, dpi, 96) };
    AdjustWindowRectExForDpi(&want, WS_OVERLAPPEDWINDOW, FALSE, WS_EX_ACCEPTFILES, dpi);
    int w = min((int)(want.right - want.left), (int)(work.right - work.left));
    int h = min((int)(want.bottom - want.top), (int)(work.bottom - work.top));
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
#ifdef EXEIAS_SELFTEST
    int failed = runSelfTest(argc, argv);
    if (argv)
        LocalFree(argv);
    DestroyWindow(app.hwnd);
    return failed;
#else
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
#endif
}
