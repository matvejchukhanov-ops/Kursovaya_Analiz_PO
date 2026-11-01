#include "economics.h"
#include "signatures.h"

#include <cmath>
#include <cstdlib>
#include <fstream>

// ================================================================ параметры организации

EconomicProfile loadProfile(const fs::path& iniPath)
{
    EconomicProfile p;
    ifstream in(iniPath, ios::binary);
    if (!in.is_open())
        return p;

    const map<string, double*> numbers = {
        { "workstations", &p.workstations }, { "hourCost", &p.hourCost }, { "specialistHour", &p.specialistHour },
        { "hostRebuildHours", &p.hostRebuildHours }, { "investigationHours", &p.investigationHours },
        { "dataValue", &p.dataValue }, { "sharedDataValue", &p.sharedDataValue }, { "backupShare", &p.backupShare },
        { "leakFineMin", &p.leakFineMin }, { "leakFineMax", &p.leakFineMax },
    };
    string line;
    while (getline(in, line))
    {
        if (line.rfind("\xEF\xBB\xBF", 0) == 0)
            line.erase(0, 3);
        while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
            line.pop_back();
        size_t eq = line.find('=');
        if (line.empty() || line[0] == '#' || line[0] == ';' || eq == NPOS)
            continue;
        string key = line.substr(0, eq), value = line.substr(eq + 1);
        while (!key.empty() && key.back() == ' ')
            key.pop_back();
        size_t first = value.find_first_not_of(' ');
        value = first == NPOS ? "" : value.substr(first);
        if (key == "name")
        {
            p.name = value;
            continue;
        }
        auto target = numbers.find(key);
        if (target == numbers.end())
            continue;
        // некорректное или отрицательное значение не принимаем, остаётся значение по умолчанию
        char* end = nullptr;
        double number = strtod(value.c_str(), &end);
        if (end != value.c_str() && *end == '\0' && isfinite(number) && number >= 0)
            *target->second = number;
    }
    p.backupShare = min(p.backupShare, 1.0);
    p.leakFineMax = max(p.leakFineMin, p.leakFineMax);
    p.source = pathToUtf8(iniPath.filename());
    return p;
}

// ================================================================ виды ущерба

struct Loss
{
    double lo = 0, hi = 0, expected = 0;
};

enum DamageKind { DMG_DATA, DMG_DOWNTIME, DMG_REBUILD, DMG_LEAK, DMG_INVESTIGATION, DMG_COUNT };

const char* const DAMAGE_NAMES[DMG_COUNT] = {
    "потеря данных", "простой рабочих мест", "восстановление узлов", "утечка данных", "расследование инцидента",
};

Loss lossOf(DamageKind kind, const EconomicProfile& p)
{
    double allData = p.dataValue + p.sharedDataValue;
    double downtimeOne = p.hostRebuildHours * p.hourCost, rebuildOne = p.hostRebuildHours * p.specialistHour;
    switch (kind)
    {
    case DMG_DATA:
        return { p.dataValue * (1 - p.backupShare), allData, allData * (1 - p.backupShare) };
    case DMG_DOWNTIME:
        return { downtimeOne, downtimeOne * p.workstations, (downtimeOne + downtimeOne * p.workstations) / 2 };
    case DMG_REBUILD:
        return { rebuildOne, rebuildOne * p.workstations, (rebuildOne + rebuildOne * p.workstations) / 2 };
    case DMG_LEAK:
        return { p.leakFineMin, p.leakFineMax, (p.leakFineMin + p.leakFineMax) / 2 };
    default:
        return { p.investigationHours * p.specialistHour / 2, p.investigationHours * p.specialistHour * 2,
                 p.investigationHours * p.specialistHour };
    }
}

// Техника ATT&CK -> виды ущерба, к которым она ведёт
struct TechniqueDamage
{
    const char* technique;
    vector<DamageKind> kinds;
};

const vector<TechniqueDamage> TECHNIQUE_DAMAGE = {
    { "T1485", { DMG_DATA, DMG_DOWNTIME } },     // уничтожение данных
    { "T1486", { DMG_DATA, DMG_DOWNTIME } },     // шифрование данных
    { "T1490", { DMG_DATA, DMG_DOWNTIME } },     // удаление резервных копий
    { "T1565", { DMG_DATA } },                   // подмена данных
    { "T1547", { DMG_REBUILD } },                // автозапуск
    { "T1546", { DMG_REBUILD } },
    { "T1036", { DMG_REBUILD } },                // маскировка в системном каталоге
    { "T1055", { DMG_REBUILD } },                // внедрение в процессы
    { "T1112", { DMG_REBUILD } },
    { "T1074", { DMG_LEAK } },                   // сбор данных для вывода
    { "T1071", { DMG_LEAK } },                   // сетевой канал управления
    { "T1095", { DMG_LEAK } },
    { "T1105", { DMG_LEAK } },
};

string levelOf(double expected)
{
    return expected <= 0 ? "нет" : expected < 100000 ? "низкая" : expected < 1000000 ? "средняя"
         : expected < 5000000 ? "высокая" : "критическая";
}

string formatRub(double value)
{
    string digits = to_string((long long)llround(value)), out;
    for (size_t i = 0; i < digits.length(); i++)
    {
        if (i && (digits.length() - i) % 3 == 0)
            out += ' ';
        out += digits[i];
    }
    return out + " руб.";
}

// Признак не подтверждён машинным кодом: ущерб возможен, но не обязателен —
// минимум 0, ожидаемое значение вдвое меньше
Loss adjusted(Loss l, bool confirmed)
{
    if (!confirmed)
    {
        l.lo = 0;
        l.expected /= 2;
    }
    return l;
}

void assessEconomics(Analysis& a)
{
    Loss worst[DMG_COUNT];
    for (Finding& f : a.findings)
    {
        // ошибки языка сами по себе ущерба не наносят, слабые признаки в расчёт не идут
        if (f.block == BLOCK_LANG || f.severity < HIGH)
            continue;
        bool confirmed = f.source == "машинный код";

        vector<DamageKind> kinds = { DMG_INVESTIGATION };
        for (const TechniqueDamage& t : TECHNIQUE_DAMAGE)
            if (f.attack.rfind(t.technique, 0) == 0)
                kinds.insert(kinds.begin(), t.kinds.begin(), t.kinds.end());

        for (DamageKind kind : kinds)
        {
            Loss l = adjusted(lossOf(kind, a.profile), confirmed);
            f.lossMin += l.lo;
            f.lossMax += l.hi;
            f.lossExpected += l.expected;
            f.damage += (f.damage.empty() ? "" : ", ") + string(DAMAGE_NAMES[kind]);
            if (l.expected > worst[kind].expected)
                worst[kind] = l;
        }
        f.econLevel = levelOf(f.lossExpected);
    }

    // Итог: каждый вид ущерба считается один раз, по наихудшей находке
    for (int kind = 0; kind < DMG_COUNT; kind++)
    {
        const Loss& l = worst[kind];
        if (l.expected <= 0)
            continue;
        a.economy.lossMin += l.lo;
        a.economy.lossMax += l.hi;
        a.economy.lossExpected += l.expected;
        a.economy.lines.push_back({ DAMAGE_NAMES[kind], l.lo, l.hi, l.expected });
        a.economy.breakdown.push_back(string(DAMAGE_NAMES[kind]) + ": от " + formatRub(l.lo) + " до " + formatRub(l.hi)
                                      + ", ожидаемо " + formatRub(l.expected));
    }
    a.economy.level = levelOf(a.economy.lossExpected);
}
