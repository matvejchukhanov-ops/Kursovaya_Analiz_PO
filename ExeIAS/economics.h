// Экономическая опасность: оценка ущерба организации от инцидента по находкам анализа
#pragma once

#include "common.h"

// Параметры организации из economics.ini (ключ=значение); нет файла — значения по умолчанию
EconomicProfile loadProfile(const fs::path& iniPath);

// Заполняет поля ущерба в находках и итог a.economy. Вызывается после оценки риска
void assessEconomics(Analysis& a);

// 1250000 -> «1 250 000 руб.»
string formatRub(double value);
