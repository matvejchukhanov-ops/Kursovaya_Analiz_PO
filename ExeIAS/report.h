// Модуль генерации качественного отчёта (ТЗ, раздел 2.3) и оценки риска
#pragma once

#include "common.h"

// Балл риска 0–100, вероятность инцидента ИБ, общий уровень и вывод
void assessRisk(Analysis& a);

// Индикаторы для блокировки и поиска на других узлах (хэш, файлы, автозапуск, мьютекс)
vector<string> collectIocs(const Analysis& a);

void writeReport(const fs::path& path, const Analysis& a);
bool writeCsv(const fs::path& path, const vector<Finding>& findings);
