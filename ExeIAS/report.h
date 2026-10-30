// Модуль генерации качественного отчёта (ТЗ, раздел 2.3) и оценки риска
#pragma once

#include "common.h"

// Балл риска 0–100, вероятность инцидента ИБ, общий уровень и вывод
void assessRisk(Analysis& a);

void writeReport(const string& path, const Analysis& a);
bool writeCsv(const string& path, const vector<Finding>& findings);
