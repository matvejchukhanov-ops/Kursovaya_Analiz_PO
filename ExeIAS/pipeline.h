// Конвейер анализа: от байтов файла до отчёта. Общий для командной строки и окна проверки
#pragma once

#include "common.h"

struct RunOptions
{
    string displayPath;     // как показывать объект в отчёте
    string name;            // имя для файлов отчёта
    fs::path sourcePath;    // путь на диске (пустой — данные из архива или стандартного ввода)
    fs::path selfPath;      // путь к ExeIAS.exe — рядом ищется strings.exe
    fs::path outDir;        // куда писать отчёты
    bool internalOnly = false;
};

struct RunFiles
{
    fs::path report, csv, strings;
};

// Все модули по порядку: PE, строки, нормализация, классификация, анализ кода, риск, отчёт
void runAnalysis(const vector<unsigned char>& bytes, const RunOptions& options, Analysis& a, RunFiles& files);
