// Окно проверки: интерактивный режим при запуске без аргументов (из Visual Studio или двойным щелчком)
#pragma once

#include "common.h"

int runInteractive(const fs::path& selfPath);

// Краткий цветной итог анализа в консоли (используется и в режиме командной строки)
void printSummary(const Analysis& a, const fs::path& reportFile);
