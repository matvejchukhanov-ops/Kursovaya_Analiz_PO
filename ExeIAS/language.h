// Распознавание языка программирования и компилятора, ошибки, характерные для этого языка
#pragma once

#include "common.h"

// Язык и средства сборки — по заголовкам PE, импорту и строкам
LanguageInfo detectLanguage(const PeInfo& pe, const vector<string>& data);

// Ошибки: найденные в машинном коде (CWE-252, CWE-120, CWE-835, CWE-674),
// типичные для языка (по строкам) и отсутствие защит компилятора
vector<Finding> languageFindings(const LanguageInfo& lang, const PeInfo& pe, const vector<string>& data, const CodeMap& code);
