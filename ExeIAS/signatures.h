// Модуль интеллектуальной классификации сигнатур (ТЗ, раздел 2.2):
// расширенная матрица сигнатур, CWE / CVE / MITRE ATT&CK, мета-данные, ошибки, аномалии PE
#pragma once

#include "common.h"

// Блоки отчёта (раздел 2.3)
extern const string BLOCK_VULN;
extern const string BLOCK_IOC;
extern const string BLOCK_FS;
extern const string BLOCK_LANG;

Metadata collectMetadata(const vector<string>& data);
vector<string> collectErrors(const vector<string>& data);

vector<Library> detectLibraries(const vector<string>& data);
vector<Finding> matchCve(const vector<Library>& libs);
vector<Finding> matchRules(const vector<string>& data, const PeInfo& pe, const set<string>& confirmedCves);
vector<Finding> matchNetwork(const vector<string>& data);
vector<Finding> matchPaths(const vector<FoundString>& all);
vector<Finding> checkPeStructure(const PeInfo& pe);

// Находки анализа кода — в блок «Взаимодействие с файловой системой»
vector<Finding> behaviorFindings(const vector<Behavior>& behaviors);
// Если код не разобран (упаковка, .NET), опираемся только на таблицу импорта
vector<Finding> importOnlyFsFindings(const PeInfo& pe, bool codeConfirmed);

// Признаки легитимного загрузчика .NET понижают критичность связанных находок
vector<string> applyContext(const vector<string>& data, vector<Finding>& findings);
