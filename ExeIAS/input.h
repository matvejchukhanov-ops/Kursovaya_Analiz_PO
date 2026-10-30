// Модуль приёма и обработки входных данных (ТЗ, раздел 2.1)
#pragma once

#include "common.h"

// Читает файл по пути или стандартный ввод («-»). При ошибке возвращает false и текст в error
bool readInput(const string& path, vector<unsigned char>& bytes, string& error);

string hashOf(const vector<unsigned char>& data, const wchar_t* algorithm);

// ASCII- и UTF-16LE-строки вместе со смещением (аналог strings.exe, ПР №3)
vector<FoundString> extractStrings(const vector<unsigned char>& bytes, size_t minLength);

// Внешняя утилита strings.exe (Sysinternals): путь или "" если не найдена
string findStringsUtility(const string& selfPath);
vector<string> runStringsUtility(const string& utility, const string& target);

// Нормализация: чистка непечатаемых символов, отсев мусора, удаление повторов
vector<string> normalizeStrings(const vector<string>& raw, size_t& meaningful);

bool isPeFile(const vector<unsigned char>& bytes);
