// Модуль приёма и обработки входных данных (ТЗ, раздел 2.1)
#pragma once

#include "common.h"

// Чтение файла по пути. При ошибке возвращает false и текст в error
bool readFile(const fs::path& path, vector<unsigned char>& bytes, string& error);

// Чтение из стандартного ввода (режим «-»: tar -xOf архив файл | ExeIAS.exe -)
bool readStdin(vector<unsigned char>& bytes, string& error);

// Архив (.rar, .zip, .7z — что умеет системный tar.exe): список файлов и чтение одного файла в память.
// Образец ВПО при этом не записывается на диск
vector<string> listArchive(const fs::path& archive, string& error);
bool readFromArchive(const fs::path& archive, const string& member, vector<unsigned char>& bytes, string& error);
bool isArchive(const fs::path& path);

string hashOf(const vector<unsigned char>& data, const wchar_t* algorithm);

// ASCII- и UTF-16LE-строки вместе со смещением (аналог strings.exe, ПР №3)
vector<FoundString> extractStrings(const vector<unsigned char>& bytes, size_t minLength);

// Внешняя утилита strings.exe (Sysinternals): путь или пустой путь, если не найдена
fs::path findStringsUtility(const fs::path& selfPath);
vector<string> runStringsUtility(const fs::path& utility, const fs::path& target);

// Нормализация: чистка непечатаемых символов, отсев мусора, удаление повторов
vector<string> normalizeStrings(const vector<string>& raw, size_t& meaningful);

bool isPeFile(const vector<unsigned char>& bytes);
