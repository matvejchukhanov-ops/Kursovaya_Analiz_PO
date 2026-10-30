// Модуль анализа взаимодействия с файловой системой (тема курсовой работы):
// поиск вызовов WinAPI и строк в машинном коде, восстановление аргументов вызовов,
// выделение функций и цепочек поведения с привязкой к MITRE ATT&CK
#pragma once

#include "common.h"

// Операции с файловой системой по функциям WinAPI
enum FsOp { FS_ENUM, FS_DRIVES, FS_OPEN, FS_WRITE, FS_COPY, FS_MOVE, FS_DELETE, FS_ATTR, FS_DIRS, FS_SELF, FS_EXEC, FS_OP_COUNT };

extern const string FS_OP_NAMES[FS_OP_COUNT];

struct FsApi
{
    string stem;      // имя без суффикса A/W
    FsOp op;
    bool lowLevel;    // вызывается и самой библиотекой CRT (fopen, fwrite) — сам по себе не показателен
};

extern const vector<FsApi> FS_APIS;

bool apiMatches(const string& name, const string& stem);

// Название операции с ФС для функции API ("" — не файловая); lowLevel — используется и CRT
string fsOpOf(const string& api, bool& lowLevel);

CodeMap analyzeCode(const vector<unsigned char>& bytes, const PeInfo& pe, const vector<FoundString>& strings);

vector<Behavior> detectBehaviors(const CodeMap& code);

// «CopyFileA("c:\wxp", var_444, FALSE)»
string formatCall(const CallSite& call);

// Смысл аргументов: «существующий файл-приёмник перезаписывается» и т.п.
string callNote(const CallSite& call);

bool isRootFilePath(const string& s);
