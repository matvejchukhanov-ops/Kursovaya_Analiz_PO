// Разбор заголовков PE: секции, энтропия, таблица импорта, адресация
#pragma once

#include "common.h"

PeInfo parsePe(const vector<unsigned char>& bytes);

uint16_t rd16(const vector<unsigned char>& b, size_t o);
uint32_t rd32(const vector<unsigned char>& b, size_t o);
uint64_t rd64(const vector<unsigned char>& b, size_t o);

size_t rvaToOffset(const PeInfo& pe, uint64_t rva);
size_t vaToOffset(const PeInfo& pe, uint64_t va);
uint64_t offsetToVa(const PeInfo& pe, size_t off);
bool isExecutable(const Section& s);
const Section* sectionOfVa(const PeInfo& pe, uint64_t va);

string machineName(uint16_t machine);
string subsystemName(uint16_t subsystem);
string formatTime(uint32_t timestamp);
