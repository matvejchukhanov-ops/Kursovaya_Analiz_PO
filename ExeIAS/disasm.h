// Декодер инструкций x86 / x64: длина, ModRM/SIB, смещение, непосредственный операнд.
// Мнемоники не нужны — анализатору достаточно знать код операции и операнды,
// чтобы восстановить содержимое стека и регистров перед вызовом функции.
#pragma once

#include "common.h"

// Номера регистров: 0 eax, 1 ecx, 2 edx, 3 ebx, 4 esp, 5 ebp, 6 esi, 7 edi, 8–15 r8–r15
enum Reg { R_AX = 0, R_CX, R_DX, R_BX, R_SP, R_BP, R_SI, R_DI };

struct Insn
{
    uint64_t addr = 0;
    size_t len = 0;
    bool twoByte = false;       // код операции 0F xx
    uint8_t op = 0;             // код операции (для 0F xx — второй байт)
    bool opsize16 = false;      // префикс 66h
    bool rep = false;           // префикс F2h / F3h
    bool rexW = false;
    uint8_t rexB = 0;

    bool hasModrm = false;
    uint8_t mod = 0;
    uint8_t reg = 0;            // поле reg с учётом REX.R
    uint8_t regRaw = 0;         // поле reg без REX (номер операции у групп 80h, F7h, FFh)
    uint8_t rm = 0;             // при mod == 3 — регистр с учётом REX.B
    int base = -1, index = -1;  // регистры адреса памяти (-1 — нет)
    bool absolute = false;      // [disp32] без регистров
    bool ripRel = false;        // [rip + disp32] (x64)
    int64_t disp = 0;
    uint64_t memAddr = 0;       // адрес для absolute / ripRel

    bool hasImm = false;
    int immSize = 0;
    int64_t imm = 0;            // со знаком
    uint64_t uimm = 0;          // без расширения знака (mov eax, 80000002h)

    bool relBranch = false;     // call/jmp/jcc с относительным адресом
    uint64_t target = 0;
};

// Декодирует инструкцию по смещению off (end — граница секции). false — байты не распознаны
bool decodeInsn(const vector<unsigned char>& b, size_t off, size_t end, uint64_t va, bool is64, Insn& out);

bool isMemory(const Insn& in);
