#include "disasm.h"

bool isMemory(const Insn& in)
{
    return in.hasModrm && in.mod != 3;
}

bool decodeInsn(const vector<unsigned char>& b, size_t off, size_t end, uint64_t va, bool is64, Insn& d)
{
    d = Insn();
    d.addr = va;
    size_t p = off;
    auto avail = [&](size_t n) { return p + n <= end && p + n <= b.size(); };

    // префиксы
    bool addr16 = false;
    for (int k = 0; k < 14; k++)
    {
        if (!avail(1))
            return false;
        uint8_t c = b[p];
        if (c == 0x66)
            d.opsize16 = true;
        else if (c == 0x67)
            addr16 = true;
        else if (c == 0xF2 || c == 0xF3)
            d.rep = true;
        else if (c != 0xF0 && c != 0x2E && c != 0x36 && c != 0x3E && c != 0x26 && c != 0x64 && c != 0x65)
            break;
        p++;
    }
    uint8_t rexR = 0, rexX = 0;
    if (is64 && avail(1) && (b[p] & 0xF0) == 0x40)
    {
        uint8_t rex = b[p++];
        d.rexW = (rex & 8) != 0;
        rexR = (rex >> 2) & 1;
        rexX = (rex >> 1) & 1;
        d.rexB = rex & 1;
    }
    if (addr16 && !is64)
        return false;     // 16-битная адресация в коде Win32 не встречается
    if (!avail(1))
        return false;

    uint8_t op = b[p++];
    bool modrm = false;
    int immSize = 0;
    const int z = d.opsize16 ? 2 : 4;

    if (op == 0x0F)
    {
        if (!avail(1))
            return false;
        d.twoByte = true;
        op = b[p++];
        if (op == 0x38)
        {
            if (!avail(1)) return false;
            p++;
            modrm = true;
        }
        else if (op == 0x3A)
        {
            if (!avail(1)) return false;
            p++;
            modrm = true;
            immSize = 1;
        }
        else if (op >= 0x80 && op <= 0x8F)
        {
            immSize = 4;
            d.relBranch = true;
        }
        else if ((op >= 0x70 && op <= 0x73) || op == 0xA4 || op == 0xAC || op == 0xBA || op == 0xC2
                 || (op >= 0xC4 && op <= 0xC6))
        {
            modrm = true;
            immSize = 1;
        }
        else if (op == 0x05 || op == 0x06 || op == 0x07 || op == 0x08 || op == 0x09 || op == 0x0B || op == 0x0E
                 || (op >= 0x30 && op <= 0x37) || op == 0x77 || op == 0xA0 || op == 0xA1 || op == 0xA2
                 || op == 0xA8 || op == 0xA9 || op == 0xAA || (op >= 0xC8 && op <= 0xCF))
        {
            // без ModRM
        }
        else
            modrm = true;
    }
    else if (op < 0x40)
    {
        if ((op & 7) < 4)
            modrm = true;                     // 00–03, 08–0B, ... 38–3B: операции r/m, r
        else if ((op & 7) == 4)
            immSize = 1;                      // al, imm8
        else if ((op & 7) == 5)
            immSize = z;                      // eax, imm32
        else if (is64 && (op == 0x06 || op == 0x07 || op == 0x0E || op == 0x16 || op == 0x17 || op == 0x1E
                          || op == 0x1F || op == 0x27 || op == 0x2F || op == 0x37 || op == 0x3F))
            return false;
    }
    else if (op < 0x60)
    {
        // inc/dec/push/pop r32 (в x64 40–4F — уже съеденный REX)
    }
    else
    {
        switch (op)
        {
        case 0x62: case 0x63:
            modrm = true;
            break;
        case 0x68:
            immSize = z;
            break;
        case 0x69:
            modrm = true; immSize = z;
            break;
        case 0x6A:
            immSize = 1;
            break;
        case 0x6B:
            modrm = true; immSize = 1;
            break;
        case 0x80: case 0x82: case 0x83: case 0xC0: case 0xC1: case 0xC6:
            modrm = true; immSize = 1;
            break;
        case 0x81: case 0xC7:
            modrm = true; immSize = z;
            break;
        case 0x9A: case 0xEA:
            if (is64)
                return false;
            immSize = 6;
            break;
        case 0xA0: case 0xA1: case 0xA2: case 0xA3:
        {
            size_t n = is64 ? 8 : 4;
            if (!avail(n))
                return false;
            uint64_t a = 0;
            for (size_t i = 0; i < n; i++)
                a |= (uint64_t)b[p + i] << (8 * i);
            p += n;
            d.absolute = true;
            d.memAddr = a;
            break;
        }
        case 0xA8: case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4: case 0xB5: case 0xB6: case 0xB7:
        case 0xCD: case 0xD4: case 0xD5: case 0xE4: case 0xE5: case 0xE6: case 0xE7:
            immSize = 1;
            break;
        case 0xA9:
            immSize = z;
            break;
        case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            immSize = d.rexW ? 8 : z;
            break;
        case 0xC2: case 0xCA:
            immSize = 2;
            break;
        case 0xC4: case 0xC5:
            if (is64)
                return false;   // VEX-префикс — векторные команды, в анализе не нужны
            modrm = true;
            break;
        case 0xC8:
            immSize = 3;
            break;
        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        case 0xE0: case 0xE1: case 0xE2: case 0xE3: case 0xEB:
            immSize = 1;
            d.relBranch = true;
            break;
        case 0xE8: case 0xE9:
            immSize = 4;
            d.relBranch = true;
            break;
        case 0xD0: case 0xD1: case 0xD2: case 0xD3:
        case 0xD8: case 0xD9: case 0xDA: case 0xDB: case 0xDC: case 0xDD: case 0xDE: case 0xDF:
        case 0xF6: case 0xF7: case 0xFE: case 0xFF:
            modrm = true;
            break;
        default:
            if (op >= 0x84 && op <= 0x8F)
                modrm = true;
            break;
        }
    }

    if (modrm)
    {
        if (!avail(1))
            return false;
        uint8_t m = b[p++];
        d.hasModrm = true;
        d.mod = m >> 6;
        d.regRaw = (m >> 3) & 7;
        d.reg = d.regRaw | (rexR << 3);
        uint8_t rm = m & 7;
        int dispSize = 0;
        if (d.mod == 3)
            d.rm = rm | (d.rexB << 3);
        else
        {
            if (rm == 4)
            {
                if (!avail(1))
                    return false;
                uint8_t sib = b[p++];
                uint8_t sbase = sib & 7;
                int idx = ((sib >> 3) & 7) | (rexX << 3);
                d.index = idx == 4 ? -1 : idx;
                if (sbase == 5 && d.mod == 0)
                {
                    dispSize = 4;
                    d.absolute = d.index < 0;
                }
                else
                    d.base = sbase | (d.rexB << 3);
            }
            else if (rm == 5 && d.mod == 0)
            {
                dispSize = 4;
                if (is64)
                    d.ripRel = true;
                else
                    d.absolute = true;
            }
            else
                d.base = rm | (d.rexB << 3);

            if (d.mod == 1)
                dispSize = 1;
            else if (d.mod == 2)
                dispSize = 4;
            if (!avail(dispSize))
                return false;
            if (dispSize == 1)
                d.disp = (int8_t)b[p];
            else if (dispSize == 4)
                d.disp = (int32_t)((uint32_t)b[p] | ((uint32_t)b[p + 1] << 8) | ((uint32_t)b[p + 2] << 16) | ((uint32_t)b[p + 3] << 24));
            p += dispSize;
        }
        // у F6/F7 непосредственный операнд есть только у test (reg 0 и 1)
        if (!d.twoByte && (op == 0xF6 || op == 0xF7))
            immSize = d.regRaw < 2 ? (op == 0xF6 ? 1 : z) : 0;
    }

    if (immSize > 0)
    {
        if (!avail(immSize))
            return false;
        d.hasImm = true;
        d.immSize = immSize;
        uint64_t u = 0;
        for (int i = 0; i < immSize && i < 8; i++)
            u |= (uint64_t)b[p + i] << (8 * i);
        d.uimm = u;
        if (immSize == 1) d.imm = (int8_t)u;
        else if (immSize == 2) d.imm = (int16_t)u;
        else if (immSize == 4) d.imm = (int32_t)u;
        else d.imm = (int64_t)u;
        p += immSize;
    }

    d.op = op;
    d.len = p - off;
    if (d.relBranch)
        d.target = va + d.len + d.imm;
    if (d.ripRel)
        d.memAddr = va + d.len + d.disp;
    else if (d.absolute && d.hasModrm)
        d.memAddr = (uint32_t)d.disp;
    return true;
}
