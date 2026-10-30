# Рисунки для курсовой. Образец читается из stdin (из архива), на диск не пишется.
import sys, os, re
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Polygon
from PIL import Image, ImageDraw, ImageFont

OUT = sys.argv[1]
BUILD = sys.argv[2]
CONSOLE = sys.argv[3]
data = sys.stdin.buffer.read()
plt.rcParams["font.family"] = "Times New Roman"
plt.rcParams["font.size"] = 12

GREY = "#F2F2F2"
EDGE = "#333333"
ACCENT = "#DCE6F2"
WARN = "#F8D7D0"


def save(fig, name):
    fig.savefig(os.path.join(OUT, name), dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def box(ax, x, y, w, h, text, fill=GREY, size=11, bold=False, shape="round"):
    if shape == "diamond":
        pts = [(x + w / 2, y + h), (x + w, y + h / 2), (x + w / 2, y), (x, y + h / 2)]
        ax.add_patch(Polygon(pts, closed=True, fc=fill, ec=EDGE, lw=1.2))
    else:
        style = "round,pad=0.02,rounding_size=0.12" if shape == "round" else "square,pad=0.02"
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=style, fc=fill, ec=EDGE, lw=1.2))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=size,
            fontweight="bold" if bold else "normal", wrap=True)


def arrow(ax, x1, y1, x2, y2, label=None, lx=0.08, ly=0.0):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle="-|>", color=EDGE, lw=1.2, shrinkA=0, shrinkB=0))
    if label:
        ax.text((x1 + x2) / 2 + lx, (y1 + y2) / 2 + ly, label, fontsize=10, ha="left", va="center")


def line(ax, pts):
    xs, ys = zip(*pts)
    ax.plot(xs, ys, color=EDGE, lw=1.2)


# ------------------------------------------------------------ 1. Архитектура ИАС
fig, ax = plt.subplots(figsize=(10, 6.2))
ax.set_xlim(0, 10); ax.set_ylim(0, 6.2); ax.axis("off")
box(ax, 0.2, 5.1, 2.3, 0.8, "Путь к файлу\nили стандартный ввод", fill="white")
box(ax, 3.0, 5.1, 3.8, 0.8, "input — приём данных, хэши,\nизвлечение и нормализация строк", fill=ACCENT)
box(ax, 7.3, 5.1, 2.5, 0.8, "strings_<имя>.txt", fill="white")
arrow(ax, 2.5, 5.5, 3.0, 5.5); arrow(ax, 6.8, 5.5, 7.3, 5.5)
box(ax, 0.2, 3.5, 2.6, 1.0, "pe — заголовки,\nсекции, энтропия,\nтаблица импорта", fill=ACCENT)
box(ax, 3.2, 3.5, 3.4, 1.0, "signatures — матрица сигнатур:\nмета-данные, ошибки, IOC,\nCWE / CVE / MITRE ATT&CK", fill=ACCENT)
box(ax, 7.0, 3.5, 2.8, 1.0, "disasm — декодер\nинструкций x86 / x64", fill=ACCENT)
arrow(ax, 4.9, 5.1, 1.5, 4.5); arrow(ax, 4.9, 5.1, 4.9, 4.5); arrow(ax, 4.9, 5.1, 8.4, 4.5)
box(ax, 4.6, 1.9, 5.2, 1.0, "fsanalysis — анализ взаимодействия с ФС:\nвызовы WinAPI с аргументами, функции,\nграф вызовов, цепочки поведения", fill=WARN)
arrow(ax, 8.4, 3.5, 8.4, 2.9); arrow(ax, 1.5, 3.5, 4.6, 2.5)
box(ax, 0.2, 0.2, 4.0, 1.1, "report — оценка риска и отчёт:\nОбъект анализа, Уязвимости, IOC,\nФС, Оценка риска, Рекомендации", fill=ACCENT)
arrow(ax, 4.9, 3.5, 2.2, 1.3); arrow(ax, 7.2, 1.9, 4.2, 0.9)
box(ax, 5.2, 0.2, 4.6, 1.1, "report_<имя>.txt — аналитический отчёт\nreport_<имя>.csv — таблица находок", fill="white")
arrow(ax, 4.2, 0.75, 5.2, 0.75)
save(fig, "fig01_arch.png")

# ------------------------------------------------------------ 2. Восстановление аргументов
fig, ax = plt.subplots(figsize=(10, 3.4))
ax.set_xlim(0, 10); ax.set_ylim(0, 3.4); ax.axis("off")
steps = [
    ("Байты секции\n.text", "white"),
    ("Границы функций\n(цели call,\nпрологи)", ACCENT),
    ("Декодирование\nинструкций\nx86 / x64", ACCENT),
    ("Модель стека,\nрегистров\nи буферов", WARN),
    ("Вызовы WinAPI\nс аргументами", ACCENT),
    ("Цепочки\nповедения\n(ATT&CK)", ACCENT),
]
w, gap = 1.45, 0.24
for i, (t, c) in enumerate(steps):
    x = 0.1 + i * (w + gap)
    box(ax, x, 1.5, w, 1.3, t, fill=c, size=10.5)
    if i:
        arrow(ax, x - gap, 2.15, x, 2.15)
ax.text(5.0, 0.75, "push / mov / lea / rep movs / repne scas / call / add esp — отслеживаются значения:\n"
        "константы, адреса строк, буферы в стеке (var_N), аргументы функции (arg_N), результаты API",
        ha="center", va="center", fontsize=10.5, style="italic")
save(fig, "fig02_pipeline.png")


# ------------------------------------------------------------ hex-дампы
def hexdump(start, end, marks, name, legend):
    font = ImageFont.truetype("C:/Windows/Fonts/cour.ttf", 26)
    bold = ImageFont.truetype("C:/Windows/Fonts/courbd.ttf", 26)
    cw, ch = 16, 34
    rows = (end - start + 15) // 16
    width = 76 * cw + 40
    height = (rows + 1) * ch + 30 + (len(legend) * 34 + 20)
    img = Image.new("RGB", (width, height), "white")
    d = ImageDraw.Draw(img)
    d.text((20, 10), "Offset    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII", font=bold, fill="black")
    color_of = {}
    for (a, b, col) in marks:
        for o in range(a, b):
            color_of[o] = col
    for r in range(rows):
        off = start + r * 16
        y = 10 + (r + 1) * ch
        d.text((20, y), f"{off:08X}", font=font, fill="#555555")
        for i in range(16):
            o = off + i
            if o >= end or o >= len(data):
                break
            x = 20 + (10 + i * 3) * cw
            ax_ = 20 + (59 + i) * cw
            if o in color_of:
                d.rectangle([x - 2, y - 2, x + 2 * cw + 2, y + ch - 6], fill=color_of[o])
                d.rectangle([ax_, y - 2, ax_ + cw, y + ch - 6], fill=color_of[o])
            d.text((x, y), f"{data[o]:02X}", font=font, fill="black")
            c = data[o]
            d.text((ax_, y), chr(c) if 32 <= c < 127 else ".", font=font, fill="black")
    y = 10 + (rows + 1) * ch + 20
    for col, text in legend:
        d.rectangle([20, y + 4, 52, y + 26], fill=col, outline="black")
        lf = ImageFont.truetype("C:/Windows/Fonts/times.ttf", 28)
        d.text((64, y), text, font=lf, fill="black")
        y += 34
    img.save(os.path.join(OUT, name))


C1, C2, C3, C4, C5 = "#FFD966", "#9DC3E6", "#A9D18E", "#F4B183", "#D9B3FF"
hexdump(0x00, 0x80, [(0, 2, C1), (0x3C, 0x40, C2), (0x4E, 0x76, C3)], "fig03_dos.png",
        [(C1, "e_magic = «MZ» — сигнатура DOS-заголовка"),
         (C2, "e_lfanew = 0x000000E0 — смещение заголовка PE"),
         (C3, "DOS-заглушка «This program cannot be run in DOS mode.»")])
nt = 0xE0
hexdump(0xE0, 0x1D8, [(nt, nt + 4, C1), (nt + 4, nt + 6, C2), (nt + 8, nt + 12, C3), (nt + 24 + 16, nt + 24 + 20, C4),
                      (nt + 24 + 28, nt + 24 + 32, C5), (nt + 24 + 96 + 8, nt + 24 + 96 + 16, C2)],
        "fig04_pe.png",
        [(C1, "Signature = «PE\\0\\0»"),
         (C2, "Machine = 0x014C (x86); DataDirectory[1] — таблица импорта: RVA 0x9580, размер 0x3C"),
         (C3, "TimeDateStamp = 0x3B874509 (25.08.2001 06:26:17 UTC)"),
         (C4, "AddressOfEntryPoint = 0x1995"),
         (C5, "ImageBase = 0x00400000")])
hexdump(0x1D8, 0x278, [(0x1D8, 0x1E0, C1), (0x200, 0x208, C1), (0x228, 0x230, C1), (0x250, 0x258, C1)],
        "fig05_sections.png", [(C1, "Имена секций: .text, .rdata, .data, .rsrc")])
hexdump(0xA040, 0xA180, [(0xA040, 0xA046, C4), (0xA054, 0xA058, C2), (0xA05C, 0xA06A, C3), (0xA09C, 0xA0A3, C4),
                         (0xA0A8, 0xA0B0, C2), (0xA0F8, 0xA119, C5), (0xA128, 0xA155, C1), (0xA158, 0xA15E, C1),
                         (0xA160, 0xA16C, C1), (0xA170, 0xA17D, C3)],
        "fig06_data.png",
        [(C4, "c:\\wxp, c:\\zwxp — файл-шаблон и пробный файл"),
         (C2, "\\*.* и Personal — маска перебора и папка «Мои документы»"),
         (C3, "notepad.exe %s и WhistlerMutex — запуск Блокнота и мьютекс"),
         (C5, "текст-послание, которым затираются файлы"),
         (C1, "ключ Run, аргумент -next и имя копии \\whismng.exe")])

# ------------------------------------------------------------ консоль
lines = open(CONSOLE, encoding="utf-8").read().splitlines()
prompt = "C:\\Claude pr\\kursovaya\\build> tar -xOf Whiter.a.rar Whiter.a.exe | ExeIAS.exe - --name Whiter.a.exe"
wrapped = [prompt]
for l in lines:
    while len(l) > 96:
        cut = l.rfind(" ", 0, 96)
        cut = cut if cut > 40 else 96
        wrapped.append(l[:cut]); l = "  " + l[cut:].lstrip()
    wrapped.append(l)
font = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 24)
img = Image.new("RGB", (98 * 13 + 40, len(wrapped) * 32 + 40), "#0C0C0C")
d = ImageDraw.Draw(img)
for i, l in enumerate(wrapped):
    d.text((20, 20 + i * 32), l, font=font, fill="#F2F2F2" if i else "#9CDCFE")
img.save(os.path.join(OUT, "fig07_console.png"))

# ------------------------------------------------------------ алгоритм Whiter.a
fig, ax = plt.subplots(figsize=(10, 13))
ax.set_xlim(0, 10); ax.set_ylim(0, 13); ax.axis("off")
box(ax, 3.5, 12.3, 3.0, 0.55, "Начало (WinMain)", fill="white")
box(ax, 2.8, 11.2, 4.4, 0.7, "CreateMutexA(\"WhistlerMutex\")", fill=ACCENT)
box(ax, 3.0, 9.9, 4.0, 0.95, "Мьютекс уже\nсуществует?", shape="diamond")
box(ax, 8.0, 10.1, 1.8, 0.55, "Выход", fill="white")
box(ax, 3.0, 8.5, 4.0, 0.95, "Командная строка\nпуста?", shape="diamond")
box(ax, 0.1, 7.2, 4.2, 0.8, "CopyFileA(себя ->\n%System%\\whismng.exe, FALSE)", fill=ACCENT)
box(ax, 0.3, 5.9, 3.8, 0.95, "Скопировано?", shape="diamond")
box(ax, 0.1, 4.6, 4.2, 0.8, "HKLM\\...\\Run: «Whistler» =\n\"...whismng.exe -next\"", fill=ACCENT)
box(ax, 0.1, 3.3, 4.2, 0.8, "Поддельный ключ XXXXX-XXXXX-...\nв %TEMP%\\~snXXXX.tmp -> Блокнот", fill=ACCENT)
box(ax, 0.3, 2.0, 3.8, 0.95, "Блокнот\nзапущен?", shape="diamond")
box(ax, 0.6, 0.6, 3.2, 0.55, "Выход до перезагрузки", fill="white")
box(ax, 5.4, 7.2, 4.4, 0.8, "Разрушительная часть\n(запуск с ключом -next)", fill=WARN, bold=True)
box(ax, 5.4, 6.0, 4.4, 0.8, "fopen(\"c:\\wxp\") + fprintf(\n\"You did a piracy, you deserve it.\")", fill=WARN)
box(ax, 5.4, 4.8, 4.4, 0.8, "Путь «Мои документы» из\nHKCU\\...\\Shell Folders\\Personal", fill=WARN)
box(ax, 5.4, 3.6, 4.4, 0.8, "sub_401000(«Мои документы»)", fill=WARN)
box(ax, 5.4, 2.4, 4.4, 0.8, "Для дисков d: … z: если создаётся\n<диск>:\\zwxp -> sub_401000(<диск>:)", fill=WARN)
box(ax, 5.4, 1.2, 4.4, 0.8, "sub_401000(\"c:\")", fill=WARN)
arrow(ax, 5.0, 12.3, 5.0, 11.9); arrow(ax, 5.0, 11.2, 5.0, 10.85)
arrow(ax, 7.0, 10.375, 8.0, 10.375, "да", lx=-0.25, ly=0.18)
arrow(ax, 5.0, 9.9, 5.0, 9.45, "нет")
line(ax, [(3.0, 8.975), (2.2, 8.975)]); arrow(ax, 2.2, 8.975, 2.2, 8.0); ax.text(0.6, 9.15, "да (первый запуск)", fontsize=10)
line(ax, [(7.0, 8.975), (7.6, 8.975)]); arrow(ax, 7.6, 8.975, 7.6, 8.0); ax.text(7.0, 9.15, "нет", fontsize=10)
arrow(ax, 2.2, 7.2, 2.2, 6.85)
arrow(ax, 2.2, 5.9, 2.2, 5.4, "да")
line(ax, [(4.1, 6.375), (4.85, 6.375), (4.85, 7.6)]); arrow(ax, 4.85, 7.6, 5.4, 7.6); ax.text(4.2, 6.55, "нет", fontsize=10)
arrow(ax, 2.2, 4.6, 2.2, 4.1); arrow(ax, 2.2, 3.3, 2.2, 2.95)
arrow(ax, 2.2, 2.0, 2.2, 1.15, "да")
line(ax, [(4.1, 2.475), (4.85, 2.475), (4.85, 7.4)]); ax.text(4.2, 2.65, "нет", fontsize=10)
arrow(ax, 7.6, 7.2, 7.6, 6.8); arrow(ax, 7.6, 6.0, 7.6, 5.6); arrow(ax, 7.6, 4.8, 7.6, 4.4)
arrow(ax, 7.6, 3.6, 7.6, 3.2); arrow(ax, 7.6, 2.4, 7.6, 2.0)
line(ax, [(9.8, 1.6), (9.95, 1.6), (9.95, 4.0)]); arrow(ax, 9.95, 4.0, 9.8, 4.0)
ax.text(9.97, 2.8, "бесконечно", fontsize=10, rotation=90, va="center")
save(fig, "fig08_algorithm.png")

# ------------------------------------------------------------ функция уничтожения
fig, ax = plt.subplots(figsize=(10, 10))
ax.set_xlim(0, 10); ax.set_ylim(0, 10); ax.axis("off")
box(ax, 3.0, 9.3, 4.0, 0.55, "sub_401000(каталог)", fill="white")
box(ax, 2.5, 8.2, 5.0, 0.7, "FindFirstFileA(\"<каталог>\\*.*\")", fill=ACCENT)
box(ax, 3.0, 6.9, 4.0, 0.9, "Имя начинается\nс «.»?", shape="diamond")
box(ax, 3.0, 5.5, 4.0, 0.9, "Это каталог?", shape="diamond")
box(ax, 7.35, 5.6, 1.9, 0.7, "sub_401000(\nподкаталог)", fill=WARN, size=10.5)
box(ax, 2.5, 4.3, 5.0, 0.75, "Атрибут «только чтение» или\n«системный» -> SetFileAttributesA(NORMAL)", fill=WARN)
box(ax, 2.5, 3.2, 5.0, 0.75, "CopyFileA(\"c:\\wxp\", файл, FALSE) —\nсодержимое заменяется посланием", fill=WARN)
box(ax, 2.5, 2.1, 5.0, 0.7, "DeleteFileA(файл)", fill=WARN)
box(ax, 2.5, 1.0, 5.0, 0.7, "FindNextFileA — следующий элемент", fill=ACCENT)
box(ax, 3.5, 0.05, 3.0, 0.5, "FindClose, возврат", fill="white")
arrow(ax, 5, 9.3, 5, 8.9); arrow(ax, 5, 8.2, 5, 7.8)
arrow(ax, 5, 6.9, 5, 6.4, "нет"); arrow(ax, 7.0, 5.95, 7.35, 5.95, "да", lx=-0.25, ly=0.2)
line(ax, [(8.3, 5.6), (8.3, 1.35)])
arrow(ax, 5, 5.5, 5, 5.05, "нет")
arrow(ax, 5, 4.3, 5, 3.95); arrow(ax, 5, 3.2, 5, 2.8); arrow(ax, 5, 2.1, 5, 1.7)
arrow(ax, 5, 1.0, 5, 0.55, "конец")
line(ax, [(2.5, 1.35), (1.2, 1.35), (1.2, 7.35)]); arrow(ax, 1.2, 7.35, 3.0, 7.35); ax.text(1.3, 4.0, "есть ещё", fontsize=10, rotation=90)
line(ax, [(7.0, 7.35), (9.6, 7.35), (9.6, 1.35)]); arrow(ax, 9.6, 1.35, 7.5, 1.35); ax.text(7.2, 7.5, "да («.», «..»)", fontsize=10)
save(fig, "fig09_wipe.png")

# ------------------------------------------------------------ граф вызовов
fig, ax = plt.subplots(figsize=(10, 4.6))
ax.set_xlim(0, 10); ax.set_ylim(0, 4.6); ax.axis("off")
box(ax, 2.6, 3.0, 4.8, 1.4, "sub_401300 (WinMain)\nмьютекс • самокопирование • автозапуск\nпоиск «Документов» • перебор дисков\nфайл-шаблон c:\\wxp", fill=ACCENT, size=10.5)
box(ax, 0.2, 0.3, 4.3, 1.4, "sub_4011E0\nвременный файл ~snXXXX.tmp\nпоказ «ключа» в Блокноте", fill=ACCENT, size=10.5)
box(ax, 5.5, 0.3, 4.3, 1.4, "sub_401000\nрекурсивный обход • снятие атрибутов\nзатирание шаблоном • удаление", fill=WARN, size=10.5)
arrow(ax, 4.2, 3.0, 2.35, 1.7, "первый запуск", lx=-1.6)
arrow(ax, 5.8, 3.0, 7.65, 1.7, "3 вызова", lx=0.1)
ax.annotate("", xy=(9.8, 1.2), xytext=(9.8, 0.8), arrowprops=dict(arrowstyle="-|>", color=EDGE, lw=1.2,
            connectionstyle="arc3,rad=-1.8"))
ax.text(9.55, 1.85, "рекурсия", fontsize=10)
save(fig, "fig10_callgraph.png")

# ------------------------------------------------------------ сравнение баллов
names = {"Whiter.a.exe": "Whiter.a.exe\n(образец ВПО)", "sample_dropper.exe": "sample_dropper\n(демо ПР №7)",
         "cmd.exe": "cmd.exe", "notepad.exe": "notepad.exe", "ConsoleApp28.exe": "ConsoleApp28\n(.NET)",
         "sample_dotnet.exe": "sample_dotnet\n(демо ПР №7)", "sample_clean.exe": "sample_clean\n(демо ПР №7)",
         "xcopy.exe": "xcopy.exe"}
scores = []
for fn in os.listdir(BUILD):
    m = re.match(r"report_(.+)\.txt$", fn)
    if not m or m.group(1) not in names:
        continue
    text = open(os.path.join(BUILD, fn), encoding="utf-8-sig").read()
    s = int(re.search(r"Балл риска:\s+(\d+)", text).group(1))
    scores.append((s, names[m.group(1)]))
scores.sort(reverse=True)
fig, ax = plt.subplots(figsize=(10, 4.4))
vals = [s for s, _ in scores]
cols = ["#C0504D" if v >= 70 else "#E6A157" if v >= 45 else "#E9CF6B" if v >= 20 else "#9BBB59" for v in vals]
bars = ax.bar(range(len(vals)), vals, color=cols, edgecolor=EDGE, width=0.65)
for b, v in zip(bars, vals):
    ax.text(b.get_x() + b.get_width() / 2, v + 1.5, str(v), ha="center", fontsize=11)
ax.set_xticks(range(len(vals)), [n for _, n in scores], fontsize=10)
ax.set_ylim(0, 112); ax.set_ylabel("Балл риска")
for y, t in ((20, "низкая / средняя"), (45, "средняя / высокая"), (70, "высокая / очень высокая")):
    ax.axhline(y, color="#888888", lw=0.8, ls="--")
    ax.text(len(vals) - 0.45, y + 1.2, t, fontsize=9, ha="right", color="#555555")
ax.spines[["top", "right"]].set_visible(False)
save(fig, "fig11_scores.png")
print("figures:", sorted(os.listdir(OUT)))
