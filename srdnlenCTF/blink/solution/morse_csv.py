import csv, sys, statistics

TABLE = {
    ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f",
    "--.": "g", "....": "h", "..": "i", ".---": "j", "-.-": "k", ".-..": "l",
    "--": "m", "-.": "n", "---": "o", ".--.": "p", "--.-": "q", ".-.": "r",
    "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x",
    "-.--": "y", "--..": "z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", "-.--.": "{", "-.--.-": "}", "..--.-": "_",
    "-....-": "-", ".-.-.-": ".", "--..--": ",", "..--..": "?", "-.-.--": "!",
    "-..-.": "/", "---...": ":", "-.-.-.": ";", "-...-": "=", ".-.-.": "+",
    ".-...": "&", ".--.-.": "@", "...-..-": "$", ".----.": "'", ".-..-.": '"',
}

rows = list(csv.reader(open(sys.argv[1])))
col = int(sys.argv[2]) if len(sys.argv) > 2 else 1
edges = [(float(r[0]), int(float(r[col]))) for r in rows[1:] if r]

runs = [(lvl, t1 - t0) for (t0, lvl), (t1, _) in zip(edges, edges[1:])]
marks = [d for lvl, d in runs if lvl == 1]
unit = statistics.median([d for d in marks if d < 2 * min(marks)])

out, sym = [], ""
for lvl, d in runs:
    u = d / unit
    if lvl == 1:
        sym += "." if u < 2 else "-"
    elif u >= 2:
        out.append(TABLE.get(sym, "#") if sym else "")
        sym = ""
        if u >= 10:
            out.append("\n")
        elif u >= 5:
            out.append(" ")
if sym:
    out.append(TABLE.get(sym, "#"))

print("".join(out).strip())
