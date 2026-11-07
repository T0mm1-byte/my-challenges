import csv
import struct
import sys

MAGIC = b"BLNK"
BLOCK = 1024
FRAME = 4 + 2 + 2 + BLOCK + 4


def stm32_crc(data):
    crc = 0xFFFFFFFF
    for (word,) in struct.iter_unpack("<I", data):
        crc ^= word
        for _ in range(32):
            crc = ((crc << 1) ^ 0x04C11DB7) if crc & 0x80000000 else (crc << 1)
            crc &= 0xFFFFFFFF
    return crc


def read_bytes(path):
    with open(path, newline="") as f:
        rows = csv.DictReader(f)
        return bytes(int(r["data"], 16) for r in rows if r["type"] == "data")


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "dump.csv"
    dst = sys.argv[2] if len(sys.argv) > 2 else "firmware.bin"

    stream = read_bytes(src)
    print(f"{len(stream)} bytes from {src}")

    blocks, total, bad = {}, None, 0
    pos = stream.find(MAGIC)
    while pos != -1 and pos + FRAME <= len(stream):
        frame = stream[pos:pos + FRAME]
        index, count = struct.unpack_from("<HH", frame, 4)
        (crc,) = struct.unpack_from("<I", frame, FRAME - 4)

        if stm32_crc(frame[:-4]) == crc and index < count:
            blocks[index] = frame[8:-4]
            total = count
            pos = stream.find(MAGIC, pos + FRAME)
        else:
            bad += 1
            pos = stream.find(MAGIC, pos + 1)

    if total is None:
        sys.exit("no valid frame found")

    missing = [i for i in range(total) if i not in blocks]
    image = b"".join(blocks.get(i, b"\xff" * BLOCK) for i in range(total))
    with open(dst, "wb") as f:
        f.write(image)

if __name__ == "__main__":
    main()
