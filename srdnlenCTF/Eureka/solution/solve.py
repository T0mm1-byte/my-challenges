import argparse

from Crypto.Util.strxor import strxor
from pwn import context, serialtube

context.log_level = "error"

BUFFER_BLOCKS = 16
QUERY_TIMEOUT = 5

Z = b"\x00" * 16
def CST(k): return k.to_bytes(16, "big")

parser = argparse.ArgumentParser()
parser.add_argument("--port", default="/dev/ttyUSB0")
parser.add_argument("--baud", type=int, default=115386)
args = parser.parse_args()

io = serialtube(args.port, baudrate=args.baud, convert_newlines=False)
io.clean(0.3)

def recv_all(first_timeout=None, idle_timeout=1):
    data = b""
    while not data:
        data = io.recv(4096, timeout=first_timeout or 1)
        if first_timeout and not data:
            raise TimeoutError("no answer from the board")
    while True:
        chunk = io.recv(4096, timeout=idle_timeout)
        if not chunk:
            return data
        data += chunk

def encrypt(msg: bytes) -> bytes:
    assert len(msg) % 16 == 0 and len(msg) <= 16 * BUFFER_BLOCKS
    io.send(msg + Z * (BUFFER_BLOCKS - len(msg) // 16))
    out = io.recvn(16 * (BUFFER_BLOCKS + 1), timeout=QUERY_TIMEOUT)
    if len(out) != 16 * (BUFFER_BLOCKS + 1):
        raise TimeoutError(f"short answer from the board: {len(out)} bytes")
    return out

def blk(ct, i):  
    return ct[16*i:16*i+16]

print("Press the start button (B18) on the board to get the encrypted flag...")
flag_enc = recv_all()
assert len(flag_enc) % 16 == 0, f"unexpected flag length: {len(flag_enc)}"
print(f"encrypted flag: {flag_enc.hex()}")
ct = [flag_enc[i:i+16] for i in range(0, len(flag_enc), 16)]
nonce = ct[-1]
n = len(ct) - 1  

def getE(y: bytes) -> bytes:
    out = encrypt(CST(2) + Z + y)  
    return strxor(blk(out, 1), CST(3))

E0 = getE(Z)  

def getD(x: bytes) -> bytes:
    p1 = strxor(strxor(E0, CST(2)), x)
    out = encrypt(p1 + Z + Z)
    return strxor(strxor(blk(out, 1), E0), CST(3))

u = [None] * (n + 2)
u[n + 1] = nonce
for j in range(n - 1, -1, -1):
    u[j + 1] = getE(strxor(ct[j], u[j + 2]))

P = [nonce]
for k in range(1, n + 1):
    P.append(getD(strxor(strxor(u[k], P[k - 1]), CST(k))))

flag = b"".join(P[1:])
print(flag.decode(errors="replace"))

io.close()
