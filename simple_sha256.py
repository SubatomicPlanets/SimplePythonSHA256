#functions used by sha256
def rotright(a, b):
    return ((a >> b) | (a << (32 - b))) %2**32
def SIG0(x):
    return rotright(x, 7) ^ rotright(x, 18) ^ (x >> 3)
def SIG1(x):
    return rotright(x, 17) ^ rotright(x, 19) ^ (x >> 10)
def EP0(x):
    return rotright(x, 2) ^ rotright(x, 13) ^ rotright(x, 22)
def EP1(x):
    return rotright(x, 6) ^ rotright(x, 11) ^ rotright(x, 25)
def CH(x, y, z):
    return (x & y) ^ (~x & z)
def MAJ(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

#constants
K = [
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]

def sha256_transform(data, state):
    #variables
    a = state[0]
    b = state[1]
    c = state[2]
    d = state[3]
    e = state[4]
    f = state[5]
    g = state[6]
    h = state[7]
    m = [0]*64

    #fill the first 16 elements of m with data
    j = 0
    for i in range(16):
        m[i] = ((data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | (data[j+3])) %2**32
        j += 4

    #fill the rest 48 elements of m
    for i in range(16, 64):
        m[i] = (SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16]) %2**32

    #64 rounds
    for i in range(64):
        t1 = (h + EP1(e) + CH(e,f,g) + K[i] + m[i]) %2**32
        t2 = (EP0(a) + MAJ(a,b,c)) %2**32
        h = g
        g = f
        f = e
        e = (d + t1) %2**32
        d = c
        c = b
        b = a
        a = (t1 + t2) %2**32

    #update the state
    state[0] = (state[0]+a) %2**32
    state[1] = (state[1]+b) %2**32
    state[2] = (state[2]+c) %2**32
    state[3] = (state[3]+d) %2**32
    state[4] = (state[4]+e) %2**32
    state[5] = (state[5]+f) %2**32
    state[6] = (state[6]+g) %2**32
    state[7] = (state[7]+h) %2**32

def sha256(data):
    #variables
    state = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]
    bytes_data_length = (len(data)*8).to_bytes(8, "big")

    #pad data
    data += b"\x80"
    padding_needed = (64-(len(data)+8)%64)%64
    for i in range(padding_needed):
        data += b"\x00"
    data += bytes_data_length

    #split data into chunks and transform
    message_blocks = [data[i:i + 64] for i in range(0, len(data), 64)]
    for block in message_blocks:
        sha256_transform(block, state)

    #output
    return "".join(hex(i)[2:] for i in state)


#use like this:
#print(sha256(b"hello world"))