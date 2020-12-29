b1 = bytes.fromhex('1c0111001f010100061a024b53535009181c')
b2 = bytes.fromhex('686974207468652062756c6c277320657965')

out = bytearray()

for i, j in zip(b1,b2):
    out.append(i^j)

print(out.hex())