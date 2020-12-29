scoreboard = {
    # From https://en.wikipedia.org/wiki/Letter_frequency
    'a': .08167, 'b': .01492, 
    'c': .02782, 'd': .04253,
    'e': .12702, 'f': .02228, 
    'g': .02015, 'h': .06094,
    'i': .06094, 'j': .00153, 
    'k': .00772, 'l': .04025,
    'm': .02406, 'n': .06749, 
    'o': .07507, 'p': .01929,
    'q': .00095, 'r': .05987, 
    's': .06327, 't': .09056,
    'u': .02758, 'v': .00978, 
    'w': .02360, 'x': .00150,
    'y': .01974, 'z': .00074,
    ' ': .13500
}

# score the given byte array based on the above scoreboard
def score(b):
    score_t = 0
    for byte in b:
        val = scoreboard.get(chr(byte).lower())
        score_t += val if val is not None else 0
    return score_t

# xor two byte arrays
def xor(b1, b2):
    b = bytearray(len(b1))
    for i, (byte1, byte2) in enumerate(zip(b1,b2)):
        b[i] = byte1 ^ byte2
    return b


if __name__ == "__main__":
    f = open("4.txt", 'r')

    best_score = 0
    best_char = None
    best_guess = 0

    for line in f.readlines():
        hex_string = bytes.fromhex(line)

        for byte_guess in range(128):
            guess = xor(hex_string, [byte_guess]*len(hex_string))

            score_guess = score(guess)

            if score_guess > best_score:
                best_score = score_guess
                best_char = byte_guess
                best_guess = guess

    print(f"Best Guess: {bytes(best_guess)}\n"
        f"Score: {best_score}\n"
        f"Char: 0x{best_char} ({bytes([best_char])})")



