import random


const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/"

func toByteSeq*(str: string): seq[byte] {.inline.} =
  @(str.toOpenArrayByte(0, str.high))

proc genRandomStr*(len: int): string =
    randomize()
    result = newStringOfCap(len)
    for i in 0..<len:
        result.add(charset[rand(len(charset)-1)])
    return result

proc byteSeqToString*(data: seq[byte]): string =
    result = ""
    for b in data:
        result.add(char(b))

proc padAES*(data: openArray[byte], blockSize: int = 16): seq[byte] =
    let paddingLen = blockSize - (len(data) mod blockSize)
    result = newSeq[byte](len(data) + paddingLen)
    for i in 0..<len(data):
        result[i] = data[i]
    for i in len(data)..<len(data) + paddingLen:
        result[i] = byte(paddingLen)

proc unpadAES*(data: openArray[byte], blockSize: int = 16): seq[byte] =
    if len(data) == 0 or len(data) mod blockSize != 0:
        raise newException(ValueError, "Invalid data length")

    let paddingLen = int(data[^1])  # Get the last byte to determine the padding length
    if paddingLen <= 0 or paddingLen > blockSize:
        raise newException(ValueError, "Invalid padding length")

    for i in len(data) - paddingLen..<len(data):
        if data[i] != byte(paddingLen):
            raise newException(ValueError, "Invalid padding")

    result = newSeq[byte](len(data) - paddingLen)
    for i in 0..<len(data) - paddingLen:
        result[i] = data[i]


when isMainModule:
    echo genRandomStr(16)
