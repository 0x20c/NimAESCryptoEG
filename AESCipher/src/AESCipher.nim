import nimcrypto
import utils


proc encryptData*(key: openArray[byte], msg: openArray[byte]): string
proc decryptData*(key: openArray[byte], msg: openArray[byte]): string


proc decryptData*(key: openArray[byte], msg: openArray[byte]): string =
    var 
        _, dctx: CBC[aes256]
        keyMem: array[aes256.sizeKey, byte]
        ivMem: array[aes256.sizeBlock, byte]
        # len(msg) - 1：去掉存储 IV 长度的那个字节。
        # aes256.sizeBlock：去掉 IV 本身的长度。
        dectext = newSeq[byte](len(msg) - aes256.sizeBlock - 1)

    let ivLen = int(msg[0])
    var iv    = msg[1..ivLen]
    copyMem(addr ivMem[0], addr iv[0], len(iv))


    if key.len != aes256.sizeKey:
        raise newException(ValueError, "Invalid key size. Expected 32 bytes for AES256.")
    copyMem(addr keyMem[0], addr key[0], len(key))

    var data = msg[ivLen+1..msg.len-1]

    dctx.init(keyMem, ivMem)
    dctx.decrypt(data, dectext)
    dctx.clear()

    let unpaddedData = unpadAES(dectext)

    echo "==============="
    echo "IV Len:           \t", ivLen
    echo "IV:               \t", iv.toHex
    echo "ENC TEXT:         \t", data.toHex
    echo "DEC TEXT:         \t", dectext.toHex
    echo "DEC TEXT(unpad):  \t", unpaddedData.toHex
    echo "DEC TEXT(string): \t", unpaddedData.byteSeqToString
    echo "==============="
    return unpaddedData.toHex

proc encryptData*(key: openArray[byte], msg: openArray[byte]): string = 
    var 
        ectx, _: CBC[aes256]
        keyMem: array[aes256.sizeKey, byte]
        ivMem: array[aes256.sizeBlock, byte]
        plaintext = newSeq[byte](len(msg))
        enctext   = newSeq[byte](len(msg))

    let ivLen = 16
    var iv    = genRandomStr(ivLen)
    copyMem(addr ivMem[0], addr iv[0], len(iv))

    copyMem(addr plaintext[0], addr msg[0], len(msg))

    if key.len != aes256.sizeKey:
        raise newException(ValueError, "Invalid key size. Expected 32 bytes for AES256.")

    copyMem(addr keyMem[0], addr key[0], len(key))

    ectx.init(keyMem, ivMem)
    ectx.encrypt(plaintext, enctext)
    ectx.clear()

    echo "==============="
    echo "IV:           \t", toHex(ivMem)
    echo "PAN:          \t", toHex(plaintext)
    echo "ENC:          \t", toHex(enctext)
    echo "RES:          \t", $ivLen & toHex(ivMem) & toHex(enctext)
    echo "==============="
    return toHex(@[byte(ivLen)]) & toHex(ivMem) & toHex(enctext)


when isMainModule:
    var key = genRandomStr(32).toByteSeq
    echo "==============="
    echo "KEY: ", key.toHex

    var data = padAES(toByteSeq("hello world"))

    let endata = encryptData(key, data)

    var _ = decryptData(key, endata.fromHex)
