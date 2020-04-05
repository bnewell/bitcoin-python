#!/usr/bin/python3
#
# Helper functions to generate uncompressed bitcoin addresses.
#
# Sources:
#   http://procbits.com/2013/08/27/generating-a-bitcoin-address-with-javascript
#   https://tools.ietf.org/html/rfc5480#section-2.2
#   http://www.secg.org/sec2-v2.pdf
#   https://en.bitcoin.it/wiki/Wallet_import_format
#
# secp256k1 refers to the parameters of the Elliptic Curve Digital Signature Algorithm (ECDSA curve) used in Bitcoin,
# and is defined in Standards for Efficient Cryptography (SEC) (http://www.secg.org/sec2-v2.pdf)
# Also known as the 256-bit Elliptic Curve Domain Parameters for the Koblitz curve
#
import random
import binascii
import hashlib
# pip3 install base58 ecdsa
import base58
import ecdsa

SAMPLE_PASSPHRASE = "correct horse battery staple"
# This is the upper bound for private keys / secret exponents
# as specified in secp256k1.
PRIVATE_KEY_UPPER_BOUND = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def passphraseToPrivateKey(passphrase):
    ''' Create private key from passphrase. '''
    return hashlib.sha256(passphrase.encode()).hexdigest()


def generatePrivateKey():
    ''' Create a randomly generated private key. '''
    privateKey = ""
    while True:
        # 255 is the highest numerical value for 8 bits
        randArr = [random.randint(0, 255) for x in range(32)]
        for i in range(len(randArr)):
            # hex() prepends '0x', remove it and prepend 0 in
            # front of any single digits.
            # (i.e. 5 -> 0x5 -> 5 -> 05)
            privateKey += hex(randArr[i])[2:].zfill(2)

        # If key is within secp256k1 bounds, we are done
        # int() converts our hex string (base 16) to a big int
        if 1 < int(privateKey, 16) < PRIVATE_KEY_UPPER_BOUND:
            break

    return privateKey.upper()


def keyToWif(key):
    ''' Convert private key to wallet import format (WIF). '''
    # Add a 0x80 byte in front of key
    keyAndVersion = "80" + key
    # Perform SHA-256 hash on key
    firstSHA = hashlib.sha256(bytes.fromhex(keyAndVersion)).hexdigest()
    # Perform 2nd SHA-256 hash on first SHA-256 hash
    secondSHA = hashlib.sha256(bytes.fromhex(firstSHA)).hexdigest()
    # First 4 bytes of the second SHA-256 hash is the checksum
    checksum = secondSHA[:8]
    # Add checksum to the end of 2nd SHA-256 hash
    privateKeyWithChecksum = keyAndVersion + checksum.upper()
    # Encode result with base58
    privateKeyWif = base58.b58encode(bytes.fromhex(privateKeyWithChecksum))
    return privateKeyWif


def wifToKey(wif):
    ''' Convert Wallet Import Format (WIF) back to private key. '''
    # Decode from base58 and remove first '0x80' byte and last 4 checksum bytes
    decodedKey = base58.b58decode(wif)[1:-4]
    key = ""
    for i in range(len(decodedKey)):
        key += hex(decodedKey[i])[2:].zfill(2)
    return key


def getXY(verifyingKey):
    ''' Get X and Y coordinates from the verifying key. '''
    x = ""
    y = ""
    for i in range(len(verifyingKey)):
        val = hex(verifyingKey[i])[2:].zfill(2)
        if (i < 32):
            x += val
        else:
            y += val
    return x, y


def compressPublicKey(x, y):
    ''' Compress public key. '''
    compressedKey = ""
    if(int(y, 16) % 2 == 0):
        # if y is even add 02 to front of x, else add 03.
        compressedKey = "02" + x
    else:
        compressedKey = "03" + x
    return compressedKey


def publicKeyToBitcoinAddress(publicKey):
    ''' Create bitcoin address from public key. '''
    publicSHA = hashlib.sha256(bytes.fromhex(publicKey)).hexdigest()
    hash160 = hashlib.new('ripemd160')
    hash160.update(bytes.fromhex(publicSHA))
    hash160 = hash160.hexdigest()
    hashAndVersion = "00" + hash160
    doubleSHA = hashlib.sha256(bytes.fromhex(hashAndVersion)).hexdigest()
    doubleSHA = hashlib.sha256(bytes.fromhex(doubleSHA)).hexdigest()
    addressChecksum = doubleSHA[:8]
    unencodedAddress = "00" + hash160 + addressChecksum
    bitcoinAddress = base58.b58encode(bytes.fromhex(unencodedAddress))
    return bitcoinAddress


def createAddressFromPassphrase(passphrase):
    ''' Create bitcoin address from a passphrase. '''
    privateKey = passphraseToPrivateKey(passphrase)
    curve = ecdsa.curves.SECP256k1
    signingKey = ecdsa.keys.SigningKey.from_secret_exponent(
        int(privateKey, 16), curve)
    verifyingKey = signingKey.get_verifying_key()
    x, y = getXY(verifyingKey.to_string())
    publicKey = "04" + x + y
    bitcoinAddress = publicKeyToBitcoinAddress(publicKey)
    return bitcoinAddress


def unit_test():
    addr = createAddressFromPassphrase(SAMPLE_PASSPHRASE)
    # The public address for "correct horse battery staple" can been seen here:
    # https://www.blockchain.com/btc/address/1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T
    assert(addr == b'1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T')


def example():
    privateKey = passphraseToPrivateKey(SAMPLE_PASSPHRASE)
    privateKeyWif = keyToWif(privateKey)
    curve = ecdsa.curves.SECP256k1
    # The secret exponent is the private key, which is used to get the public key.
    secretExponent = int(privateKey, 16)
    signingKey = ecdsa.keys.SigningKey.from_secret_exponent(
        secretExponent, curve)
    verifyingKey = signingKey.get_verifying_key()
    x, y = getXY(verifyingKey.to_string())
    # An uncompompressed public key is a 65 byte long value consisting of a leading 0x04
    # and X and Y coordinates of 32 bytes each.
    publicKey = "04" + x + y
    bitcoinAddress = publicKeyToBitcoinAddress(publicKey)
    print("private key: %s" % privateKey)
    print("        wif: %s" % privateKeyWif)
    print("public addr: %s" % bitcoinAddress.decode("utf-8"))
    print("public  key: %s" % publicKey)


unit_test()
example()
