from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
from Crypto.PublicKey import RSA

from Crypto.Util.Padding import unpad

key = b"YELLOW SUBMARINE"

cipher = AES.new(key, AES.MODE_ECB)
plaintext = b'the guy is homosexual'

msg =cipher.encrypt(pad(plaintext, AES.block_size))
#print(msg)

#print(unpad(cipher.decrypt(msg), AES.block_size))
a = 'sddf'
bytes(a.encode('utf-8'))

a = json.dumps({'nombre': 'corro'})

print(type(json.loads(a)))

keyPair = RSA.generate(bits=1024) # it can also be imported from a file
pubKey = keyPair.publickey()
#print(pubKey)

def verificar(document):
    dict_document = json.loads(document)
    msg = bytes(dict_document['documento'], 'utf-8')
    signature_bytes = bytes.fromhex(dict_document['firma'])
    hash = SHA256.new(msg)
    verifier = PKCS115_SigScheme(pubKey)
    try:
        verifier.verify(hash, signature_bytes)
        return print("Signature is valid.")
    except:
        return  print("Signature is invalid.")

to_verify = {"documento":"gloria","firma":"25dfd17f76eda19934281c7bcf19d724f8acff0dbab6dcaa2018ed0f40df78d988180e383b62dae0426f7065b8cf0ebc29432cc10530b9983e08277de728cc8080538082c220f478e6937862d9a155c9f24b1b9c023adaa0e990745a13808ee81ad0cde7a37b12c55dfbd75d44416f782a7e68039f2056fd9760ec03ab5ce61f"}

print(verificar(to_verify))