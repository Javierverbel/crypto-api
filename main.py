from flask import Flask
from flask import jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
import json
from flask import request

app = Flask(__name__)

@app.route("/")
def hello():
    return "Hello, World!"

key = b"YELLOW SUBMARINE"

@app.route("/cifrador/<plaintext>")
def cifrador(plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    msg = cipher.encrypt(pad(bytes(plaintext.encode('utf-8')), AES.block_size))
    return msg.hex()

@app.route("/descifrador/<ciphertext>")
def descifrador(ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    msg = unpad(cipher.decrypt(bytes.fromhex(ciphertext)), AES.block_size)
    return msg

keyPair = RSA.generate(bits=1024) # it can also be imported from a file
pubKey = keyPair.publickey()

@app.route("/firmar/<document>")
def firmar(document):
    hash = SHA256.new(bytes(document, 'utf-8'))
    signer = PKCS115_SigScheme(keyPair)
    signature = signer.sign(hash)
    return jsonify({'documento': document, 'firma': signature.hex()})


@app.route("/verificar", methods=['POST'])
def verificar():
    dict_document = request.json
    msg = bytes(dict_document['documento'], 'utf-8')
    signature_bytes = bytes.fromhex(dict_document['firma'])
    hash = SHA256.new(msg)
    verifier = PKCS115_SigScheme(pubKey)
    try:
        verifier.verify(hash, signature_bytes)
        return "Signature is valid."
    except:
        return "Signature is invalid."


app.run(host='0.0.0.0')


