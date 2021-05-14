from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA


def openPrivateKeyFile(privatekey):
    f = open('./assets/privatekey.txt', 'wb')
    f.write(bytes(privatekey.exportKey('PEM')));
    f.close()
    g = open('./assets/privatekey.txt').read()
    print(g)
    return g

def openSignatureFile(sig):
    f = open('./assets/signature.txt', 'wb')
    f.write(bytes(sig));
    f.close()
    s = open('./assets/signature.txt', 'rb')
    signature = s.read();
    s.close()
    print(signature)
    return signature

def openPublicKeyFile(publickey):
    f = open('./assets/publickey.txt', 'wb')
    f.write(bytes(publickey.exportKey('PEM')));
    f.close()
    g = open('./assets/publickey.txt').read()
    print(g)
    return g


def main():
    message = open('./assets/text.txt').read().encode('utf-8')

    privatekey = RSA.generate(1024)
    g = openPrivateKeyFile(privatekey)

    key = RSA.importKey(g)
    h = SHA.new(message)

    print(h.hexdigest())

    signer = PKCS1_v1_5.new(key)
    sig = signer.sign(h)
    signature = openSignatureFile(sig)

    publickey = privatekey.publickey()
    g = openPublicKeyFile(publickey)
    key = RSA.importKey(g)
    h = SHA.new(message)
    verifier = PKCS1_v1_5.new(key)
    if verifier.verify(h, signature):
        print("The same signature")
    else:
        print("Wrong signature")


if __name__ == "__main__":
    main()