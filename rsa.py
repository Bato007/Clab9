import Crypto.Util.number as CN
import Crypto.Random as random
import hashlib
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from base64 import b64decode, b64encode
from generator import Keys

class RSA(object):
    def encrypt(self, path):
        # Cargo el path del mensaje
        with open(path + '.txt', 'r') as f: message = f.read()
        # Cargo llave publica
        publicKey = Keys().load('keys')[0]
        
        e, N = [int(pk) for pk in publicKey.split('.')]
        
        # Generate x value
        while True:
            x = CN.getRandomInteger(N.bit_length(), randfunc=random.get_random_bytes)
            if 1 < x and x < N: break

        # Generates y value
        y = (x**e) % N

        # Generates k value
        hash = hashlib.sha256()
        hash.update(bytes(str(x), 'utf-8'))
        k = hash.digest()

        # Get ciphered message
        cbc = AES.new(k, AES.MODE_CBC)
        iv = b64encode(cbc.iv).decode('utf-8')
        
        ct_bytes = cbc.encrypt(pad(bytes(message, 'utf-8'), AES.block_size))
        c = iv + ' ' + b64encode(ct_bytes).decode('utf-8')
        
        with open('encrypt.txt', 'w') as f:
            f.write(str(y) + ' ' + c)

    def decrypt(self, path):
        # Cargo iv y resultado del cifrado
        with open(path + '.txt', 'r') as f: lines = f.read().split(' ')
        y, iv, mbytes = int(lines[0]), lines[1], lines[2]
        privateKey = Keys().load('keys')[1]
        d, N = [int(pk) for pk in privateKey.split('.')]
        x = (y ** d) % N

        # Generates k value
        hash = hashlib.sha256()
        hash.update(bytes(str(x), 'utf-8'))
        k = hash.digest()

        # Getting the information to cypher
        iv = b64decode(iv)
        mbytes = b64decode(mbytes)
        # Decifro en CBC2
        decrypt = AES.new(k, AES.MODE_CBC, iv)
        ct = unpad(decrypt.decrypt(mbytes), AES.block_size).decode('utf-8')
        # Lo escribo
        with open('decrypt.txt', 'w') as f:
            f.write(ct)

rsa = RSA()

while True:
    print('--------------------------------------')
    print('1. Generar llaves')
    print('2. Encriptar mensaje')
    print('3. Decifrar mensaje')
    print('4. Salir')
    print('--------------------------------------')
    option = input('Seleccione la opcion: ')

    if (option == '1'):
        generator = Keys()
        generator.generateKeys()
        generator.save('keys')
    elif (option == '2'):
        path = input('Ingrese el nombre del archivo txt: ')
        rsa.encrypt(path)
    elif (option == '3'):
        path = input('Ingrese el nombre del archivo txt: ')
        rsa.decrypt(path)  
    else:
        break
