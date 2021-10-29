from generator import Keys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import json
class RSA(object):
  def encrypt(self, path):
      # Cargo el path del mensaje
      with open(path, 'r') as f:
          message = f.read()
      # Cargo llave publica
      f = open('keys.json',)
      publicKey = json.load(f)['public'].encode('ascii')[:16]
      # Obtengo el mensaje en ascii
      message = message.encode('ascii')
      # Encripto en CBC
      cipher = AES.new(publicKey, AES.MODE_CBC)
      cipherbytes = cipher.encrypt(pad(message, AES.block_size))
      iv = base64.b64encode(cipher.iv).decode("utf-8")
      result = base64.b64encode(cipherbytes).decode("utf-8")
      # Lo escribo
      with open(path, 'w') as f:
          f.write(iv)
          f.write("\n")
          f.write(result)
      # Retorno iv, texto cifrado
      return iv, result

  def decrypt(self, path):
      # Cargo iv y resultado del cifrado
      with open(path, 'r') as f:
        lines = f.readlines()
      iv = lines[0]
      result = lines[1]

      # Cargo llave publica
      f = open('keys.json',)
      publicKey = json.load(f)['public'].encode('ascii')[:16]

      iv = base64.b64decode(iv)
      result = base64.b64decode(result)
      # Decifro en CBC
      decrypt = AES.new(publicKey, AES.MODE_CBC, iv)
      # Resultado
      final = unpad(decrypt.decrypt(result), AES.block_size).decode("utf-8")
      # Lo escribo
      with open(path, 'w') as f:
          f.write(final)



rsa = RSA()

while True:
  print('--------------------------------------')
  print('1. Generar llaves')
  print('2. Encriptar mensaje')
  print('3. Decifrar mensaje')
  print('4. Salir')
  print('--------------------------------------')
  option = int(input('Seleccione la opcion: '))

  if (option == 1):
    generator = Keys()
    generator.generateKeys()
    generator.save('keys')
  elif (option == 2):
    rsa.encrypt('text.txt')
  elif (option == 3):
    rsa.decrypt('text.txt')  
  else:
    break