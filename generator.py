from base64 import b64decode, b64encode
import Crypto.Util.number as CN
import Crypto.Random as random
import json

class Keys(object):

    def __get64Coded__(self, string):
        return b64encode(bytes(string, 'utf-8')).decode('utf-8')
    
    def __get64UnCoded__(self, string):
        return b64decode(bytes(string, 'utf-8')).decode('utf-8')

    def __randomPrime__(self, bits, minn, maxx):
        temp = 0
        while True:
            temp = CN.getPrime(bits, randfunc=random.get_random_bytes)
            if ((minn < temp) and (temp < maxx)): break
        return temp

    def generateKeys(self, minn=200, maxx=1000):
        bits = maxx.bit_length()    # Para indicar que es el maximo

        # Se generan los random
        p = self.__randomPrime__(bits, minn, maxx)
        q = self.__randomPrime__(bits, minn, maxx)
        
        N = p * q 

        PHI = (p - 1) * (q - 1)

        e = self.__randomPrime__(N.bit_length(), 1, (N-1))
        d = CN.inverse(e, PHI)
        
        # Saving the keys
        self.public = str(e) + '.' + str(N)
        self.private = str(d) + '.' + str(N)

    def save(self, file='out'):
        information = {
            'public': self.__get64Coded__(self.public), 
            'private': self.__get64Coded__(self.private),
        }
        with open(file + '.json', 'w') as outfile:
            json.dump(information, outfile, indent=2)
    
    def load(self, file='out'):
        with open(file + '.json', 'r') as outfile:
            data = json.load(outfile)
            public = self.__get64UnCoded__(data['public']) 
            private = self.__get64UnCoded__(data['private']) 
            return public, private 

def __generatorMain__():
    a = Keys()
    a.generateKeys()
    a.save('keys')

if __name__ == '__main__':
    __generatorMain__()
