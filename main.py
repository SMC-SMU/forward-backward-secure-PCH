from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT,pair
from ac17 import AC17CPABE
from charm.toolbox.ABEnc import ABEnc
import string
from hashlib import sha512
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import inverse
#from Cryptodome.Util import Padding
import binascii
from math import gcd


# keys
sig_params = {}
group = None


def Setup(N):
    pairing_group = PairingGroup('MNT224')

    # AC17 CP-ABE under DLIN (2-linear)
    cpabe = AC17CPABE(pairing_group, 2)

    # run the set up
    (pk, msk) = cpabe.setup()
    
    g = pk['g']
    h = pk['h']
    alpha = cpabe.group.random(ZR)
    beta = cpabe.group.random(ZR)
    g_beta = g ** beta
    h_1_alpha = h ** (1/alpha)
    h_beta_alpha = h ** (beta/alpha)
    beta_alpha = beta / alpha
    sig_params = {'g_beta':g_beta, 'h_1_alpha':h_1_alpha, 'h_beta_alpha':h_beta_alpha, 'beta_alpha':beta_alpha}

    attr_list = []
    i = 0
    while i < N:
        attr_list.append(str(i))
        i += 1

    return cpabe,pk,msk, pairing_group, attr_list, sig_params


def KeyGen(cpabe, pk, msk, attr_list):
    key = cpabe.keygen(pk, msk, attr_list)
    rsaKey = RSA.generate(2048)
    
    return key, rsaKey

def Hash(cpabe,pk,ct_msg, h_msg, policy_str,key, rsaKey, sig_params):
    h=pk['h']
    g = pk['g']
    group = cpabe.get_group_obj()

    # Generate ephemeral trapdoor
    etd_rsaKey = RSA.generate(2048)    
    while (gcd(rsaKey.n, etd_rsaKey.n) != 1):
        etd_rsaKey = RSA.generate(2048)
        
    r = get_random_bytes(128)
    
    nnPrime = rsaKey.n * etd_rsaKey.n
    
    # RSA CH
    x = int.from_bytes(sha512(h_msg).digest(), byteorder='big')   
    r = int.from_bytes(r, byteorder="big")
    ct = pow(r, rsaKey.e, nnPrime)  # r^e
    h_rsa = x * ct % nnPrime  
    
    # AES encryption    
    aesKey = b'1234567890123456' 
    iv = get_random_bytes(16)
    phiNPrime = (etd_rsaKey.p-1) * (etd_rsaKey.q-1)
    data = phiNPrime.to_bytes(1024, 'big')
    cipher = AES.new(aesKey, AES.MODE_CBC, iv)
    aes_data= cipher.encrypt(data)
    
    # ABE encryption
    key = int.from_bytes(aesKey, byteorder='big')    
    ctxt = cpabe.encrypt(pk, key, policy_str)

    return ctxt, h_rsa, r, etd_rsaKey, aes_data, iv


def Verify(rsaKey, etd_rsaKey, h_msg, r, h_rsa):
    nnPrime = rsaKey.n * etd_rsaKey.n
    x = int.from_bytes(sha512(h_msg).digest(), byteorder='big')   
    hPrime = x * pow(r, rsaKey.e, nnPrime)
    hPrime = hPrime  % nnPrime 

    if (h_rsa == hPrime):
        return 0
    else:
        return 1


def Adapt(cpabe,pk, ctxt, aes_data, iv, h_msgPrime, key, rsaKey, etd_rsaKey, h_rsa):
    g = pk['g']
    h = pk['h']
    group = cpabe.get_group_obj()
    
    # ABE decryption to get AES key
    data = cpabe.decrypt(pk, ctxt, key)
    aesKey = int(data).to_bytes(16, 'big')
    
    # AES decryption to get phiNPrime, ephemeral trapdoor
    cipher = AES.new(aesKey, AES.MODE_CBC, iv)
    data = cipher.decrypt(aes_data)
    phiNPrime = int.from_bytes(data, byteorder='big')
    
    # RSA Adapt
    nnPrime = rsaKey.n * etd_rsaKey.n
    phiN = (rsaKey.p-1) * (rsaKey.q-1) * phiNPrime 
    d = inverse(rsaKey.e, phiN)
    
    _x = int.from_bytes(sha512(h_msgPrime).digest(), byteorder='big') % nnPrime
    _r = pow(h_rsa * inverse(_x, nnPrime) % nnPrime, d, nnPrime)

    return _r



def main():
    d = 10
    trial = 100
    Test_Setup = False
    Test_KeyGen = False
    Test_Hash = False
    Test_Adapt = False
    Test_Verify = True

    id = 1010
    ct_msg = 1034342
    h_msg = b"0123456789"
    h_msgPrime = b"abcdefg"

    # instantiate a bilinear pairing map
    #pairing_group = PairingGroup('MNT224')
    
    # AC17 CP-ABE under DLIN (2-linear)
    #pchba = PCHBA(pairing_group, 2, 10)	# k = 10 (depth of the tree)

    # run the set up
    (cpabe,pk,msk, pairing_group, attr_list, sig_params) =Setup(d)

    
    if Test_Setup:
        print ('Testing Setup ...')
        k = 10
        f = open('result_setup.txt', 'w+')
        f.write("("+str(k)+",")
        T=0
        Temp=0
        start = 0
        end = 0
        for i in range(trial):
            start = time.time()
            (cpabe,pk,msk, pairing_group, attr_list, sig_params) =Setup(d)
            end = time.time()
            Temp=end - start
            T+=Temp
        T=T/trial
        f.write(str(T) + ")\n")
        f.close()

    # generate a key
    key, rsaKey = KeyGen(cpabe, pk, msk,attr_list)

    if Test_KeyGen:
        print ('Testing KeyGen ...')
        d=10      # number of attributes
        NN = 100
        
        f = open('result_keygen.txt', 'w+')
        while d <= NN:
            print (d)
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            for i in range(d):
                attr_list.append(str(i))
            for i in range(trial):
                start = time.time()
                key, rsaKey = KeyGen(cpabe, pk, msk,attr_list)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()

   
    # generate a ciphertext
    policy_str=""
    for j in range(d):
        if j!=d-1:
            policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
        else:
            policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"

    ctxt, h_rsa, r, etd_rsaKey, aes_data, iv = Hash(cpabe,pk,ct_msg, h_msg, policy_str, key, rsaKey, sig_params)

    if Test_Hash:
        print ('Testing Hash ...')
        d=10      # number of attributes
        NN = 100
        f = open('result_hash.txt', 'w+')
        while d <= NN:
            print (d)
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            for i in range(2*d+1):
                attr_list.append(str(i))
            key, rsaKey = KeyGen(cpabe, pk, msk,attr_list)
            policy_str=""
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
                else:
                    policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"
            
            for i in range(trial):
                m = None
                start = time.time()
                ctxt, h_rsa, r, etd_rsaKey, aes_data, iv = Hash(cpabe,pk,ct_msg, h_msg, policy_str, key, rsaKey, sig_params)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()

    if (Verify(rsaKey, etd_rsaKey, h_msg, r, h_rsa) == 0):
        print ("Hash: Successful verification.")
    else:
        print ("Hash: Verification failed.")

    if Test_Verify:
        print ('Testing Verify ...')
        d=10      # number of attributes
        NN = 100
        f = open('result_verify.txt', 'w+')
        while d <= NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            for i in range(2*d+1):
                attr_list.append(str(i))
            key, rsaKey = KeyGen(cpabe, pk, msk,attr_list)
            policy_str=""
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
                else:
                    policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"
            
            ctxt, h_rsa, r, etd_rsaKey, aes_data, iv = Hash(cpabe,pk,ct_msg, h_msg, policy_str, key, rsaKey, sig_params)
            
            for i in range(trial):
                m_prime = None 
                ID_i = None
                start = time.time()
                Verify(rsaKey, etd_rsaKey, h_msg, r, h_rsa)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()

    _r = Adapt(cpabe, pk, ctxt, aes_data, iv, h_msgPrime, key, rsaKey, etd_rsaKey, h_rsa)

    if Test_Adapt:
        print ('Testing Adapt ...')
        d=10      # number of attributes
        NN = 100
        f = open('result_adapt.txt', 'w+')
        while d <= NN:
            print (d)
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            for i in range(2*d+1):
                attr_list.append(str(i))
            key, rsaKey = KeyGen(cpabe, pk, msk,attr_list)
            policy_str=""
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
                else:
                    policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"
            
            ctxt, h_rsa, r, etd_rsaKey, aes_data, iv = Hash(cpabe,pk,ct_msg, h_msg, policy_str, key, rsaKey, sig_params)
            
            for i in range(trial):
                m_prime = None 
                ID_i = None
                start = time.time()
                _r = Adapt(cpabe, pk, ctxt, aes_data, iv, h_msgPrime, key, rsaKey, etd_rsaKey, h_rsa)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()
    
    if (Verify(rsaKey, etd_rsaKey, h_msgPrime, _r, h_rsa) == 0):
        print ("Adapt: Successful verification.")
    else:
        print ("Adapt: Verification failed.")

    
    '''
    NN = 100
    d=10
    trial=100
    id = 1010
    ct_msg = 1034342
    h_msg = b"0123456789"

    #Setup benchmark
    (cpabe,pk,msk, pairing_group, attr_list, sig_params) =Setup(d)
    key, rsaKey = KeyGen(cpabe, pk, msk,attr_list)

    policy_str=""
    for j in range(d):
        if j!=d-1:
            policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
        else:
            policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"

    ctxt, h_rsa, r, etd_rsaKey, aes_data, iv = Hash(cpabe,pk,ct_msg, h_msg, policy_str, key, rsaKey, sig_params)
    print (Verify(rsaKey, etd_rsaKey, h_msg, r, h_rsa))
    h_msgPrime = b"abcdefg"
    _r = Adapt(cpabe, pk, ctxt, aes_data, iv, h_msgPrime, key, rsaKey, etd_rsaKey, h_rsa)
    print (Verify(rsaKey, etd_rsaKey, h_msgPrime, _r, h_rsa))
    ''' 



if __name__ == "__main__":
    #debug = False
    debug = True
    main()
