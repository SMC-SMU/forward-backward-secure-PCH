from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT,pair
from ac17 import AC17CPABE
from charm.toolbox.ABEnc import ABEnc
import string
import hashlib
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import inverse
#from Cryptodome.Util import Padding
import binascii
from math import gcd



def Setup(N):
    pairing_group = PairingGroup('MNT224')

    # AC17 CP-ABE under DLIN (2-linear)
    cpabe = AC17CPABE(pairing_group, 2)

    # run the set up
    (pk, msk) = cpabe.setup()
    
    g = pk['g']
    h = pk['h']

    attr_list = []
    i = 0
    while i < N:
        attr_list.append(str(i))
        i += 1

    return cpabe,pk,msk, pairing_group, attr_list


def KeyGen(cpabe, pk, msk, attr_list):
    key = cpabe.keygen(pk, msk, attr_list)
    return key

def keyUp0(cpabe, pk, msk, key):
    return cpabe.keyUp0(pk, msk, key)
    

def keyUp1(cpabe, pk, key):
    cpabe.keyUp1(pk, key)


def DK(cpabe, pk, key, sk_tx):
    cpabe.DK(pk, key, sk_tx)



def Hash(cpabe,pk, h_msg, policy_str):
    h=pk['h']
    g = pk['g']
    group = cpabe.get_group_obj()
    
    r = cpabe.group.random(ZR)
    R = cpabe.group.random(ZR)
    g_ch = g ** R
    b_ch = g ** r * g_ch ** h_msg
    
    x = cpabe.group.random(ZR)
    sha224 = hashlib.new('sha224')
    sha224.update(str(x).encode())
    k = sha224.hexdigest()
    sha256 = hashlib.new('sha256')
    sha256.update(str(x).encode())
    com = sha256.hexdigest()
      
    Gkprime = group.hash(str(R), ZR)    # k' = R
    ctxtPrime = Gkprime + R + x
    
    ct_msg = R 
    ctxt = cpabe.encrypt(pk, ct_msg, policy_str)
    
    temp_m = str(ctxt) + str(ctxtPrime) + str(k)
    sha256 = hashlib.new('sha256')
    sha256.update(temp_m.encode())
    tag = sha256.hexdigest()
    
    # generate ZK proof
    # g||zkR||g^rPrime
    zkR = g ** r
    rPrime = cpabe.group.random(ZR)
    RPrime = g**rPrime
    tmp = g * zkR * RPrime
    sha256 = hashlib.new('sha256')
    sha256.update(group.serialize(tmp))   
    hd = sha256.hexdigest() 
    seed = str(hd)
    c = group.hash(seed, ZR)
    
    rHat = rPrime - r*c
    

    return ctxt, ctxtPrime, com, tag, {'g_ch':g_ch, 'b_ch':b_ch, 'h_msg':h_msg, 'r':r}, {'g':g, 'R':zkR, 'rHat':rHat, 'c':c}


def Verify(cpabe, pk, ch, zk):
    g = pk['g']
    group = cpabe.get_group_obj()
    
    # verify chameleon hash
    b_prime = g ** ch['r'] * ch['g_ch'] ** ch['h_msg']
    
    # verify zk
    t1 = zk['R']**zk['c']
    t2 = zk['g']**zk['rHat']
    t3 = zk['g']*zk['R']*t1*t2
    
    sha256 = hashlib.new('sha256')
    sha256.update(group.serialize(t3))   
    hd = sha256.hexdigest() 
    seed = str(hd)
    c_prime = group.hash(seed, ZR)
    

    if (ch['b_ch'] == b_prime and zk['c'] == c_prime):
        return 0
    else:
        return 1



def Adapt(cpabe,pk, sk_tx, ctxt, ctxtPrime, com, tag, key, ch, zk):
    g = pk['g']
    h = pk['h']
    group = cpabe.get_group_obj()
    
    # FBABE to get the trapdoor
    td = cpabe.decrypt(pk, ctxt, key, sk_tx)
    
    # check mac
    Gkprime = group.hash(str(td), ZR)    # k' = td
    x = ctxtPrime - Gkprime - td
    sha224 = hashlib.new('sha224')
    sha224.update(str(x).encode())
    k = sha224.hexdigest()
    sha256 = hashlib.new('sha256')
    sha256.update(str(x).encode())
    comPrime = sha256.hexdigest()
    temp_m = str(ctxt) + str(ctxtPrime) + str(k)
    sha256 = hashlib.new('sha256')
    sha256.update(temp_m.encode())
    tagPrime = sha256.hexdigest()
    
    if (comPrime != com and tagPrime != tag):
        return 1   # abort
    
    # find collision
    h_msg_prime = 987654321
    r_prime = ch['r'] + (ch['h_msg'] - h_msg_prime) * td
    ch['r'] = r_prime
    ch['h_msg'] = h_msg_prime
    
    # generate ZK proof
    # g||zkR||g^rPrime
    zkR = g ** r_prime
    rPrime = cpabe.group.random(ZR)
    RPrime = g**rPrime
    tmp = g * zkR * RPrime
    sha256 = hashlib.new('sha256')
    sha256.update(group.serialize(tmp))   
    hd = sha256.hexdigest() 
    seed = str(hd)
    c = group.hash(seed, ZR)
    
    rHat = rPrime - r_prime*c


def main():
    
    d = 10
    trial = 100
    Test_Setup = False
    Test_KeyGen = False
    Test_Hash = False
    Test_Adapt = False
    Test_Verify = False
    Test_KeyUp0 = False
    Test_KeyUp1 = False
    id = 1010
    ct_msg = 123456789
    h_msg = 987654321

    # instantiate a bilinear pairing map
    #pairing_group = PairingGroup('MNT224')
    
    # AC17 CP-ABE under DLIN (2-linear)
    #pchba = PCHBA(pairing_group, 2, 10)	# k = 10 (depth of the tree)

    # run the set up
    
    (cpabe,pk,msk,pairing_group, attr_list) =Setup(d)

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
            (cpabe,pk,msk,pairing_group, attr_list) =Setup(d)
            end = time.time()
            Temp=end - start
            T+=Temp
        T=T/trial
        f.write(str(T) + ")\n")
        f.close()

    # generate a key
    #attr_list = ['ONE', 'TWO', 'THREE']
    #sk_delta = pchba.keygen(sk, pk, msk, mpk, attr_list)
    key = KeyGen(cpabe, pk, msk,attr_list)

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
                key = KeyGen(cpabe, pk, msk,attr_list)
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

    ctxt, ctxtPrime, com, tag, ch, zk = Hash(cpabe,pk, h_msg, policy_str)
    
    if Test_KeyUp0:
        print ('Testing KeyUp0 ...')
        d=10      # number of attributes
        NN = 10
        
        f = open('result_keyup0.txt', 'w+')
        while d <= NN:
            print (d)
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            for i in range(trial):
                start = time.time()
                sk_tx = keyUp0(cpabe, pk, msk, key)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()
        
    sk_tx = keyUp0(cpabe, pk, msk, key)
    
    if Test_KeyUp1:
        print ('Testing KeyUp1 ...')
        d=10      # number of attributes
        NN = 10
        
        f = open('result_keyup1.txt', 'w+')
        while d <= NN:
            print (d)
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            for i in range(trial):
                key_test = key
                start = time.time()
                keyUp1(cpabe, pk, key_test)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()
        
    keyUp1(cpabe, pk, key)
    DK(cpabe, pk, key, sk_tx)

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
            key = KeyGen(cpabe, pk, msk,attr_list)
            policy_str=""
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
                else:
                    policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"
            
            for i in range(trial):
                m = None
                start = time.time()
                ctxt, ctxtPrime, com, tag, ch, zk = Hash(cpabe,pk, h_msg, policy_str)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()
        sk_tx = keyUp0(cpabe, pk, msk, key)
        keyUp1(cpabe, pk, key)
        DK(cpabe, pk, key, sk_tx)

    if (Verify(cpabe, pk, ch, zk) == 0):
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
            key = KeyGen(cpabe, pk, msk,attr_list)
            policy_str=""
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
                else:
                    policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"
            
            ctxt, ctxtPrime, com, tag, ch, zk = Hash(cpabe,pk, h_msg, policy_str)
            
            for i in range(trial):
                m_prime = None 
                ID_i = None
                start = time.time()
                Verify(cpabe, pk, ch, zk)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()
        sk_tx = keyUp0(cpabe, pk, msk, key)
        keyUp1(cpabe, pk, key)
        DK(cpabe, pk, key, sk_tx)

    
    Adapt(cpabe, pk, sk_tx, ctxt, ctxtPrime, com, tag, key, ch, zk)
    
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
            key = KeyGen(cpabe, pk, msk,attr_list)
            policy_str=""
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
                else:
                    policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"
            
            ctxt, ctxtPrime, com, tag, ch, zk = Hash(cpabe,pk, h_msg, policy_str)
            
            sk_tx = keyUp0(cpabe, pk, msk, key)
            keyUp1(cpabe, pk, key)
            DK(cpabe, pk, key, sk_tx)
            
            for i in range(trial):
                m_prime = None 
                ID_i = None
                start = time.time()
                Adapt(cpabe, pk, sk_tx, ctxt, ctxtPrime, com, tag, key, ch, zk)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()
    
    if (Verify(cpabe, pk, ch, zk) == 0):
        print ("Adapt: Successful verification.")
    else:
        print ("Adapt: Verification failed.")
    
    
    '''
    NN = 100
    d=10
    trial=100
    id = 1010
    ct_msg = 1034342
    h_msg = 123456789

    #Setup benchmark
    (cpabe,pk,msk,pairing_group, attr_list) =Setup(d)
    key = KeyGen(cpabe, pk, msk,attr_list)
    

    policy_str=""
    for j in range(d):
        if j!=d-1:
            policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
        else:
            policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"

    ctxt, ctxtPrime, com, tag, ch, zk = Hash(cpabe,pk, h_msg, policy_str)
    
    sk_tx = keyUp0(cpabe, pk, msk, key)
    keyUp1(cpabe, pk, key)
    DK(cpabe, pk, key, sk_tx)
    print (Verify(cpabe, pk, ch, zk))
    Adapt(cpabe, pk, sk_tx, ctxt, ctxtPrime, com, tag, key, ch, zk)
    print (Verify(cpabe, pk, ch, zk))
    '''


if __name__ == "__main__":
    #debug = False
    debug = True
    main()
