from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from msp import MSP
import hashlib

debug = False
#debug=True

Tlen = 210


class AC17CPABE(ABEnc):
    def __init__(self, group_obj, assump_size, verbose=False):
        ABEnc.__init__(self)
        self.group = group_obj
        self.assump_size = assump_size  # size of linear assumption, at least 2
        self.util = MSP(self.group, verbose)
        self.id = b"12345"

    def get_group_obj(self):
        return self.group

    def setup(self):
        """
        Generates public key and master secret key.
        """

        if debug:
            print('\nSetup algorithm:\n')

        # generate two instances of the k-linear assumption
        A = []
        B = []



        for i in range(self.assump_size):
            A.append(self.group.random(ZR))
            B.append(self.group.random(ZR))  # note that A, B are vectors here

        # vector
        k = []
        for i in range(self.assump_size + 1):
            k.append(self.group.random(ZR))

        # pick a random element from the two source groups and pair them
        g = self.group.random(G1)
        h = self.group.random(G2)
        e_gh = pair(g, h)

        # now compute various parts of the public parameters

        # compute the [A]_2 term
        h_A = []                 #H_1, H_2--------------------------------------
        for i in range(self.assump_size):
            h_A.append(h ** A[i])
        h_A.append(h)

        # compute the e([k]_1, [A]_2) term
        g_k = []      # g^{{d_1}; g^{d_2}; g^{d_3}   -------------------------------
        for i in range(self.assump_size + 1):
            g_k.append(g ** k[i])

        e_gh_kA = []    # T_1, T_2 --------------------------------------
        for i in range(self.assump_size):
            e_gh_kA.append(e_gh ** ((k[i] * A[i] + k[self.assump_size])))
            
        # compute F(t) and F(t,id)
        g_i = []    # ten elements
        t_i = []    # four elements

        for i in range(4):
            t_i.append(self.group.random(ZR))
            
        for i in range(10):
            g_i.append(self.group.random(G1))
        
        g_0 = self.group.random(G1)
        
        Ft = g_0
        for i in range(4):
            Ft = Ft * (g_i[i] ** t_i[i])
        
        sha256 = hashlib.new('sha256')
        sha256.update(self.id)
        hd = sha256.hexdigest() 
        seed = str(hd)
        h_id = self.group.hash(seed, ZR) 
        Ft_id = g_0
        for i in range(4):
            Ft_id = Ft_id * (g_i[i]**t_i[i])	    
        Ft_id = Ft_id * (g_i[9]**h_id)   
        
        FtPrime = g_0
        t_i.append(self.group.random(ZR))   # add one element to t_i, t_i has 5 elements now
        for i in range(5):
            FtPrime = FtPrime * (g_i[i] ** t_i[i])  
     
        # the public key
        pk = {'g': g, 'h': h,'h_A': h_A, 'e_gh_kA': e_gh_kA, 'g_i': g_i, 't_i':t_i, 'Ft':Ft, 'Ft_id':Ft_id, 'FtPrime':FtPrime}

        # the master secret key
        msk = { 'g_k': g_k, 'A': A, 'B': B}

        return pk, msk

    def keygen(self, pk, msk, attr_list):
        """
        Generate a key for a list of attributes.
        """

        if debug:
            print('\nKey generation algorithm:\n')

        # pick randomness
        r = []
        sum = 0
        for i in range(self.assump_size):
            rand = self.group.random(ZR)
            r.append(rand)
            sum += rand


        # first compute just Br as it will be used later too
        Br = []
        for i in range(self.assump_size):
            Br.append(msk['B'][i] * r[i])
        Br.append(sum)

        # now compute [Br]_2
        K_0 = []
        for i in range(self.assump_size + 1):
            K_0.append(pk['h'] ** Br[i])
            

        # compute [W_1 Br]_1, ...
        K = {}
        A = msk['A']
        g = pk['g']

        for attr in attr_list:
            key = []
            sigma_attr = self.group.random(ZR)
            for t in range(self.assump_size):
                prod = 1
                a_t = A[t]
                for l in range(self.assump_size + 1):
                    input_for_hash = attr + str(l) + str(t)
                    prod *= (self.group.hash(input_for_hash, G1) ** (Br[l]/a_t))
                prod *= (g ** (sigma_attr/a_t))          
                key.append(prod)
            key.append(g ** (-sigma_attr))
            K[attr] = key

        # compute [k + VBr]_1
        Kp = []
        Rk = []
        g_k = msk['g_k']
        sigma = self.group.random(ZR)
        g_x = self.group.random(G1)
        Rk.append(g_x)

        # compute sk1, sk2
        for t in range(self.assump_size):
            prod = g_k[t]
            a_t = A[t]
            for l in range(self.assump_size + 1):
                input_for_hash = '01' + str(l) + str(t)
                prod *= (self.group.hash(input_for_hash, G1) ** (Br[l] / a_t))
            prod *= (g ** (sigma / a_t))       
            Kp.append(prod)
        # compute sk3, for revocation and forward-security
        Kp.append(g_k[self.assump_size] / g_x * (g ** (-sigma)) * (pk['Ft']**sum))
        # compute sk4, for one-way key update to ensure forward-security
        Kp.append(pk['g_i'][4]**sum)   
        key = {'attr_list': attr_list, 'K_0': K_0, 'K': K, 'Kp': Kp, 'Rk':Rk}
        
        return key
        
     
    def keyUp0(self, pk, msk, key):   
        # KGC decides revocation and broadcasts sk_tx
        sk_tx = []
        Rk = key['Rk']
        rx = self.group.random(ZR)
        sk_tx.append(Rk[0]*pk['FtPrime']**rx)
        sk_tx.append(pk['h']**rx)
        sk_tx.append(pk['g_i'][4]**rx)
   
        return sk_tx
        
    def keyUp1(self, pk, key):
        # Key holder performs key update locally
        h = pk['h']
        rPrime = self.group.random(ZR)
        temp = key['K_0'][2] * (h ** rPrime)
        key['K_0'].append(temp)
        FtPrime = pk['FtPrime'] ** rPrime
        t_i_1 = pk['t_i'][4]
        g_i_1 = key['Kp'][3] ** t_i_1               
        key['Kp'][2] = key['Kp'][2] * g_i_1 * FtPrime

        
    def DK(self, pk, key, sk_tx):
        # Key holder generates a decryption key after keyUp0. 
        #keyUp1 is optional for achieving forward-security.
        key['Kp'][2] = key['Kp'][2] * sk_tx[0]
        

    def encrypt(self, pk, msg, policy_str):
        """
        Encrypt a message msg under a policy string.
        """
        if debug:
            print('\nEncryption algorithm:\n')

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # pick randomness
        s = []
        sum = 0
        for i in range(self.assump_size):
            rand = self.group.random(ZR)
            s.append(rand)
            sum += rand

        # compute the [As]_2 term
        C_0 = []
        h_A = pk['h_A']
        for i in range(self.assump_size):
            C_0.append(h_A[i] ** s[i])
        C_0.append(h_A[self.assump_size] ** sum)
        C_0.append(pk['FtPrime']**sum)  # addtional element for forward-security


        # pre-compute hashes
        hash_table = []
        for j in range(num_cols):
            x = []
            input_for_hash1 = '0' + str(j + 1)
            for l in range(self.assump_size + 1):
                y = []
                input_for_hash2 = input_for_hash1 + str(l)
                for t in range(self.assump_size):
                    input_for_hash3 = input_for_hash2 + str(t)
                    hashed_value = self.group.hash(input_for_hash3, G1)
                    y.append(hashed_value)
                x.append(y)
            hash_table.append(x)

        C = {}
        for attr, row in list(mono_span_prog.items()):
            ct = []
            attr_stripped = self.util.strip_index(attr)  # no need, re-use not allowed
            for l in range(self.assump_size + 1):
                prod = 1
                cols = len(row)
                for t in range(self.assump_size):
                    input_for_hash = attr_stripped + str(l) + str(t)
                    prod1 = self.group.hash(input_for_hash, G1)
                    for j in range(cols):
                        prod1 *= (hash_table[j][l][t] ** row[j])
                    prod *= (prod1 ** s[t])
                ct.append(prod)
            C[attr] = ct

        Cp = 1
        for i in range(self.assump_size):
            Cp = Cp * (pk['e_gh_kA'][i] ** s[i])

        seed= str(Cp)
        seed = seed[:Tlen]

        #generate two sub-keys
        K1=self.group.hash(seed+str(00),ZR)

        Cpp = []
        Cpp.append(K1*msg)

        return {'policy': policy, 'C_0': C_0, 'C': C, 'Cp': Cpp}
        

    def decrypt(self, pk, ctxt, key, sk_tx):
        """
        Decrypt ciphertext ctxt with key key.
        """

        if debug:
            print('\nDecryption algorithm:\n')

        nodes = self.util.prune(ctxt['policy'], key['attr_list'])
        if not nodes:
            print ("Policy not satisfied.")
            return None

        prod1_GT = 1
        prod2_GT = 1

        for i in range(self.assump_size + 1):
            #print("i=",i)
            prod_H = 1
            prod_G = 1
            for node in nodes:
                attr = node.getAttributeAndIndex()
                attr_stripped = self.util.strip_index(attr)  # no need, re-use not allowed
                prod_H *= key['K'][attr_stripped][i]
                prod_G *= ctxt['C'][attr][i]
            prod1_GT *= pair(key['Kp'][i] * prod_H, ctxt['C_0'][i])
            prod2_GT *= pair(prod_G, key['K_0'][i])
        
        # add one more pairing to decrypt a ciphertext
        prod2_GT = prod2_GT * pair(ctxt['C_0'][3], sk_tx[1]*key['K_0'][3])
       

        Cpp = ctxt['Cp']
        K = prod2_GT/prod1_GT
        K = -K
        seed = str(K)
        seed = seed[:Tlen]


        K1 = self.group.hash(seed + str(00), ZR)
        
        M = (Cpp[0]/K1)


        return M
