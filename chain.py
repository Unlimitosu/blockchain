'''
    암호분석 경진대회 #2
'''

import hashlib
import random
import math
import ctypes
import multiprocessing as mp
from concurrent import futures
from re import L

class BlockChain():
    def __init__(self, numofblocks : int) -> None:
        #? Generate blocks as many as numofblocks except the genesis block
        self.numofblocks = numofblocks
        self.chain       = []
        self.transaction = []
        self.hashval     = []
        
        #? SHA3 constants
        self.__SHA3outlen   = ctypes.c_int(32)
        self.__SHA3inlen    = ctypes.c_int(200)
        self.__SHA3bitsize  = ctypes.c_int(256) # bitsize = 8 * outlen
        self.__SHA3useSHAKE = ctypes.c_int(0)
        
        self.__genesis_block()
        for _ in range(self.numofblocks):
            self.__new_block()

#: generate block/info functions
    def __genesis_block(self) -> None:
        #? Create a genesis block
        genesis = {
                'Transaction' : self.__new_transaction(),
                'BlockID' : len(self.chain), 
                'PreviousHashval' : 0x00
            }
        self.chain.append(genesis)

    def __new_block(self) -> None:
        #? Create new block and add to the chain
        # BlockID is 160bits
        if len(self.chain)>(1<<160):
            raise Exception("Chain length is larger than 2**160")
        # Hash value is last 160bits(=20bytes)
        new_block = {
                'Transaction' : self.__new_transaction(),
                'BlockID' : len(self.chain), 
                'PreviousHashval' : self.__ctype_hash_lastblock()
            }
        self.chain.append(new_block)

    def __new_transaction(self) -> dict:
        #? Create new transaction to the transaction list with 8 (TxID, TransactionValue) pairs
        new_trans = {}
        while len(new_trans.keys()) <= 8:
            key=self.__get_large_randint(160) ^ 0x14 # 20
            if key not in new_trans:
                new_trans[key] = self.__get_large_randint(864) ^ 0x6C # 108
        self.transaction.append(new_trans)
        return new_trans

#: hash functions
    def __hash_lastblock(self) -> str: #! temporary
        #? Returns a SHA3-256 hash value of the last block
        return hashlib.sha3_256(self.__lastblock_info().encode()).hexdigest()[:20]
    
    def __ctype_hash_lastblock(self) -> str:
        #? SHA-3 hashing using ctypes module
        val = bytes(list(self.__lastblock_info().encode()))
        ret = bytes([0] * 32)    
        
        libc = ctypes.CDLL('./sha3dll.dll') # import C code dll file
        #libc.sha3_hash.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int]
        #libc.sha3_hash.restype = ctypes.c_int
        libc.sha3_hash(ret, self.__SHA3outlen, val, 
                       self.__SHA3inlen, self.__SHA3bitsize, self.__SHA3useSHAKE)
        return self.__parse_bytes(ret)
    
    def __parse_bytes(self, bytesval) -> str:
        #? Transform bytes into hex string
        ret = ''
        idx = 0
        while idx < len(bytesval):
            tmp = str(hex(bytesval[idx]))[2:]
            ret += tmp
            if len(tmp) == 1: 
                ret = '0' + ret
            idx += 1
        if len(ret) != 64: # Return length of SHA3-256 is 256bit
            raise Exception('LengthError: return value is not 256bit')
        return ret
    
    def __SHA3_update_one(self, val : str) -> None:
        #? Do SHA3-256 Update for transaction data
        #? Update for BlockID and Hashval will be proceeded procedurally
        val = bytes(val)
        ret = bytes([0] * 32)    

        libc = ctypes.CDLL('./sha3dll.dll') # import C code dll file
        libc.sha3_init(self.__SHA3bitsize, self.__SHA3useSHAKE)
        libc.sha3_update(ret, self.__SHA3outlen)
        return self.__parse_bytes(ret)
        
    def __SHA3_update_parallel(self) -> None:
        #? SHA3 update using multiprocessing
        #todo SHA3 멀티프로세싱 구현
        pass

    def __SHA3_update_remain_and_finalize(self) -> None:
        #todo BlockID, hashval 순차적 해시 과정 구현
        libc = ctypes.CDLL('./sha3dll.dll') # import C code dll file
        for hashed, info in zip(self.hashval, self.__remain_info()):
            # fin_absorb = 
            pass

#: transform functions(temporary)
    def hex2list(self, hexval : str) -> list:
        #? Transform hex value into binary list
        #? ex) '12' -> [0, 0, 0, 1, 0, 0, 1, 0]
        ret = []
        for ch in hexval:
            if 48 <= ord(ch) <= 57:
                ch = ord(ch) - 48
            elif 97 <= ord(ch) <= 102:
                ch = ord(ch) - 87
            else:
                raise Exception("Unexpected Error during parsing.")  
            tmp = bin(ch)[2:]  # int -> binary
            while len(tmp) != 4:
                tmp = '0' + tmp
            ret += list(map(int, tmp))
        return ret
    
    def list2hex(self, val : list) -> str:
        #? Transform binary list into hex value string
        #? ex) [0, 0, 0, 1, 0, 0, 1, 0] -> '12'
        ret = ''
        idx = 0
        while idx < len(val):
            fourbits = val[idx:idx + 4]
            tmp = 0
            for bitidx in range(4):
                tmp += fourbits[3 - bitidx] * (2**bitidx)
            ret += str(hex(tmp))[-1]
            idx += 4
        return ret

#: get info/block functions
    def genesis_block(self) -> dict:
        #? Return Genesis Block of the chain
        return self.chain[0]

    def last_block(self) -> dict:
        #? Returns last block of the chain
        return self.chain[-1]
    
    def chain_len(self) -> int:
        #? Returns the length of current chain
        return len(self.chain)
    
    def __lastblock_info(self) -> str:
        #? Returns the concatenation of information of last block
        tmp = []
        tmp.append(self.last_block()['BlockID'])
        tmp.append(self.last_block()['PreviousHashval'])
        for tx in self.last_block()['Transaction']:
            tmp.append(tx)
            tmp.append(self.last_block()['Transaction'][tx])
        return ''.join(str(x) for x in tmp)
    
    def __transaction_info(self) -> list:
        #? Return a list of transaction info
        ret = []
        for block in self.chain:
            ret.append(block['Transaction'])
        return ret
    
    def __remain_info(self) -> list:
        #? Return a list of BlockID and hashval
        ret = []
        for block in self.chain:
            ret.append(block['BlockID'] + block['PreviousHashval'])
        return ret
    
#: verify functions
    def vaild_transaciton(self) -> bool:
        #? Validate the transaction
        pass

#: etc(incl. debug)
    def print_chain(self) -> None:
        #? Print chain info: BlockID, Previous Hash Value
        print('Current Chain:')
        for blocks in self.chain:
            print('BlockID:', blocks['BlockID'])
            print('PrevHashval:', blocks['PreviousHashval'],'\n')
    
    def __get_large_randint(self, digits) -> int:
        #? Return a large random integer with
        ret = ''
        for _ in range(digits // 16):
            ret = ret + str(math.floor(random.random() * (10 ** 16)))
        ret += str(math.floor(random.random() * (10 ** (digits % 16))))
        return int(ret)
# EOF
