'''
    암호분석 경진대회 #2
'''

from array import array
import hashlib
import random
import math
import ctypes
from concurrent import futures

class BlockChain():
    def __init__(self, numofblocks : int) -> None:
        #? Generate blocks as many as numofblocks except the genesis block
        self.chain = []
        self.transaction = []
        self.__genesis_block()
        for _ in range(numofblocks):
            self.__new_block()
        
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
                'PreviousHashval' : self.ctype_hash()
            }
        self.chain.append(new_block)

    def __new_transaction(self) -> dict:
        #? Create new transaction to the transaction list with 10 (TxID, TransactionValue) pairs
        new_trans = {}
        while len(new_trans.keys()) <= 10:
            key=self.__get_large_randint(160) ^ 0x14
            if key not in new_trans:
                new_trans[key] = self.__get_large_randint(864) ^ 0x6C
        self.transaction.append(new_trans)
        return new_trans
    
    def __lastblock_info(self) -> str:
        #? Returns the concatenation of information of last block
        tmp = []
        tmp.append(self.last_block()['BlockID'])
        tmp.append(self.last_block()['PreviousHashval'])
        for tx in self.last_block()['Transaction']:
            tmp.append(tx)
            tmp.append(self.last_block()['Transaction'][tx])
        return ''.join(str(x) for x in tmp)

    def __hash_lastblock(self) -> str:
        #? Returns a SHA3-256 hash value of the last block
        return hashlib.sha3_256(self.__lastblock_info().encode()).hexdigest()[:20]
    
    def ctype_hash(self):
        val = bytes(list(self.__lastblock_info().encode()))
        ret = bytes([1] * 512)
        
        outlen = ctypes.c_int(32)
        inlen = ctypes.c_int(200)
        bitsize = useSHAKE = ctypes.c_int(0)
        
        libc = ctypes.CDLL('./sha3dll.dll')
        #libc.sha3_hash.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int]
        #libc.sha3_hash.restype = ctypes.c_int
        libc.sha3_hash(ret, outlen, val, inlen, bitsize, useSHAKE)
        return ret

    def hex2list(self, hexval : str) -> list[int]:
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
    
    def list2hex(self, val : list[int]) -> str:
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
            
    def genesis_block(self) -> dict:
        #? Return Genesis Block of the chain
        return self.chain[0]

    def last_block(self) -> dict:
        #? Returns last block of the chain
        return self.chain[-1]
    
    def vaild_transaciton(self) -> bool:
        #? Validate the transaction
        pass

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
