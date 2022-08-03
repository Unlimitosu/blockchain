'''
    암호분석 경진대회 #2
'''

import hashlib
import random
import math

class BlockChain():
    def __init__(self) -> None:
        self.chain = []
        self.transaction = []
        self.new_block()   # Genesis block

    def new_block(self) -> None:
        #? Create new block and add to the chain

        # BlockID is 160bits
        if len(self.chain)>(1<<160):
            raise Exception("Chain length is larger than 2**160")

        if self.chain:  # Case of next blocks
            # Hash value is last 160bits(=20bytes)
            new_block = {
                'BlockID' : len(self.chain), 
                'PreviousHashval': hashlib.sha3_256(self.chain[-1]['PreviousHashval'].encode()).hexdigest()[:20],
                'Transaction': self.new_transaction()
            }

        else:   # Case of Genesis Block
            new_block = {
                'BlockID' : len(self.chain), 
                'PreviousHashval': 'Genesis Block', #! or 0x00?
                'Transaction': self.new_transaction()
            }
        self.chain.append(new_block)

    def new_transaction(self) -> dict:
        #? Create new transaction to the transaction list with 10 (TxID, TransactionValue) pairs
        '''
                Transaction Overview

        TxID#1  : Random Number
        TxID#2  : Random Number
                ...
        TxID#10 : Random Number
        '''
        new_trans = {}
        while len(new_trans.keys())<=10:
            key=self.get_large_randint(160) ^ 0x14
            if key not in new_trans:
                new_trans[key] = self.get_large_randint(864) ^ 0x6C
        self.transaction.append(new_trans)
        return new_trans

    def hash(block):
        #? Data hashing(SHA3-256)
        #todo SHA3-256 implementation & optimization
        pass

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
    
    def get_large_randint(self, digits) -> int:
        #? Return a large random integer with
        ret = ""
        for _ in range(digits // 16):
            ret = ret + str(math.floor(random.random() * 10000000000000000))
        ret = ret + str(math.floor(random.random() * (10 ** (digits % 16))))
        return int(ret)

# EOF