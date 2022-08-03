import chain

def main():
    block = chain.BlockChain
    block.new_block()
    block.new_block()
    block.print_chain

if __name__=="__main__":
    main()