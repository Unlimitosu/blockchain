import chain
import platform

def main():
    block = chain.BlockChain(5)
    block.print_chain()

if __name__=="__main__":
    main()
