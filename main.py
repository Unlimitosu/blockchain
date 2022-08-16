import chain
import platform

def main():
    block = chain.BlockChain(5)
    block.print_chain()
    if block.vaild_transaction():
        print("ok")
    
if __name__=="__main__":
    main()
# EOF
