import os
import sys
import psutil
import argparse
from multiprocessing import Pool



def main():
    if os.getuid() != 0:
        quit("Данная программа требует права администратора.")
    parser = argparse.ArgumentParser()
    
if __name__ == "__main__":
    main()