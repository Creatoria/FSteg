import argparse
from util import *

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='hide by fft')
    parser.add_argument('-in', help='the source audio file', type=str)
    parser.add_argument('-out', help='the output audio file', type=str)
    parser.add_argument(
        '-pk', help='the private key in string or file', type=str)
    parser.add_argument('-key', help='key file specified', type=str)
    parser.add_argument('-m', '--message', help='the file to hide', type=str)
    args = parser.parse_args()
