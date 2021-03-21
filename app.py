import argparse
from util import *

MODE = {'MODE_PLAIN': 0,
        'MODE_AES': 1}


def getenc(u):
    return MODE['MODE_' + u.upper()]


parser = argparse.ArgumentParser(description='hide messages by fft')

base_parser = argparse.ArgumentParser(add_help=False)
base_parser.add_argument(
    '-ths', help='minimum threshold', default=1600, type=int)
base_parser.add_argument(
    '-frame', help='points per frame', default=441, type=int)

subparsers = parser.add_subparsers(dest='func')
est = subparsers.add_parser(
    'estimate', description='estimate the capacity of the audiofile', parents=[base_parser])
emb = subparsers.add_parser(
    'embeed', description='embeed the message into the audiofile', parents=[base_parser])
ext = subparsers.add_parser(
    'extract', description='extract the message from the audiofile', parents=[base_parser])

est.add_argument('-if', help='the source file', type=str)
emb.add_argument('-if', help='the source file', type=str)
ext.add_argument('-if', help='the source file', type=str)

emb.add_argument('-of', help='the output file', type=str)
ext.add_argument('-of', help='the output file', type=str)

emb.add_argument('-enc', help='the encryption mode',
                 default='plain', type=str)
ext.add_argument('-enc', help='the decryption mode',
                 default='plain', type=str)

emb.add_argument('-key', help='the key used top encrypt', type=str)
ext.add_argument('-key', help='the key used top decrypt', type=str)

emb.add_argument(
    '--verify', help='check the integrity of the message', action='store_true')
ext.add_argument(
    '--verify', help='check the integrity of the message', action='store_true')

emb.add_argument(
    '-pk', help='the private key used to sign', type=str)
ext.add_argument(
    '-pk', help='the public key used to verify', type=str)


emb.add_argument('-m', '--message', help='the file to hide', type=str)


if __name__ == "__main__":
    try:
        args = parser.parse_args()
    except Exception:
        print('Unrecognized command or arguments. Exiting.')
        exit(0)
    vv = vars(args)
    # print(vv)
    if vv['func'] == 'estimate':
        size, srt, ll = estimate(vv['if'], vv['ths'], vv['frame'])
        print('{} Bytes available under {}Hz, {}kbps in average, under {} points per frame, threshold = {}'.format(
            size, srt, size * 8 / ll / srt, vv['frame'], vv['ths']))
    elif vv['func'] == 'embeed':
        cc = Cryp(mode=getenc(vv['enc']), password=vv['key'],
                  verify=vv['verify'], key=vv['pk'])
        mm = open(vv['message'], 'rb').read()
        ee = cc.encrypt(mm)
        embeed(EMess(ee), vv['if'], vv['of'], vv['ths'], vv['frame'])
    elif vv['func'] == 'extract':
        dd = Cryp(mode=getenc(vv['enc']), password=vv['key'],
                  verify=vv['verify'], key=vv['pk'])
        ee = extract(vv['if'], vv['ths'], vv['frame'])
        mm, broken = dd.decrypt(ee)
        if broken:
            print('data may broken during embeeding.')
        if vv['of'] is None:
            print(mm)
        else:
            open(vv['of'], 'wb').write(mm)
    else:
        print('Unrecognized command. Exiting.')
