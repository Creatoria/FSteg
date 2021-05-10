from gooey import Gooey, GooeyParser
from util import *
MODE = {'MODE_PLAIN': 0,
        'MODE_AES': 1}


def getenc(u):
    return MODE['MODE_' + u.upper()]


@Gooey(program_name='FSteg', program_description="Hide messages by fft")
def main():
    parser = GooeyParser()
    parser.add_argument('-if', metavar="源音频文件", widget="FileChooser")
    parser.add_argument('-of', metavar="导出音频文件", widget="FileChooser")
    parser.add_argument('-m', metavar="待嵌入的文件", widget='FileChooser')
    funn = parser.add_mutually_exclusive_group()
    funn.add_argument('-est', dest='est', metavar='预估容量', action='store_true')
    funn.add_argument('-emb', dest='emb', metavar='嵌入', action='store_true')
    funn.add_argument('-ext', dest='ext', metavar='提取', action='store_true')

    parser.add_argument('-verify', metavar='签名',
                        action='store_true', widget='CheckBox')
    parser.add_argument('-pk', metavar='证书路径', widget='FileChooser')
    parser.add_argument('-enc', metavar='加密',
                        choices=['Plain', 'AES'], widget='Dropdown')
    parser.add_argument('-key', metavar='密钥')
    parser.add_argument('-ths', metavar='阈值', default=1600, type=int)
    parser.add_argument('-frame', metavar='点数', default=441, type=int)

    args = parser.parse_args()
    vv = vars(args)
    # print(vv['est'], vv['emb'], vv['ext'])
    # exit(0)
    if vv['est']:
        size, srt, ll = estimate(vv['if'], vv['ths'], vv['frame'])
        print('{} Bytes available under {}Hz, {}kbps in average, under {} points per frame, threshold = {}'.format(
            size, srt, size * 8 / ll / srt, vv['frame'], vv['ths']))
    elif vv['emb']:
        cc = Cryp(mode=getenc(vv['enc']), password=vv['key'],
                  verify=vv['verify'], key=vv['pk'])
        mm = open(vv['message'], 'rb').read()
        ee = cc.encrypt(mm)
        embeed(EMess(ee), vv['if'], vv['of'], vv['ths'], vv['frame'])
    elif vv['ext']:
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


if __name__ == '__main__':
    main()
