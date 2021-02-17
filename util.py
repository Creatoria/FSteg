import numpy as np
from scipy.signal import stft, istft
from scipy.io import wavfile
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import random
import struct
from reedsolo import RSCodec

_check = 64
_rsc_block = 255 - _check
_header_size = 32
MODE_PLAIN = 0
MODE_RSA = 1
MODE_AES = 2

__all__ = ['Cryptor', 'EMess', 'embeed', 'extract', 'estimate']


class EMess():
    def __init__(self, text: bytes) -> None:
        self.text = text
        self.nn = 0
        self.bn = 0
        self.blen = len(text) * 8

    def __iter__(self):
        return self

    def __next__(self):
        if self.nn * 8 + self.bn > self.blen:
            raise StopIteration
        cc = bin(self.text[self.nn])[2:].zfill(8)[self.bn]
        self.bn += 1
        if self.bn == 8:
            self.nn += 1
            self.bn = 0
        return cc

    def __len__(self):
        return len(self.text)

    def __eq__(self, tt: object) -> bool:
        return self.text == tt


class Cryptor():
    def __init__(self, mode=None, debug=False, key=None, **kwargs):
        if mode is not None:
            self.mode = mode
            if self.mode not in [0, 1, 2]:
                raise TypeError('Unknown encryption mode')
            if self.mode == MODE_AES:
                if isinstance(key, bytes):
                    self.cipher = AES.new(
                        pad(key, 16), AES.MODE_CBC, bytes(16))
                elif isinstance(key, str):
                    self.cipher = AES.new(
                        pad(key.encode(), 16), AES.MODE_CBC, bytes(16))
                else:
                    raise TypeError('Unknown key type')
                self.block_size = self.cipher.block_size
            elif self.mode == MODE_RSA:
                k = RSA.import_key(key)
                self.cipher = PKCS1_OAEP.new(k)
                hLen = self.cipher._hashObj.digest_size
                # if not k.has_private():
                #     raise Exception('Not a private key')
                self.sz = k.size_in_bytes()
                self.block_size = self.sz - 2 * hLen - 2
            else:
                pass
        else:
            self.mode = MODE_PLAIN
            self.block_size = 16
        self.debug = debug
        if self.debug:
            print(self.block_size)

    def decrypt(self, data: bytes):
        bb = self._unhead(data[:_header_size])
        _rrs = RSCodec(_check)
        dd = data[_header_size:bb * 255 + _header_size]
        dd = unpad(_rrs.decode(dd)[0], _rsc_block)
        if self.mode == MODE_AES:
            dd = self._aes_dec(dd)
        elif self.mode == MODE_RSA:
            dd = self._rsa_dec(dd)
        else:
            dd = dd
        return unpad(dd, self.block_size)

    def encrypt(self, data: bytes):
        ee = pad(data, self.block_size)
        if self.mode == MODE_AES:
            ee = self._aes_enc(ee)
        elif self.mode == MODE_RSA:
            ee = self._rsa_enc(ee)
        else:
            pass
        return self._ehead(ee)

    def _ehead(self, data: bytes):
        header = b'FsTeg' + b'\x01\x02\x03'
        ee = pad(data, self.block_size)
        if self.mode == MODE_RSA:
            ll = struct.pack('i', 1 + len(ee) // self.sz)
        else:
            ll = struct.pack('i', 1 + len(ee) // self.block_size)
        _rrs1 = RSCodec()
        _rrs2 = RSCodec(_check)
        return _rrs1.encode(pad(header + ll, _header_size - 10)) + _rrs2.encode(pad(data, _rsc_block))

    def _unhead(self, hh: bytes):
        _rrs = RSCodec()
        hd = _rrs.decode(hh)[0]
        if hd[:5] != b'FsTeg':
            raise Exception('Unknown header type')
        if self.mode == MODE_RSA:
            ll = 1 + int.from_bytes(hd[8:12], 'little') * \
                self.sz // _rsc_block
        else:
            ll = 1 + int.from_bytes(hd[8:12], 'little') * \
                self.block_size // _rsc_block
        return ll

    def _aes_enc(self, data: bytes):
        return self.cipher.encrypt(data)

    def _aes_dec(self, data: bytes):
        return self.cipher.decrypt(data)

    def _rsa_enc(self, data: bytes):
        ''' eb = oaep_pad(pkcs7_pad(data))'''
        k = b''
        bc = len(data) // self.block_size
        for i in range(bc):
            u = self.cipher.encrypt(
                data[i * self.block_size:(i + 1) * self.block_size])
            k += u
        return k

    def _rsa_dec(self, data: bytes):
        k = b''
        ct = 0
        bb = len(data) // self.sz
        while ct < bb:
            u = self.cipher.decrypt(
                data[ct * self.sz:(ct + 1) * self.sz])
            ct += 1
            k += u
        return k


def extract(audiofile: str, ths=1800, perseg=441, overlap=0):
    srt, sig = wavfile.read(audiofile)
    bb = sig.shape[0] // (perseg - overlap) - 1
    f, t, zxxl = stft(sig[:bb * (perseg - overlap), 0], srt,
                      'rect', perseg, overlap)
    f, t, zxxr = stft(sig[:bb * (perseg - overlap), 1], srt,
                      'rect', perseg, overlap)
    i = 0
    d = ''
    while i < bb:
        cl = zxxl[:, i]
        cr = zxxr[:, i]
        idxl = np.argwhere(np.abs(cl) > ths)
        idxr = np.argwhere(np.abs(cr) > ths)
        for j in idxl:
            d += _gp_by_amp(cl[j])
        for j in idxr:
            d += _gp_by_amp(cr[j])
        # print('left channel:', [list(f[idxl].T[0]), list(np.abs(cl[idxl].T[0]).astype(int))],
        #       ',right channel:', [list(f[idxr].T[0]), list(np.abs(cr[idxr].T[0]).astype(int))], '@', t[i])
        i += 1
    return _bin2byt(d)


def embeed(mess: EMess, infile: str, outfile: str, ths=1800, perseg=441, overlap=0):
    srt, sig = wavfile.read(infile)
    sig = np.nan_to_num(sig)
    bb = sig.shape[0] // (perseg - overlap) - 1
    f, t, zxxl = stft(sig[:bb * (perseg - overlap), 0], srt,
                      'rect', perseg, overlap)
    f, t, zxxr = stft(sig[:bb * (perseg - overlap), 1], srt,
                      'rect', perseg, overlap)
    sl = []
    sr = []
    ll = 0
    i = 0
    lm = len(mess) * 8
    while ll < lm:
        cpl = zxxl[:, i].copy()
        cpr = zxxr[:, i].copy()
        idxl = np.argwhere(np.abs(cpl) > ths)
        idxr = np.argwhere(np.abs(cpr) > ths)
        # print('left channel:', [list(f[idxl].T[0]), list(np.abs(cpl[idxl].T[0]).astype(int))],
        #       ',right channel:', [list(f[idxr].T[0]), list(np.abs(cpr[idxr].T[0]).astype(int))], '@', t[i])
        for j in range(min(len(idxl), lm - ll)):
            cpl[idxl[j]] = _hb_by_amp(cpl[idxl[j]], next(mess))
            ll += 1
        for j in range(min(len(idxr), lm - ll)):
            cpr[idxr[j]] = _hb_by_amp(cpr[idxr[j]], next(mess))
            ll += 1
        sl.append(cpl)
        sr.append(cpr)

        i += 1
    print('blocks used:', i, 'total:', bb)
    _, rsl = istft(np.array(sl).T, srt, 'rect', perseg, overlap)
    _, rsr = istft(np.array(sr).T, srt, 'rect', perseg, overlap)
    fsg = list(np.array(np.around([rsl, rsr]), np.int16).T)
    fsg += list(sig[i * (perseg - overlap):])
    fsg = np.array(fsg, np.int16)
    wavfile.write(outfile, srt, fsg)
    # print(fsg.shape, sig.shape)
    # print(sum(np.abs(fsg - sig)))


def _hb_by_amp(nn: complex, b: str):
    i = nn.real
    j = nn.imag
    mm = np.abs(nn)
    if (int(mm // 10) % 2) ^ int(b):
        i += np.cos(np.angle(nn)) * 10
        j += np.sin(np.angle(nn)) * 10
    return np.complex(i, j)


def _gp_by_amp(tt: complex):
    bb = '1' if int(np.abs(tt) // 10) % 2 else '0'
    return bb


def _hb_by_ang(nn: complex, b: str):
    ll = np.abs(nn)
    aa = np.angle(nn, True)
    if (int(aa) // 3 % 2) ^ int(b):
        aa -= 3
        return np.complex(np.sin(aa) * ll, np.cos(aa) * ll)
    return nn


def _gp_by_ang(nn: complex):
    return '1' if (int(np.angle(nn, True)) // 3) % 2 else '0'


def _bin2byt(s: str):
    d = b''
    while len(s) >= 8:
        ct = int(s[:8], 2).to_bytes(1, 'little')
        d += ct
        s = s[8:]
    return d


def estimate(audiofile: str, ths=1800, perseg=441, overlap=0):
    srt, sig = wavfile.read(audiofile)
    bb = sig.shape[0] // (perseg - overlap) - 1
    _, _, zxxl = stft(sig[:bb * (perseg - overlap), 0], srt,
                      'rect', perseg, overlap)
    _, _, zxxr = stft(sig[:bb * (perseg - overlap), 1], srt,
                      'rect', perseg, overlap)
    i = 0
    u = 0
    while i < bb:
        cl = zxxl[:, i]
        cr = zxxr[:, i]
        u += sum(np.abs(cl) > ths) + sum(np.abs(cr) > ths)
        i += 1
    return u // 8


if __name__ == '__main__':
    infile = 'test/wavs/02.wav'
    outfile = 'out.wav'
    privk = 'test/test.key'
    print(estimate(infile), 'bytes available.')

    # c = Cryptor(MODE_AES, debug=0, key=b'123456')
    # d = Cryptor(MODE_AES, key=b'123456')

    # c = Cryptor(MODE_RSA, debug=True, key=open(privk).read())
    # d = Cryptor(MODE_RSA, key=open(privk).read())

    # mm = random.randbytes(2048)
    # mm = b'hello' * 100
    # ee = c.encrypt(mm)
    # print(ee, len(ee))
    # embeed(EMess(ee), infile, outfile)
    # dd = extract(outfile)
    # print(dd[:len(ee)], len(dd))
    # dd = d.decrypt(dd)
    # print(dd == mm)
