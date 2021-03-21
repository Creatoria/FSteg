# FSteg

基于傅里叶变换的隐写，让你能够在音频文件(wav)中隐藏信息。使用RS码进行纠错，支持AES加密与RSA签名验证。

## Usage

```
> py .\app.py -h         
usage: app.py [-h] {estimate,embeed,extract} ...       

hide messages by fft

positional arguments:
  {estimate,embeed,extract}

optional arguments:
  -h, --help            show this help message and exit

> py app.py estimate -h
usage: app.py estimate [-h] [-ths THS] [-frame FRAME]
                       [-if IF]

estimate the capacity of the audiofile

optional arguments:
  -h, --help    show this help message and exit
  -ths THS      minimum threshold
  -frame FRAME  points per frame
  -if IF        the source file     

> py app.py embeed -h  
usage: app.py embeed [-h] [-ths THS] [-frame FRAME] [-if IF] [-of OF] [-pk PK]
                     [-enc ENC] [-key KEY] [--verify] [-m MESSAGE]

embeed the message into the audiofile

optional arguments:
  -h, --help            show this help message and exit
  -ths THS              minimum threshold
  -frame FRAME          points per frame
  -if IF                the source file
  -of OF                the output file
  -enc ENC              the encryption mode
  -key KEY              the key used top encrypt
  --verify              check the integrity of the message
  -pk PK                the private key used to sign
  -m MESSAGE, --message MESSAGE
                        the file to hide        

> py app.py extract -h 
usage: app.py extract [-h] [-ths THS] [-frame FRAME] [-if IF] [-of OF] [-pk PK]
                      [-enc ENC] [-key KEY] [--verify]

extract the message from the audiofile

optional arguments:
  -h, --help    show this help message and exit
  -ths THS      minimum threshold
  -frame FRAME  points per frame
  -if IF        the source file
  -of OF        the output file
  -enc ENC      the decryption mode
  -key KEY      the key used top decrypt
  --verify      check the integrity of the message
  -pk PK        the public key used to verify
```

受载体音频以及参数(每帧点数、阈值、校验位等)的不同，实际可以隐藏的容量也有很大差异


## 已知问题

- 通过初相位角进行隐写时虽然能够保持在转换编码后仍有较高的鲁棒性，但也会有更高的误码率；通过幅度进行嵌入时不易出现字节错误，但无法承受压缩转换。
- 由于面向字节，在同步攻击下应该会有很差的效果
- **早期版本，鲁棒性仍不可靠**

## Reference

- 王秋生,孙圣和.基于量化数字音频信号频域参数的水印嵌入算法[J].声学学报,2002(04):379-385.

## License
Apache

**禁 止 抄 袭**