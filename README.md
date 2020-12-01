# Spectre BTB gadget finder

These scripts find gadgets suitable for a spectre BTB attack that tries to
recover ASCII text. It looks for indirect jumps and calls into the libc, and
search for valid gadgets from there.

It has been tuned for the Donjon's CTF "ghostbuster" stage, but could be
adapted to any other situation. A writeup of this challenge using this tool can
be read [on the Donjon's blog](https://donjon.ledger.com/ghostbuster/).

## Installation

Python requirements can be installed using the provided `requirements.txt` file:

```
$ pip install -r requirements.txt
```

Moreover, it uses LLVM for disassembly. You need development packages, as
header files are needed to call C API using
[DragonFFI](https://github.com/aguinet/dragonffi). Under Debian/Ubuntu, this
can be installed by doing:

```
$ sudo apt install llvm-10-dev
```

It is known to work with an LLVM version from 7 to 11.

## Usage

```
$ python ./find.py
Usage: ./find.py llvm_root libc ninstrs
```

where arguments are:

* `llvm_root` is the root of your LLVM installation. For instance, if you use
Ubuntu 18's `llvm-10-dev` package, this will be `/usr/lib/llvm-10`.
* `libc` is the path to the libc to find gadget into
* `ninstrs` is the number of instruction to consider in the gadgets (ending with a call/jump instruction)

## Example

Using the `libc` version used for the Ghostbuster challenge
(`libc_ghostbuster.so` in this repository), this outputs (for `ninstrs=5`):

```
$ python ./find.py /usr/lib/llvm-10 ./libc_ghostbuster.so 5
[x] Disassembling...
[x] Found 968 indirect calls/jmps. Looking for valid gadgets...
[+] Gadget at 0x313a2, table with 1 elts, table address = 0x001A96EC, element size = 4, valid characters: ' '
[+] Gadget at 0x6b5c1, table with 3 elts, table address = 0x001AE19C, element size = 4, valid characters: 'be}'
[+] Gadget at 0x6bab4, table with 1 elts, table address = 0x001AE3A8, element size = 4, valid characters: 'J'
[+] Gadget at 0x7383b, table with 2 elts, table address = 0x001AE5A8, element size = 4, valid characters: 'em'
[+] Gadget at 0x73af5, table with 5 elts, table address = 0x001AE664, element size = 4, valid characters: '>Tdil'
[+] Gadget at 0x73d94, table with 3 elts, table address = 0x001AE7B4, element size = 4, valid characters: 'J_b'
[+] Gadget at 0x7c76f, table with 2 elts, table address = 0x001AE9C0, element size = 4, valid characters: 'A{'
[+] Gadget at 0x7d604, table with 2 elts, table address = 0x001AF1DC, element size = 4, valid characters: 'ks'
[+] Gadget at 0x9ac5d, table with 62 elts, table address = 0x001AF340, element size = 4, valid characters: '9:;<=>?@ABCDEFIJKLMNOPQRSTUVYZ[\]^_`abcdefijklmnopqrstuxyz{|}~'
[+] Gadget at 0xa84c4, table with 88 elts, table address = 0x001AF3B4, element size = 4, valid characters: ' !"#$%&'()*,-./0123456789<=>?@ABCDEFGHILMNOPQRSTUVWXY[\]^_`abcdefghijklmnopqrstuvwxz{|}~'
[+] Gadget at 0xa8669, table with 90 elts, table address = 0x001AF3FC, element size = 4, valid characters: ' !"#$%&'(*+,-./01234567:;<=>?@ABCDEFGIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}'
[+] Gadget at 0xbba70, table with 3 elts, table address = 0x001AFB80, element size = 4, valid characters: '=OU'
[+] Gadget at 0xd7892, table with 2 elts, table address = 0x001B0120, element size = 4, valid characters: 'no'
[+] Gadget at 0xd7d42, table with 5 elts, table address = 0x001B0200, element size = 4, valid characters: ' 56y~'
[+] Gadget at 0xdc509, table with 3 elts, table address = 0x001B06B4, element size = 4, valid characters: 'PZs'
[+] Gadget at 0xe6f01, table with 1 elts, table address = 0x001B0CD0, element size = 4, valid characters: 'q'
[+] Gadget at 0xe9c36, table with 1 elts, table address = 0x001B0D24, element size = 4, valid characters: '\'
[+] Gadget at 0xea237, table with 1 elts, table address = 0x001B0DA4, element size = 4, valid characters: '<'
[+] Gadget at 0x1560ed, table with 1 elts, table address = 0x001B3944, element size = 4, valid characters: ' '
[+] Gadget at 0x196d42, table with 14 elts, table address = 0x001BDF20, element size = 4, valid characters: '-.79;AC^dvxz|~'
```
