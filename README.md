Tuya Encryption
===============

This program re-implements the encryption algorithm used for firmware packages for BK7231T Tuya devices.

It's still not entierly finished; Only the scramble3 method has been verified against a known result. The scramble1 and scramble2 functions still needs to be verified. Also, the output filename is hardcoded in this program, instead of adding "_enc" to the filename before the extension. The ".cpr" and ".out" file are also not generated (are those even used by anything?).

Hopefully I or someone else can make a decryption routine based on this here code.

Compiling
---------

```sh
gcc --std=c99 encrypt.c -o encrypt
```

How the passcodes work
----------------------

* passcode0 is used if scramble3 is enabled.
* passcode1 is used if scramble1 and/or scramble2 is enabled.
* passcode2 is XOR'd with the result if scramble4 is enabled.
* passcode3 determines which scramble methods are enabled.

### passcode3 format
```txt
    31      24 23      16 15      8  7       0
    |       |  |       |  |       |  |       |
    0000 0000  0000 0000  0000 0000  0000 0000
    '-------|  |||| ||||  |||| ||||  |||| |||'- scramble1EnableFlag (0: enable, 1: disable)
            |  |||| ||||  |||| ||||  |||| ||'-- scramble2EnableFlag (0: enable, 1: disable)
            |  |||| ||||  |||| ||||  |||| |'--- scramble3EnableFlag (0: enable, 1: disable)
            |  |||| ||||  |||| ||||  |||| '---- scramble4EnableFlag (0: enable, 1: disable)
            |  |||| ||||  |||| ||||  |||'------ scramble2Add256 (0: disable, 1: enable)
            |  |||| ||||  |||| ||||  |''------- scramble1Variant
            |  |||| ||||  |||| ||||  '--------- unused
            |  |||| ||||  |||| ||''------------ scramble2Variant
            |  |||| ||||  |||'-+'-------------- unused
            |  |||| ||||  |''------------------ scramble3Variant
            |  '+++-++++--'-------------------- unused
            '---------------------------------- disableScramble (if 0x00 or 0xFF; all other values ignored)
```
