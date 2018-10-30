# ncmdump
C version of ncmdump with no external dependency but standard C library.
C语言版本的ncm格式转换程序，依赖程序均已包含。
感谢[nondanee/ncmdump](https://github.com/nondanee/ncmdump)提供了python算法。
使用python确实太慢了，可能需要数十秒。此C语言版本平均每首用时约1秒，可见C语言的威力。

AES decryption code is from [AN324 ADVANCED ENCRYPTION STANDAR](https://www.silabs.com/documents/public/application-notes/AN324.pdf), SILICON LABS.
JSON parser is from [DaveGamble/cJSON](https://github.com/DaveGamble/cJSON)
