# online resources and bookmarks

stuff to open in browser tabs during the ctf. all publicy available, no login needed.

---

## main ones

| site                      | url                                                                         | what its for                                             |
| ------------------------- | --------------------------------------------------------------------------- | -------------------------------------------------------- |
| HackTricks binary exploit | https://book.hacktricks.xyz/binary-exploitation                             | bof, rop, fmt str, heap - basically everthing pwn        |
| pwntools docs             | https://docs.pwntools.com/en/stable/                                        | pwntools api reference                                   |
| CyberChef                 | https://gchq.github.io/CyberChef/                                           | decode/encode anything in browser (b64, xor, aes, rot13) |
| syscall table x86_64      | https://filippo.io/linux-syscall-table/                                     | searchable syscall numbers + args                        |
| libc.rip                  | https://libc.rip/                                                           | identify libc from leaked addrs                          |
| dogbolt                   | https://dogbolt.org/                                                        | online decompiler (multiple engines)                     |
| pylingual                 | https://pylingual.io/                                                       | python bytcode decompiler online                         |
| dcode cipher id           | https://www.dcode.fr/cipher-identifier                                      | identify unkown ciphers                                  |
| steg toolkit ref          | https://github.com/DominicBreuker/stego-toolkit/blob/master/README.md#tools | big list of steg tools                                   |
| exploit-db ghdb           | https://www.exploit-db.com/google-hacking-database                          | google dorks database                                    |
| shodan                    | https://www.shodan.io/                                                      | search engine for devices/services                       |

---

## pwn specific

| site            | url                                             | notes                                     |
| --------------- | ----------------------------------------------- | ----------------------------------------- |
| HackTricks pwn  | https://book.hacktricks.xyz/binary-exploitation | main reference for all exploit techinques |
| pwntools        | https://docs.pwntools.com/en/stable/            | api docs - search any function            |
| pwndbg cmds     | https://pwndbg.re/pwndbg/commands/              | gdb pwndbg command refrence               |
| shell-storm     | http://shell-storm.org/shellcode/               | shellcode database                        |
| how2heap        | https://github.com/shellphish/how2heap          | heap exploit PoCs per glibc version       |
| rop emporium    | https://ropemporium.com/                        | rop practice + technique ref              |
| one_gadget      | https://github.com/david942j/one_gadget         | magic gadget finder                       |
| seccomp-tools   | https://github.com/david942j/seccomp-tools      | dump seccomp rules                        |
| ir0nstone notes | https://ir0nstone.gitbook.io/notes/             | well organized pwn notes                  |

---

## rev specific

| site          | url                                                         | notes                              |
| ------------- | ----------------------------------------------------------- | ---------------------------------- |
| angr examples | https://docs.angr.io/en/latest/examples.html                | angr usage patterns + ctf examples |
| z3 tutorial   | https://ericpony.github.io/z3py-tutorial/guide-examples.htm | z3 python api guide                |
| x86 ref       | https://www.felixcloutier.com/x86/                          | x86/x64 instruction lookup         |
| godbolt       | https://godbolt.org/                                        | compiler explorer (C to asm)       |
| online asm    | https://defuse.ca/online-x86-assembler.htm                  | assemble x86 to bytes online       |
| dogbolt       | https://dogbolt.org/                                        | multi-decompiler online            |
| pylingual     | https://pylingual.io/                                       | decompile python bytecode          |

---

## forensics / steg

| site           | url                                                                         | notes                                 |
| -------------- | --------------------------------------------------------------------------- | ------------------------------------- |
| CyberChef      | https://gchq.github.io/CyberChef/                                           | decode anything                       |
| stego toolkit  | https://github.com/DominicBreuker/stego-toolkit/blob/master/README.md#tools | comprehensive steg tool list          |
| steg online    | https://georgeom.net/StegOnline/upload                                      | online steg analysis (bit planes etc) |
| futureboy steg | https://futureboy.us/stegano/decinput.html                                  | online steganography decoder          |
| brandfolder    | https://brandfolder.com/                                                    | image metadata viewer                 |
| kaitai IDE     | https://ide.kaitai.io/                                                      | binary format parser/viewer           |
| forensically   | https://29a.ch/photo-forensics/                                             | image forensics suite online          |

---

## crypto

| site                    | url                                                       | notes                                  |
| ----------------------- | --------------------------------------------------------- | -------------------------------------- |
| CyberChef               | https://gchq.github.io/CyberChef/                         | all the encoding/decoding              |
| dcode                   | https://www.dcode.fr/en                                   | cipher id + decrypt (ceaser, vig, etc) |
| dcode cipher identifier | https://www.dcode.fr/cipher-identifier                    | paste ciphertext, tells u what it is   |
| boxentriq cipher id     | https://www.boxentriq.com/code-breaking/cipher-identifier | another cipher identifier              |
| hash analyzer           | https://www.tunnelsup.com/hash-analyzer/                  | identify hash types                    |
| crackstation            | https://crackstation.net/                                 | hash lookup (md5, sha1 etc)            |
| factordb                | http://factordb.com/                                      | factor large numbers (rsa)             |
| rsactftool              | https://github.com/RsaCtfTool/RsaCtfTool                  | auto rsa attacks                       |
| quipqiup                | https://quipqiup.com/                                     | auto substitution cipher solver        |

---

## web

| site            | url                                                | notes                          |
| --------------- | -------------------------------------------------- | ------------------------------ |
| HackTricks web  | https://book.hacktricks.xyz/                       | web exploit techniques         |
| jwt.io          | https://jwt.io/                                    | decode jwt tokens              |
| jwt_tool        | https://github.com/ticarpi/jwt_tool                | jwt attack tool                |
| exploit-db ghdb | https://www.exploit-db.com/google-hacking-database | google dork database           |
| shodan          | https://www.shodan.io/                             | internet device search         |
| requestbin      | https://pipedream.com/requestbin                   | catch http callbacks (xss etc) |

---

## osint

| site            | url                                          | notes                          |
| --------------- | -------------------------------------------- | ------------------------------ |
| sherlock        | https://github.com/sherlock-project/sherlock | username search                |
| whatsmyname     | https://whatsmyname.app/                     | username enum                  |
| HIBP            | https://haveibeenpwned.com/                  | email breach check             |
| crt.sh          | https://crt.sh/                              | cert transparency / subdomains |
| wayback machine | https://web.archive.org/                     | old website versions           |
| shodan          | https://www.shodan.io/                       | device/service search          |
| ipinfo          | https://ipinfo.io/                           | ip geolocation                 |
| tineye          | https://tineye.com/                          | reverse image search           |

---

## OT / automotive

| site           | url                                            | notes                |
| -------------- | ---------------------------------------------- | -------------------- |
| can-utils docs | https://github.com/linux-can/can-utils         | can bus tools        |
| savvycan       | https://github.com/collin80/SavvyCAN           | can gui analyzer     |
| caringcaribou  | https://github.com/CaringCaribou/caringcaribou | can security testing |

---

## general ctf

| site       | url                             | notes                          |
| ---------- | ------------------------------- | ------------------------------ |
| ctf wiki   | https://ctf-wiki.org/           | structured ctf reference       |
| ctf101     | https://ctf101.org/             | intro to each category         |
| ctfrecipes | https://www.ctfrecipes.com/     | categorized exploit techniques |
| ctftime    | https://ctftime.org/            | past ctf writeups              |
| nightmare  | https://guyinatuxedo.github.io/ | ctf walkthrough collection     |

---

## quick bookmark list

```
https://book.hacktricks.xyz/binary-exploitation
https://docs.pwntools.com/en/stable/
https://gchq.github.io/CyberChef/
https://filippo.io/linux-syscall-table/
https://libc.rip/
https://dogbolt.org/
https://pylingual.io/
https://docs.angr.io/en/latest/examples.html
https://ericpony.github.io/z3py-tutorial/guide-examples.htm
https://www.felixcloutier.com/x86/
https://shell-storm.org/shellcode/
https://ir0nstone.gitbook.io/notes/
https://ctf-wiki.org/
https://defuse.ca/online-x86-assembler.htm
https://godbolt.org/
https://crackstation.net/
https://www.dcode.fr/en
https://ropemporium.com/
https://github.com/DominicBreuker/stego-toolkit/blob/master/README.md#tools
https://www.exploit-db.com/google-hacking-database
https://www.shodan.io/
https://www.dcode.fr/cipher-identifier
https://www.boxentriq.com/code-breaking/cipher-identifier
https://www.tunnelsup.com/hash-analyzer/
https://futureboy.us/stegano/decinput.html
https://georgeom.net/StegOnline/upload
https://brandfolder.com/
https://ide.kaitai.io/
https://quipqiup.com/
http://factordb.com/
https://jwt.io/
```

tip: open all these before the ctf starts so theyre cached even if network gets slow
