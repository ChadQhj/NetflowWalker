#!/bin/sh
cat user_white_domain_* > user_white_domain.txt
objcopy -I binary -O  elf64-x86-64 -B i386:x86-64 maltrails.csv maltrails.o
objcopy -I binary -O  elf64-x86-64 -B i386:x86-64 whitelist.txt whitelist.o
objcopy -I binary -O  elf64-x86-64 -B i386:x86-64 web_shells.txt web_shells.o
objcopy -I binary -O  elf64-x86-64 -B i386:x86-64 ua.txt ua.o
objcopy -I binary -O  elf64-x86-64 -B i386:x86-64 user_white_domain.txt user_white_domain.o
gcc -shared -fPIC -o libmt.so *.o
