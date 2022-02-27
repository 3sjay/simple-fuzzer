## Info

Simple commandline fuzzer written in rust for tools who parse local files
We are making use of ramdisk to enhance the fuzzing speed a bit.

Hence execute the following commands before running the fuzzer (path currently hardcoded)
```
diskutil erasevolume HFS+ 'RAMDisk' `hdiutil attach -nomount ram://4388608`
mkdir /Volumes/RAMDisk/ramstuff
```

Run the fuzzer on some binary,
arg[1] => corpus
arg[2] => tool to fuzz
arg[n] => other commandline paramters
arg[n+1] => (will be added by the fuzzer automatically) is the mutated file on the ramdisk
```
# cargo run ~/fun/fuzz/targets/targetbin/corpus  ~/fun/fuzz/targets/assetutil/CARParser 
```

The libgmalloc is used to hopefully find more heap related bugs, here the cmd for easily retesting the bug
```
# DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib
```
