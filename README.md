# multirdp
Patch for Windows XP/Vista for multiple access over RDP

It will works only for XP/Vista. For newer version use [rdpwrap](https://github.com/stascorp/rdpwrap).

### Compile

msvc:

```
cl /c termsrv_patcher.c
link termsrv_patcher.obj advapi32.lib /out:termsrv_patcher.exe
```
gcc:

```
gcc termsrv_patcher.c
```

### Usage

```
termsrv_patcher.exe --patch
termsrv_patcher.exe --restore
```
