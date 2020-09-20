# Rootkit Breaker

![](rootkit-breaker-logo.png)    

The paper "Effectiveness of Linux Rootkit Detection Tools" by Juho Junnila (http://jultika.oulu.fi/files/nbnfioulu-202004201485.pdf) makes it clear that current Linux rootkit detection tools (except perhaps LKRG) don't do a great job!    

The most alarming statement is that __**"37.3% of detection tests didn't provide any indication of a rootkit infection"**__      

Rootkit breaker is an experimental **proof of concept** LKM showing the use of kprobes to try and detect/prevent certain types of **known** rootkits by a few different techniques.   

Rootkit breaker can prevent some **known** rootkits from loading and can stop some **known** and **unknown** rootkits (using **known** techniques) from functioning correctly while still (hopefully) allowing other LKM to operate. 

Rootkit breaker does not try in any way to guard itself against malware that attempts to circumvent or bypass it. 

Rootkit breaker tries to stop rootkits from being loaded or from functioning properly - it is **not a rootkit detection tool** 

Rootkit breaker is **proof of concept** (see N.A.S.T.Y warning below!) Use it to study anti-rootkit. Don't run it on your important stuff and get sad when something bad happens!    

### Identifying known bad LKM using signatures (first line defence)   

Each loadable kernel module being inserted into the kernel is checked for patterns in the code or data sections associated with **known** rootkits. This area of the program currently has a _small number or signatures_ associated with some of the more prominent Linux LKM rootkits (enough to show how it could work - not intending to cover every rootkit ever) If a signature is found then the module is prevented from loading by overwriting it's init function pointer in the struct module with pointer to a function that returns -EACCES  

### Gatekeeping certain functions (second line defence)     

Some kernel functions are abused time and again because rootkit developers are **developers** and all developers like to reuse some working code! :) So you see a bunch of stuff like kallsyms_lookup_name("sys_call_table") in lots of rootkits but "not so much" in other software.. Kprobes are used to check some functions for suspect arguments and we can prevent the call.. however.. this poses a problem.. rootkit developers (like ALL kernel developers.. ;) sometimes forget to check return values and might go ahead and dereference a NULL pointer you give them and blow up in the middle of YOUR running kernel! To protect against this we try and steer them into an area of pre-allocated memory to do the things like overwrite a pointer in (fake) syscall table etc. 

### Userland global preload prevention (tertiary defence)   

The userland 'LD_PRELOAD' rootkits often insert an entry into the file /etc/ld.so.preload to be loaded into all processes (even privileged processes) As this feature is only used occasionally for debugging so I think we can feel free to disable it in most case! The dynamic linker/loader first checks for /etc/ld.so.preload with a sys_access call before opening the file so we can arrange for that call to fail. There are rootkits that patch the linker/loader to check for a different path so more would need to be done in the real world.   

## Important! N.A.S.T.Y warning! 

_"..**N**ot **a** **s**ecurity **t**ool **y**eah?.."_

This is a proof of concept to show a couple of different techniques. If you want to fork it and make it a full tool then please go ahead! I'd be sad to learn you're using it on your important systems as-is! 


