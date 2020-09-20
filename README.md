# Rootkit Breaker

![](rootkit-breaker-logo.png)    

The paper "Effectiveness of Linux Rootkit Detection Tools" by Juho Junnila (http://jultika.oulu.fi/files/nbnfioulu-202004201485.pdf) makes it clear that current Linux rootkit detection tools (except perhaps LKRG which has a bit of a different design motivation) don't do a great job!    

__The most alarming statement is that **"37.3% of detection tests didn't provide any indication of a rootkit infection"**__      

Rootkit breaker is an experimental **proof of concept** tool showing the use of kprobes to try and detect/prevent certain types of **known** rootkits by a few different techniques.   

### Identifying known bad LKM using signatures (first line defence)   

Each loadable kernel module being inserted into the kernel is checked for patterns in the code or data associated with **known** rootkits. This area of the code currently has a _small number or signatures_ associated with some of the more prominent Linux LKM rootkits. If a signature is found then the module is prevented from loading by overwriting it's init function pointer in the struct module with one of our own.   

### Gatekeeping certain functions (second line defence)     

Some kernel functions are abused time and again because rootkit developers are **developers** and all developers like to reuse some working code! :) So you see a bunch of stuff like kallsyms_lookup_name("sys_call_table") in lots of rootkits but "not so much" in other softwares.. Kprobes are used to check some functions for suspect arguments and we can prevent the call.. however.. this poses a problem. Rootkit developers (like ALL kernel developers.. ;) sometimes forget to check return values and might go ahead and dereference a NULL pointer you give them so to protect against this we try and steer them into an area of pre-allocated memory to do things like overwrite a fake syscall table etc. 

### Userland global preload prevention (tertiary defence)   

The userland 'LD_PRELOAD' rootkits often insert an entry into the file /etc/ld.so.preload to be loaded into all processes (even privileged processes) As this feature is only used occasionally for debugging so I think we can feel free to disable it in most case! The dynamic linker/loader first checks for /etc/ld.so.preload with a sys_access call before opening the file so we can arrange for that call to fail. There are rootkits that patch the linker/loader to check for a different path so more would need to be done in the real world.   


