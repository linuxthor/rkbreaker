## Rootkit Breaker

(rootkit-breaker-logo.png)    

The paper "Effectiveness of Linux Rootkit Detection Tools" by Juho Junnila (http://jultika.oulu.fi/files/nbnfioulu-202004201485.pdf) makes it clear that current Linux rootkit detection tools (except perhaps LKRG which has a bit of a different design motivation) don't do a great job! The most alarming statement is that **"37.3% of detection tests didn't provide any indication of a rootkit infection"**  

Rootkit breaker is an experimental **proof of concept** tool using kprobes to try and detect/prevent certain types of **known** rootkits.    

   
    
