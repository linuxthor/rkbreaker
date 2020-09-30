/* 
 * rkbreaker 
 *
 * Copyright (c) 2020 linuxthor.
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3. Or give it to the rag and 
 * bone man because I love eels.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of your 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>
#include <linux/slab.h>

unsigned long *sct; 
unsigned long *fake_sct;
char *fake_argstr = "fake_sct";

void *memsrch(const void *s1, size_t len1, const void *s2, size_t len2)
{
    if (!len2)
    {
        return (void *)s1;
    }
    while (len1 >= len2)
    {
        len1--;
        if (!memcmp(s1, s2, len2))
        {
            return (void *)s1;
        }
        s1++;
    }
    return NULL;
}

static struct kprobe sct_kp = { 
};

// kallsyms_lookup_name is going away (https://lwn.net/Articles/813350/) so we use a kprobe to 
// try find the sys_call_table address.. seems to work ok for now.. 
unsigned long *kprobe_find_sct(void)
{
    unsigned long *table; 

    sct_kp.symbol_name = "sys_call_table";
    register_kprobe(&sct_kp);
    table = (void *)sct_kp.addr;
    if(table != 0)
    {
        printk("rkb: sys_call_table at %px\n",(void *)table);
    } 
    else
    {
        printk("rkb: sys_call_table not found\n"); 
    }
    return table;
}

static int fake_init_function(void)
{
    return -13;
}

static int do_init_module_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    int x; 
    struct module *mods;

    // 
    // code signatures.. 
    //
    // 0f 22 c0            mov    %rax,%cr0
    char cr0_rax[3] = {'\x0f','\x22','\xc0'};

    //
    // data signatures.. 
    //    
    char *data_str[24] = {
    // strings associated with (unmodified) reptile rootkit    
      "/reptile/reptile","KHOOK_","is_proc_invisible",
    // strings associated with (unmodified) rootfoo rootkit
      "ROOTKIT syscall_table", "ROOTKIT sys_call_table", "un_hijack_execve",
    // strings associated with (unmodified) sutekh rootkit
      "Giving r00t", "[?] SCT:", "Example Rootkit",
    // strings associated with (unmodified) lilyofthevalley rootkit
      "givemeroot"," lilyofthevalley"," u want to hide",
    // strings associated with (unmodified) diamorphine rootkit
      "diamorphine_","m0nad","LKM rootkit",
    // strings associated with (unmodified) honeypot bears rootkit
      "_backdoor_user","/home/haxor","/etc/secretshadow",
    // strings associated with (unmodified) nuk3gh0stbeta rootkit
      "hide pid command","hide file command","asm_hook_remove_all",
    // strings associated with generic rootkits in general
      "r00tkit","r00tk1t","module_hide"
    };

    mods = (void *)regs->di;

    // code check.. 
    if(memsrch(mods->core_layout.base, mods->core_layout.text_size, cr0_rax, 3) != 0)
    {
       //
       // a hack.. hooking do_init_module is quite late so we need to overwrite the 'init'
       // function pointer if we see something we don't like so we can fail cleanly
       //
        printk("rkb: Module %s contains suspect cr0 instructions\n",mods->name);
        mods->init = &fake_init_function;
    }

    // data check.. 
    for (x = 0; x < (sizeof(data_str) / sizeof(char *)); x++)
    {
        if(memsrch((mods->core_layout.base + mods->core_layout.text_size), 
                      (mods->core_layout.ro_size - mods->core_layout.text_size), (char *)data_str[x],  
                                                                     strlen((char *)data_str[x])) != 0)
        {
            printk("rkb: Module %s contains suspect string\n",mods->name);
            mods->init = &fake_init_function; 
        }
    }
  
    return 0;
}

static int rkeybdnotif_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    // unsure if this should hard fail.. there appears a couple of accessibility
    // use cases with braille terminals that use it.. 
    printk("rkb: Warning register_keyboard_notifier called\n");
    return 0;
}

static int kallsyms_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    char *symsym; 

    if(regs->di != 0)
    {
        symsym = (char *)regs->di; 
        if(strcmp(symsym, "sys_call_table") == 0)
        {
            printk("rkb: kallsyms_lookup_name called for sys_call_table!\n");
            regs->di = (unsigned long)fake_argstr;
        }
    }
    return 0;
}

// kallsyms_on_each_symbol.. 
// 
// int kallsyms_on_each_symbol(int (*fn)(void *, const char *, struct module *,
//                                                       unsigned long), void *data);
//
// (first arg is a callback function called once for each symbol and second arg a ptr
//   to some data) 
//
// code sample from the reptile rootkit:
//
// static int khook_lookup_cb(long data[], const char *name, void *module, long addr)
// {
//      int i = 0; while (!module && (((const char *)data[0]))[i] == name[i]) {
//              if (!name[i++]) return !!(data[1] = addr);
//      } return 0;
// }
//
// static void *khook_lookup_name(const char *name)
// {
//      long data[2] = { (long)name, 0 };
//      kallsyms_on_each_symbol((void *)khook_lookup_cb, data);
//      return (void *)data[1];
// }
//
// we could look at the second argument to this function (**data) but.. meh.....  
// kallsyms_on_each_symbol doesn't really specify what the second (data) argument
// is.. it's just void ptr to some data passed to your callback function (first arg) so 
// it's not to say that a pointer to ye string absolutely is in data[0] or whatnot..  
// so.. in this case it seems reasonable to attach a kprobe to the callback function 
// and look at things there(?)  

static int kallsyms_cback_func_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    char *symsym; 

    if(regs->si != 0)
    {
        symsym = (char *)regs->si; 

        if(strcmp(symsym, "sys_call_table") == 0)
        {
            printk("rkb: kallsyms_on_each_symbol scrubbing symbol\n");
            regs->cx = (unsigned long)fake_sct; 
        }

        // These two for the kmatryoshka loader.. 
        if((strcmp(symsym, "SYS_INIT_MODULE") == 0) || 
           (strcmp(symsym, "__DO_SYS_INIT_MODULE") == 0))
        {
            printk("rkb: kallsyms_on_each_symbol (init_module) scrubbing\n");
            regs->cx = 0; 
        }
    }
    return 0;
}

static struct kprobe kallsyms_cback_kp = {
    .pre_handler         = kallsyms_cback_func_pre_handler
};

static int kallsyms_on_each_symbol_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    int ret;

    if(regs->di != 0)
    {
        printk("rkb: kallsyms_on_each_symbol called so attaching to callback\n");
        if(kallsyms_cback_kp.addr != 0)
        {
            unregister_kprobe(&kallsyms_cback_kp);
            kallsyms_cback_kp.symbol_name = 0;
            kallsyms_cback_kp.flags = 0;
        }
        kallsyms_cback_kp.addr = (void *)regs->di;
        if((ret = register_kprobe(&kallsyms_cback_kp)) < 0)
        {
            pr_err("rkb: kallsyms_cback register_probe returned %d\n", ret);
        }
    }
    return 0;
}

// lookup_address() is called to fetch page table entry for sys_call_table and directly set 
// that writable by some rootkits.. code to do so looks something like:  
//
//   unsigned int level;
//   pte_t *pte = lookup_address(sct, &level);
//   if (pte->pte &~_PAGE_RW)
//   {
//       pte->pte |=_PAGE_RW;
//   }
//
static int lookupad_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    if(sct == 0)
    {
        return 0;
    }
    if((unsigned long)regs->di == (unsigned long)sct)
    {
        printk("rkb: Warning - lookup_address called for sys_call_table\n");
        // XXX should fail it here(?)
    }
    return 0;
}

static struct kprobe do_init_module_kp = {
    .pre_handler         = do_init_module_pre_handler
};

static struct kprobe rkeybdnotif_kp  = {
    .pre_handler         = rkeybdnotif_pre_handler
};

static struct kprobe kallsyms_kp = {
    .pre_handler         = kallsyms_pre_handler
};

static struct kprobe kallsyms_on_each_symbol_kp = {
    .pre_handler         = kallsyms_on_each_symbol_pre_handler
};

static struct kprobe lookup_address_kp = {
    .pre_handler         = lookupad_pre_handler
};

int init_module(void)
{
    int ret;
  
    sct = (void *)kprobe_find_sct();

    fake_sct = kmalloc(PAGE_SIZE, GFP_KERNEL); 

    do_init_module_kp.symbol_name            = "do_init_module";
    rkeybdnotif_kp.symbol_name               = "register_keyboard_notifier";
    kallsyms_kp.symbol_name                  = "kallsyms_lookup_name";
    kallsyms_on_each_symbol_kp.symbol_name   = "kallsyms_on_each_symbol";
    lookup_address_kp.symbol_name            = "lookup_address";  
 
    if((ret = register_kprobe(&do_init_module_kp)) < 0)    
    {
        pr_err("rkb: do_init_module register_kprobe returned %d\n", ret);
        return ret;
    }
    if((ret = register_kprobe(&rkeybdnotif_kp)) < 0)    
    {
        pr_err("rkb: register_keyboard_notifier register_kprobe returned %d\n", ret);
        return ret;
    }
    if((ret = register_kprobe(&kallsyms_kp)) < 0)    
    {
        pr_err("rkb: kallsyms register_kprobe returned %d\n", ret);
        return ret;
    }
    if((ret = register_kprobe(&kallsyms_on_each_symbol_kp)) < 0)    
    {
        pr_err("rkb: kallsyms_on_each_symbol register_kprobe returned %d\n", ret);
        return ret;
    }
    if((ret = register_kprobe(&lookup_address_kp)) < 0)    
    {
        pr_err("rkb: lookup_address register_kprobe returned %d\n", ret);
        return ret;
    }
    return 0;
}

void cleanup_module(void)
{
    unregister_kprobe(&do_init_module_kp);
    unregister_kprobe(&rkeybdnotif_kp);
    unregister_kprobe(&kallsyms_kp);
    unregister_kprobe(&kallsyms_on_each_symbol_kp);
    unregister_kprobe(&lookup_address_kp);

    if (kallsyms_cback_kp.addr != 0)
    {
        unregister_kprobe(&kallsyms_cback_kp);
    }

    kfree(fake_sct);
}

MODULE_AUTHOR("linuxthor");
MODULE_LICENSE("GPL");
