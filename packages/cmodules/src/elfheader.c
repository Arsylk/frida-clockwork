#include "glib.h"
#include <gum/guminterceptor.h>
#include <gum/gummemory.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEBUG_LOG FALSE

#define PT_DYNAMIC 2

#define DT_NULL 0
#define DT_PLTRELSZ 2
#define DT_PLTGOT 3
#define DT_HASH 4
#define DT_STRTAB 5
#define DT_SYMTAB 6
#define DT_RELA 7
#define DT_RELASZ 8
#define DT_RELAENT 9
#define DT_STRSZ 10
#define DT_SYMENT 11
#define DT_INIT 12
#define DT_FINIT 13
#define DT_SONAME 14
#define DT_RPATH 15
#define DT_REL 17
#define DT_RELSZ 18
#define DT_RELENT 19
#define DT_PLTREL 20
#define DT_JMPREL 23
#define DT_RELRSZ 35
#define DT_RELR 36
#define DT_RELRENT 37
#define DT_ANDROID_REL 0x6000000f
#define DT_ANDROID_RELA 0x60000011
#define DT_ANDROID_RELASZ 0x60000012
#define DT_ANDROID_RELSZ 0x60000010
#define DT_GNU_HASH 0x6ffffef5
#define DT_RELCOUNT 0x6ffffff8
#define DT_RELACOUNT 0x6ffffff9

#define STT_GNU_IFUNC 10
#define ELF_ST_BIND(info) ((info) >> 4)
#define ELF_ST_TYPE(info) ((info)&0xf)

typedef uint64_t u64;
typedef int64_t s64;
typedef uint32_t u32;
typedef int32_t s32;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint8_t u8;
typedef int8_t s8;

typedef u64 Elf64_Addr;
typedef u16 Elf64_Half;
typedef s16 Elf64_SHalf;
typedef u64 Elf64_Off;
typedef s32 Elf64_Sword;
typedef u32 Elf64_Word;
typedef u64 Elf64_Xword;
typedef s64 Elf64_Sxword;

typedef unsigned char byte;
typedef unsigned short word;
typedef unsigned int dword;
typedef unsigned long qword;

typedef struct elf64_ehdr {
  byte e_ident[16];
  Elf64_Half e_type;
  Elf64_Half e_machine;
  Elf64_Word e_version;
  Elf64_Addr e_entry;
  Elf64_Off e_phoff;
  Elf64_Off e_shoff;
  Elf64_Word e_flags;
  Elf64_Half e_ehsize;
  Elf64_Half e_phentsize;
  Elf64_Half e_phnum;
  Elf64_Half e_shentsize;
  Elf64_Half e_shnum;
  Elf64_Half e_shstrndx;
} Elf64_Ehdr;

typedef struct elf64_sym {
  u32 st_name;
  byte st_info;
  byte st_other;
  u16 st_shndx;
  u64 st_value;
  u64 st_size;
} Elf64_Sym;

typedef struct elf64_phdr {
  Elf64_Word p_type;
  Elf64_Word p_flags;
  Elf64_Off p_offset;
  Elf64_Addr p_vaddr;
  Elf64_Addr p_paddr;
  Elf64_Xword p_filesz;
  Elf64_Xword p_memsz;
  Elf64_Xword p_align;
} Elf64_Phdr;

typedef struct elf64_shdr {
  Elf64_Word sh_name;
  Elf64_Word sh_type;
  Elf64_Xword sh_flags;
  Elf64_Addr sh_addr;
  Elf64_Off sh_offset;
  Elf64_Xword sh_size;
  Elf64_Word sh_link;
  Elf64_Word sh_info;
  Elf64_Xword sh_addralign;
  Elf64_Xword sh_entsize;
} Elf64_Shdr;

typedef struct elf64_rela {
  qword r_offset;
  qword r_info;
  qword r_addend;
} Elf64_Rela;

typedef struct elf64_rel {
  qword r_offset;
  qword r_info;
} Elf64_Rel;

typedef struct {
  Elf64_Sxword d_tag;
  union {
    Elf64_Xword d_val;
    Elf64_Addr d_ptr;
  } d_un;
} Elf64_Dyn;

typedef struct elf64_relr {
  qword r_data;
} Elf64_Relr;

typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Sym Elf_Sym;
typedef Elf64_Dyn Elf_Dyn;
typedef Elf64_Rela Elf_Rela;
typedef Elf64_Rel Elf_Rel;
typedef Elf64_Relr Elf_Relr;

#define ELF64_R_SYM(i) ((i) >> 32)
#define ELF64_R_TYPE(i) ((i)&0xffffffffL)

typedef struct {
  u32 nbuckets;
  u32 symoffset;
  u32 bloom_size;
  u32 bloom_shift;
  u64 *bloom;
  u32 *buckets;
  u32 *chain;
} gnu_hash_table_t;

typedef struct {
  u64 base;
  u64 end;
  Elf_Rela *rela;
  Elf_Rel *rel;
  size_t relaent;
  size_t relent;
  int rela_count;
  int rel_count;
  Elf_Sym *dynsym;
  char *strtab;
  size_t syment;
  int sym_count;
  char name[256];
} Module;

typedef struct {
  u64 start;
  u64 end;
  char perms[5];
  u64 offset;
  char dev[6];
  u64 inode;
  char pathname[256];
} MapEntry;

typedef struct {
  MapEntry *entries;
  size_t count;
} MapList;

typedef enum JMPREL_TYPE { REL = 1, RELA = 2 } Jmprel_Type;

extern FILE *fopen(const char *pathname, const char *mode);
extern int sscanf(const char *str, const char *format, ...);
extern char *strstr(const char *haystack, const char *needle);
extern void *realloc(void *ptr, size_t size);
extern char *strncpy(char *dest, const char *src, size_t n);
extern char *strrchr(const char *s, int c);
extern char *fgets(char *s, int size, FILE *stream);
extern int fclose(FILE *stream);
extern void *malloc(size_t size);
extern void *calloc(size_t nmemb, size_t size);
extern void free(void *ptr);
static void mklog(const char *format, ...);
extern void frida_log(const gchar *messag, ...);
extern char *addressOf(void *ptr);
extern void *ensureReadable(void *ptr);
char *resolve_address(u64 add);

// Free map list
static void free_map_list(MapList *list) {
  if (list) {
    free(list->entries);
    free(list);
  }
}

static MapList *load_map_entries() {
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps)
    return NULL;

  MapList *list = (MapList *)malloc(sizeof(MapList));
  if (!list) {
    fclose(maps);
    return NULL;
  }

  list->entries = NULL;
  list->count = 0;

  char line[512];
  while (fgets(line, sizeof(line), maps)) {
    MapEntry *new_entries = (MapEntry *)realloc(
        list->entries, (list->count + 1) * sizeof(MapEntry));
    if (!new_entries) {
      free_map_list(list);
      fclose(maps);
      return NULL;
    }
    list->entries = new_entries;
    list->count++;

    MapEntry *entry = &list->entries[list->count - 1];
    memset(entry, 0, sizeof(MapEntry));

    // 56555000-56556000 r--p 00000000 08:02 393254 /usr/bin/cat
    int parsed =
        sscanf(line, "%lx-%lx %4s %lx %5s %lu %255[^\n]", &entry->start,
               &entry->end, entry->perms, &entry->offset, entry->dev,
               &entry->inode, entry->pathname);

    // Handle entries without pathname
    if (parsed < 7) {
      entry->pathname[0] = '\0';
    }

    // Filter out entries with no permissions
    if (strstr(entry->perms, "---")) {
      list->count--;
    }
  }

  fclose(maps);
  return list;
}

u32 find_max_sym_index(u64 gnu_hash) {
  u32 *header = (u32 *)gnu_hash;
  u32 nbuckets = header[0];
  u32 symndx = header[1];
  u32 maskwords = header[2];

  // The start of the hash buckets array (skip bloom filter)
  u32 *buckets = &header[4 + maskwords * 2];

  // The start of the hash chains
  u32 *chains = &buckets[nbuckets];

  u32 max_index = symndx > 0 ? symndx - 1 : 0;

  // Iterate through all the buckets
  for (u32 i = 0; i < nbuckets; i++) {
    if (buckets[i] != 0) {
      u32 current_index = buckets[i];

      // Iterate through the chain to find the last symbol
      while (1) {
        if (current_index > max_index) {
          max_index = current_index;
        }

        // Check the stop bit (least significant bit)
        if ((chains[current_index - symndx] & 1) != 0) {
          break;
        }
        current_index++;
      }
    }
  }

  return max_index;
}

static char *check_pltgot(u64 addr, u64 pltgot_addr, u64 got_size,
                          Elf_Sym *symtab, char *strtab, Elf_Rela *jmprel,
                          int jmprel_count, Jmprel_Type jmprel_type,
                          u64 base_addr, const char *soname) {
  if (!pltgot_addr || !symtab || !strtab || !jmprel)
    return NULL;

  mklog("Checking PLTGOT at 0x%lx for address 0x%lx", pltgot_addr, addr);

  // The PLTGOT layout is typically:
  // [0] = address of _DYNAMIC
  // [1] = link_map pointer
  // [2] = dl_runtime_resolve
  // [3+] = GOT entries for PLT

  u64 *got = (u64 *)pltgot_addr;
  u64 got_end = pltgot_addr + got_size;

  // Check if the address we're looking for is inside the GOT itself
  if (addr >= pltgot_addr && addr < got_end) {
    int got_index = (addr - pltgot_addr) / 8;
    mklog("Address is GOT entry [%d] at offset 0x%lx", got_index,
          addr - pltgot_addr);

    // Try to find which PLT entry this corresponds to
    for (int i = 0; i < jmprel_count; i++) {
      u64 reloc_offset = jmprel[i].r_offset;
      u64 reloc_addr = base_addr + reloc_offset;

      if (reloc_addr == addr) {
        u32 sym_idx = ELF64_R_SYM(jmprel[i].r_info);
        if (sym_idx < (u32)-1) {
          Elf_Sym *sym = &symtab[sym_idx];
          char *name = strtab + sym->st_name;

          if (name && name[0] != '\0') {
            u64 resolved_addr = got[got_index];
            mklog("GOT[%d] for %s: currently points to 0x%lx", got_index, name,
                  resolved_addr);
            return g_strdup_printf("%s!%s@got[%d]", soname ? soname : "unknown",
                                   name, got_index);
          }
        }
      }
    }
  }

  // Check if the address we're looking for is what a GOT entry points to
  // This handles the case where we're resolving the actual function address
  for (int i = 0; i < jmprel_count; i++) {
    u64 reloc_offset = jmprel[i].r_offset;
    u64 reloc_addr = base_addr + reloc_offset;

    // Calculate GOT index from relocation offset
    if (reloc_addr >= pltgot_addr) {
      int got_index = (reloc_addr - pltgot_addr) / 8;
      u64 got_value = got[got_index];

      // Check if this GOT entry points to our target address
      if (got_value == addr) {
        u32 sym_idx = ELF64_R_SYM(jmprel[i].r_info);
        if (sym_idx < (u32)-1) {
          Elf_Sym *sym = &symtab[sym_idx];
          char *name = strtab + sym->st_name;

          if (name && name[0] != '\0') {
            mklog("Found GOT[%d] pointing to 0x%lx -> %s", got_index, addr,
                  name);
            return g_strdup_printf("%s!%s@resolved",
                                   soname ? soname : "unknown", name);
          }
        }
      }
    }
  }

  return NULL;
}

static char *check_got_entry(u64 addr, u64 base_addr, Elf_Sym *symtab,
                             char *strtab, u32 dynsym_count,
                             const char *soname) {
  if (!symtab || !strtab)
    return NULL;

  // Read the value at the address (GOT entry points to actual function)
  u64 target_addr = *(u64 *)addr;

  // Check if target address points to a symbol
  for (u32 i = 0; i < dynsym_count; i++) {
    Elf_Sym *sym = &symtab[i];

    if (sym->st_value == 0)
      continue;

    u64 sym_addr = base_addr + sym->st_value;
    char *name = strtab + sym->st_name;
    mklog("got: 0x%lx %s", sym_addr, name);

    // Check if GOT entry points to this symbol
    if (target_addr == sym_addr) {

      if (name && name[0] != '\0') {
        return g_strdup_printf("%s!%s@got", soname ? soname : "unknown", name);
      }
    }
  }

  return NULL;
}

// Check if address is in a relocation entry
static char *check_relocations(u64 addr, u64 base_addr, Elf_Rel *rel,
                               int rel_count, Elf_Sym *symtab, char *strtab,
                               const char *soname) {
  mklog("check_relocations: 0x%lx 0x%lx 0x%lx", rel, symtab, strtab);
  if (!rel || !symtab || !strtab)
    return NULL;

  for (int i = 0; i < rel_count; i++) {
    u64 reloc_addr = base_addr + rel[i].r_offset;
    mklog("reloc: 0x%lx", reloc_addr);

    // Check if the address matches this relocation
    if (addr == reloc_addr) {
      u32 sym_idx = ELF64_R_SYM(rel[i].r_info);
      if (sym_idx < (u32)-1) {
        Elf_Sym *sym = &symtab[sym_idx];
        char *name = strtab + sym->st_name;

        if (name && name[0] != '\0') {
          return g_strdup_printf("%s!%s@rel", soname ? soname : "unknown",
                                 name);
        }
      }
    }
  }

  return NULL;
}

// Check if address is in a RELA relocation entry
static char *check_rela_relocations(u64 addr, u64 base_addr, Elf_Rela *rela,
                                    int rela_count, Elf_Sym *symtab,
                                    char *strtab, const char *soname) {
  mklog("check_rela_relocations: 0x%lx 0x%lx 0x%lx", rela, symtab, strtab);
  if (!rela || !symtab || !strtab)
    return NULL;

  for (int i = 0; i < rela_count; i++) {
    u64 reloc_addr = base_addr + rela[i].r_offset;
    u32 sym_idx = ELF64_R_SYM(rela[i].r_info);
    Elf_Sym *sym = &symtab[sym_idx];
    char *name = strtab + sym->st_name;
    mklog("reloc_addr: 0%lx %s", reloc_addr, name);

    // Check if the address matches this relocation
    if (addr == reloc_addr) {
      if (sym_idx < (u32)-1) {

        if (name && name[0] != '\0') {
          if (rela[i].r_addend != 0) {
            return g_strdup_printf("%s!%s+0x%lx@rela",
                                   soname ? soname : "unknown", name,
                                   rela[i].r_addend);
          }
          return g_strdup_printf("%s!%s@rela", soname ? soname : "unknown",
                                 name);
        }
      }
    }
  }

  return NULL;
}

static char *parse_elf(u64 addr, u64 find, MapList *list) {
  // Parse ELF
  Elf_Ehdr *ehdr = (Elf_Ehdr *)addr;
  if (ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E' ||
      ehdr->e_ident[2] != 'L' || ehdr->e_ident[3] != 'F')
    return NULL;

  mklog("0x%lx ~ ph: %d * 0x%x @ +0x%lx ~ sh: %d * 0x%x @ +0x%lx", addr,
        ehdr->e_phnum, ehdr->e_phentsize, ehdr->e_phoff, ehdr->e_shnum,
        ehdr->e_shentsize, ehdr->e_shoff);

  Elf_Phdr *phdrs = (Elf_Phdr *)(addr + ehdr->e_phoff);

  char *soname = NULL;
  Elf_Sym *symtab = NULL;
  char *strtab = NULL;
  Elf_Rela *rela = NULL;
  Elf_Rel *rel = NULL;
  Elf_Rela *jmprel = NULL;
  Elf_Relr *relr = NULL;
  u64 pltgot = 0, got_size = 0;
  int rela_count = 0;
  int rel_count = 0;
  int jmprel_count = 0;
  Jmprel_Type jmprel_type;
  int relr_count = 0;
  int pltrel_type = 0;
  u32 dynsym_count = 0;

  for (int i = 0; i < ehdr->e_phnum; i++) {
    Elf_Phdr *phdr = &phdrs[i];
    mklog("phdr: 0x%lx - type: %d", phdr, phdr->p_type);

    if ((int)phdr->p_type == PT_DYNAMIC) {
      Elf_Dyn *dyn = (Elf_Dyn *)(addr + phdr->p_offset);
      mklog("dyn: 0x%lx | %s", dyn, addressOf((void *)dyn));
      for (size_t i = 0; i < list->count; i++) {
        MapEntry *entry = &list->entries[i];
        mklog("dyn: %03d | 0x%lx-0x%lx %s", (int)i, entry->start, entry->end,
              entry->pathname);
      }

      size_t syment = 0, relaent = 0, rela_size = 0;
      size_t relent = 0, rel_size = 0;
      size_t jmprel_size = 0;
      size_t relrent = 0, relr_size = 0;
      u64 offsoname = 0;

      while (dyn->d_tag != DT_NULL) {
        mklog((dyn->d_tag > 100) ? "dyn->d_tag: 0x%lx" : "dyn->d_tag: %d",
              dyn->d_tag);
        switch (dyn->d_tag) {
        case DT_SONAME:
          offsoname = dyn->d_un.d_val;
          break;
        case DT_SYMTAB:
          symtab = (Elf_Sym *)(addr + dyn->d_un.d_ptr);
          break;
        case DT_STRTAB:
          strtab = (char *)(addr + dyn->d_un.d_ptr);
          break;
        case DT_SYMENT:
          syment = dyn->d_un.d_val;
          break;
        case DT_RELA:
          rela = (Elf_Rela *)(addr + dyn->d_un.d_ptr);
          break;
        case DT_RELAENT:
          relaent = dyn->d_un.d_val;
          break;
        case DT_RELASZ:
          rela_size = dyn->d_un.d_val;
          break;
        case DT_RELACOUNT:
          rela_count = dyn->d_un.d_val;
          break;
        case DT_REL:
          rel = (Elf_Rel *)(addr + dyn->d_un.d_ptr);
          break;
        case DT_RELENT:
          relent = dyn->d_un.d_val;
          break;
        case DT_RELSZ:
          rel_size = dyn->d_un.d_val;
          break;
        case DT_RELCOUNT:
          rel_count = dyn->d_un.d_val;
          break;
        case DT_JMPREL:
          jmprel = (Elf_Rela *)(addr + dyn->d_un.d_ptr);
          break;
        case DT_PLTRELSZ:
          jmprel_size = dyn->d_un.d_val;
          break;
        case DT_PLTREL:
          pltrel_type = dyn->d_un.d_val; // DT_REL=17 or DT_RELA=7
          break;
        case DT_PLTGOT:
          pltgot = addr + dyn->d_un.d_ptr;
          break;
        case DT_RELR:
          relr = (Elf_Relr *)(addr + dyn->d_un.d_ptr);
          break;
        case DT_RELRSZ:
          relr_size = dyn->d_un.d_val;
          break;
        case DT_RELRENT:
          relrent = dyn->d_un.d_val;
          break;
        case DT_ANDROID_REL:
          if (!rel)
            rel = (Elf_Rel *)(addr + dyn->d_un.d_ptr);
          break;
        case DT_ANDROID_RELSZ:
          if (rel_size == 0)
            rel_size = dyn->d_un.d_val;
          break;
        case DT_ANDROID_RELA:
          if (!rela)
            rela = (Elf_Rela *)(addr + dyn->d_un.d_ptr);
          break;
        case DT_ANDROID_RELASZ:
          if (rela_size == 0)
            rela_size = dyn->d_un.d_val;
          break;
        case DT_GNU_HASH:
          dynsym_count = find_max_sym_index(addr + dyn->d_un.d_ptr);
          break;
        }
        dyn++;
      }

      if (pltgot != 0) {
        u64 max_got_offset = 0;
        if (jmprel && jmprel_count > 0) {
          for (int i = 0; i < jmprel_count; i++) {
            u64 reloc_offset = jmprel[i].r_offset;
            if (reloc_offset > max_got_offset) {
              max_got_offset = reloc_offset;
            }
          }
          // Add space for the entry itself (8 bytes) and some padding
          got_size = max_got_offset - (pltgot - addr) + 16;
          mklog("Calculated GOT size: 0x%lx (based on max offset 0x%lx)",
                got_size, max_got_offset);
        }
        if (rela && rela_count > 0) {
          for (int i = 0; i < rela_count; i++) {
            u64 reloc_offset = rela[i].r_offset;
            u64 reloc_addr = addr + reloc_offset;

            // If this relocation is in the GOT area, update size
            if (reloc_addr >= pltgot && reloc_offset > max_got_offset) {
              max_got_offset = reloc_offset;
              got_size = max_got_offset - (pltgot - addr) + 16;
            }
          }
        }
        if (rel && rel_count > 0) {
          for (int i = 0; i < rel_count; i++) {
            u64 reloc_offset = rel[i].r_offset;
            u64 reloc_addr = addr + reloc_offset;

            if (reloc_addr >= pltgot && reloc_offset > max_got_offset) {
              max_got_offset = reloc_offset;
              got_size = max_got_offset - (pltgot - addr) + 16;
            }
          }
        }
      }

      if (jmprel && jmprel_size > 0) {
        if (relaent > 0) {
          jmprel_type = RELA;
          jmprel_count = jmprel_size / relaent;
        } else if (relent > 0) {
          jmprel_type = REL;
          jmprel_count = jmprel_size / relent;
        }
      }

      if (relaent > 0 && rela_size > 0) {
        rela_count = rela_size / relaent;
      }

      if (relent > 0 && rel_size > 0) {
        rel_count = rel_size / relent;
      }

      if (symtab && strtab) {
        if (offsoname > 0) {
          soname = (char *)(strtab + offsoname);
        }

        mklog("Symbol resolution for 0x%lx: dynsym_count=%d, rel_count=%d, "
              "rela_count=%d, jmprel_count=%d, relr_count=%d",
              find, dynsym_count, rel_count, rela_count, jmprel_count,
              relr_count);

        // Check GOT
        char *result =
            check_got_entry(find, addr, symtab, strtab, dynsym_count, soname);
        if (result)
          return result;

        // Check PLTGOT
        if (pltgot != 0 && jmprel && jmprel_count > 0) {
          result = check_pltgot(find, pltgot, got_size, symtab, strtab, jmprel,
                                jmprel_count, jmprel_type, addr, soname);
          if (result)
            return result;
        }

        // Check JMPREL
        if (jmprel && jmprel_count > 0) {
          if (jmprel_type == 1) {
            result = check_relocations(find, addr, (Elf_Rel *)jmprel,
                                       jmprel_count, symtab, strtab, soname);
            if (result)
              return result;
          }
          if (jmprel_type == 2) {
            result = check_rela_relocations(find, addr, jmprel, jmprel_count,
                                            symtab, strtab, soname);
            if (result)
              return result;
          }
        }

        // Check relocations (REL)
        result = check_relocations(find, addr, rel, rel_count, symtab, strtab,
                                   soname);
        if (result)
          return result;

        // Check RELA relocations
        result = check_rela_relocations(find, addr, rela, rela_count, symtab,
                                        strtab, soname);
        if (result)
          return result;

        // Check regular symbols
        for (u32 j = 0; j < dynsym_count; j++) {
          Elf_Sym *sym = &symtab[j];

          if (sym->st_value == 0)
            continue;

          u64 sym_start = addr + sym->st_value;
          u64 sym_end =
              sym_start + (u64)((sym->st_size > 0) ? sym->st_size : 1);
          char *name = strtab + sym->st_name;
          mklog("symbol: 0x%lx-0x%lx %s", sym_start, sym_end, name);

          if (find >= sym_start && find < sym_end) {

            if (!name || name[0] == '\0')
              continue;

            u64 symoff = find - sym_start;

            if (symoff == 0) {
              return g_strdup_printf("%s!%s", soname ? soname : "unknown",
                                     name);
            }
            return g_strdup_printf("%s!%s+0x%lx", soname ? soname : "unknown",
                                   name, symoff);
          }
        }
      }
    }
  }

  return NULL;
}

char *resolve_address(u64 addr) {
  MapList *list = load_map_entries();
  if (!list)
    return NULL;

  char *result = NULL;

  MapEntry *entry;
  for (size_t i = 0; i < list->count; i++) {
    entry = &list->entries[i];
    if (addr >= entry->start && addr < entry->end) {
      // Find the base mapping for this module
      int j = i;
      MapEntry *start = &list->entries[j];

      while (j > 0 && strncmp(start->pathname, list->entries[j - 1].pathname,
                              256) == 0) {
        j--;
        start = &list->entries[j];
      }

      mklog("Base: %03d | 0x%lx-0x%lx %s", j, start->start, start->end,
            start->pathname);
      mklog("Found: %03d | 0x%lx-0x%lx %s", (int)i, entry->start, entry->end,
            entry->pathname);

      result = parse_elf(start->start, addr, list);
      break;
    }
  }

  free_map_list(list);
  return result;
}

static void mklog(const char *format, ...) {
  if (!DEBUG_LOG)
    return;
  gchar *message;
  va_list args;
  va_start(args, format);
  message = g_strdup_vprintf(format, args);
  va_end(args);
  frida_log(message);
  g_free(message);
}
