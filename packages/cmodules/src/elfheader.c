#include "glib.h"
#include <gum/guminterceptor.h>
#include <gum/gummemory.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEBUG_LOG 1

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
#define DT_FINI 13
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
#define ELF_ST_TYPE(info) ((info) & 0xf)

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
  Elf64_Xword r_offset;
  Elf64_Xword r_info;
  Elf64_Sxword r_addend;
} Elf64_Rela;

typedef struct elf64_rel {
  Elf64_Xword r_offset;
  Elf64_Xword r_info;
} Elf64_Rel;

typedef struct {
  Elf64_Sxword d_tag;
  union {
    Elf64_Xword d_val;
    Elf64_Addr d_ptr;
  } d_un;
} Elf64_Dyn;

typedef struct elf64_relr {
  Elf64_Xword r_data;
} Elf64_Relr;

typedef struct aarch64_stat_t {
  u64 st_dev;     /* Device ID */
  u64 st_ino;     /* Inode number */
  u32 st_mode;    /* File type and mode */
  u32 st_nlink;   /* Number of hard links */
  u32 st_uid;     /* User ID */
  u32 st_gid;     /* Group ID */
  u64 st_rdev;    /* Device ID (if special file) */
  u64 __pad1;     /* Padding for 8-byte alignment */
  s64 st_size;    /* Total size in bytes */
  s32 st_blksize; /* Block size for I/O */
  u32 __pad2;     /* Padding */
  s64 st_blocks;  /* Number of 512B blocks allocated */

  /* Timestamps */
  s64 st_atime;    /* Access time (seconds) */
  u64 st_atime_ns; /* Access time (nanoseconds) */
  s64 st_mtime;    /* Modification time (seconds) */
  u64 st_mtime_ns; /* Modification time (nanoseconds) */
  s64 st_ctime;    /* Status change time (seconds) */
  u64 st_ctime_ns; /* Status change time (nanoseconds) */

  u32 __unused[2]; /* Reserved for future use */
} stat_t;

typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Sym Elf_Sym;
typedef Elf64_Dyn Elf_Dyn;
typedef Elf64_Rela Elf_Rela;
typedef Elf64_Rel Elf_Rel;
typedef Elf64_Relr Elf_Relr;

#define ELF64_R_SYM(i) ((i) >> 32)
#define ELF64_R_TYPE(i) ((i) & 0xffffffffL)
#define ELF64_ST_BIND(info) ((info) >> 4)
#define ELF64_ST_TYPE(info) ((info) & 0xf)
#define MIN_ZERO(a, b) ((a) > (b) ? ((a) - (b)) : 0)

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

extern int stat(const char *pathname, stat_t *statbuf);
extern FILE *fopen(const char *pathname, const char *mode);
extern int fseek(FILE *stream, long offset, int origin);
extern size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
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

int hex_len(u64 n) {
  if (n == 0)
    return 1;
  int len = 0;
  while (n > 0) {
    n >>= 4;
    len += 1;
  }
  return len;
}
int dec_len(u64 n) {
  if (n == 0)
    return 1;
  int len = 0;
  while (n > 0) {
    n /= 10;
    len += 1;
  }
  return len;
}

const char *get_pt_type_name(long p) {
  switch (p) {
  case 1:
    return "PT_LOAD";
  case 2:
    return "PT_DYNAMIC";
  case 3:
    return "PT_INTERP";
  case 4:
    return "PT_NOTE";
  case 6:
    return "PT_PHDR";
  case 7:
    return "PT_TLS";
  case 0x6474e550:
    return "PT_GNU_EH_FRAME";
  case 0x6474e551:
    return "PT_GNU_STACK";
  case 0x6474e552:
    return "PT_GNU_RELRO";
  default:
    return "DT_UNKNOWN";
  }
}

char *get_pt_type_text(long p) {
  const char *name = get_pt_type_name(p);
  return g_strdup_printf((p > 100) ? "%s(0x%x)" : "%s(%d)", name, p);
}

const char *get_dt_type_name(long tag) {
  switch (tag) {
  /* Standard System V Tags */
  case 0:
    return "DT_NULL";
  case 1:
    return "DT_NEEDED";
  case 2:
    return "DT_PLTRELSZ";
  case 3:
    return "DT_PLTGOT";
  case 4:
    return "DT_HASH";
  case 5:
    return "DT_STRTAB";
  case 6:
    return "DT_SYMTAB";
  case 7:
    return "DT_RELA";
  case 8:
    return "DT_RELASZ";
  case 9:
    return "DT_RELAENT";
  case 10:
    return "DT_STRSZ";
  case 11:
    return "DT_SYMENT";
  case 12:
    return "DT_INIT";
  case 13:
    return "DT_FINI";
  case 14:
    return "DT_SONAME";
  case 15:
    return "DT_RPATH";
  case 16:
    return "DT_SYMBOLIC";
  case 17:
    return "DT_REL";
  case 18:
    return "DT_RELSZ";
  case 19:
    return "DT_RELENT";
  case 20:
    return "DT_PLTREL";
  case 21:
    return "DT_DEBUG";
  case 22:
    return "DT_TEXTREL";
  case 23:
    return "DT_JMPREL";
  case 24:
    return "DT_BIND_NOW";
  case 25:
    return "DT_INIT_ARRAY";
  case 26:
    return "DT_FINI_ARRAY";
  case 27:
    return "DT_INIT_ARRAYSZ";
  case 28:
    return "DT_FINI_ARRAYSZ";
  case 29:
    return "DT_RUNPATH";
  case 30:
    return "DT_FLAGS";

  /* Modern Relative Relocations (SHT_RELR) */
  case 35:
    return "DT_RELRSZ";
  case 36:
    return "DT_RELR";
  case 37:
    return "DT_RELRENT";

  /* Android Specific Extensions */
  case 0x6000000f:
    return "DT_ANDROID_REL";
  case 0x60000010:
    return "DT_ANDROID_RELSZ";
  case 0x60000011:
    return "DT_ANDROID_RELA";
  case 0x60000012:
    return "DT_ANDROID_RELASZ";

  /* GNU / OS Specific Extensions */
  case 0x6ffffef5:
    return "DT_GNU_HASH";
  case 0x6ffffef6:
    return "DT_TLSDESC_PLT";
  case 0x6ffffef7:
    return "DT_TLSDESC_GOT";
  case 0x6ffffff9:
    return "DT_RELACOUNT";
  case 0x6ffffff8:
    return "DT_RELCOUNT";
  case 0x6ffffffb:
    return "DT_FLAGS_1";
  case 0x6ffffff0:
    return "DT_VERSYM";
  case 0x6ffffffe:
    return "DT_VERNEED";
  case 0x6fffffff:
    return "DT_VERNEEDNUM";
  case 0x6ffffffc:
    return "DT_VERDEF";
  case 0x6ffffffd:
    return "DT_VERDEFNUM";

  default:
    return "DT_UNKNOWN";
  }
}

static int64_t read_sleb128(const uint8_t **ptr) {
  const uint8_t *p = *ptr;
  int64_t value = 0;
  int shift = 0;
  uint8_t byte;

  do {
    byte = *p++;
    value |= (int64_t)(byte & 0x7f) << shift;
    shift += 7;
  } while (byte & 0x80);

  /* Sign extend if negative */
  if (shift < 64 && (byte & 0x40)) {
    value |= -(1LL << shift);
  }

  *ptr = p;
  return value;
}

static uint64_t read_uleb128(const uint8_t **ptr) {
  const uint8_t *p = *ptr;
  uint64_t value = 0;
  int shift = 0;
  uint8_t byte;

  do {
    byte = *p++;
    // Extract the low 7 bits and shift them into the correct position
    value |= (uint64_t)(byte & 0x7f) << shift;
    shift += 7;
  } while (byte & 0x80); // Continue if the continuation bit (0x80) is set

  *ptr = p;
  return value;
}

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

  // The PLTGOT layout is typically:
  // [0] = address of _DYNAMIC
  // [1] = link_map pointer
  // [2] = dl_runtime_resolve
  // [3+] = GOT entries for PLT

  u64 *got = (u64 *)pltgot_addr;
  u64 got_end = pltgot_addr + got_size;
  mklog("Checking PLTGOT at 0x%lx-0x%lx for address 0x%lx", pltgot_addr,
        got_end, addr);

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
  mklog("check_rel_relocations: 0x%lx - %d | sym: 0x%lx str: 0x%lx", rel,
        rel_count, symtab, strtab);
  if (!rel || !symtab || !strtab)
    return NULL;

  for (int i = 0; i < rel_count; i += 1) {
    Elf64_Rel *r = &rel[i];
    u64 reloc_addr = base_addr + r->r_offset;
    u32 sym_idx = ELF64_R_SYM(rel[i].r_info);
    Elf_Sym *sym = &symtab[sym_idx];
    char *name = strtab + sym->st_name;
    mklog("rel: 0x%lx offset: 0x%lx sym_idx: %d %s", reloc_addr, r->r_offset,
          sym_idx, name);

    // Check if the address matches this relocation
    if (addr == reloc_addr) {
      if (name && name[0] != '\0') {
        return g_strdup_printf("%s!%s@rel", soname ? soname : "unknown", name);
      }
      return g_strdup_printf("%s!0x%lx@rel", soname ? soname : "unknown",
                             r->r_offset);
    }
  }

  return NULL;
}

// Check if address is in a RELA relocation entry
static char *check_rela_relocations(u64 addr, u64 base_addr, Elf_Rela *rela,
                                    int rela_count, Elf_Sym *symtab,
                                    char *strtab, const char *soname) {
  mklog("check_rela_relocations: 0x%lx - %d | sym: 0x%lx str: 0x%lx", rela,
        rela_count, symtab, strtab);
  if (!rela || !symtab || !strtab)
    return NULL;

  for (int i = 0; i < rela_count; i += 1) {
    Elf64_Rela *r = &rela[i];
    u64 reloc_addr = base_addr + r->r_offset;
    u32 sym_idx = ELF64_R_SYM(r->r_info);
    Elf_Sym *sym = &symtab[sym_idx];
    char *name = strtab + sym->st_name;
    mklog("rela: 0x%lx offset: 0x%lx sym_idx: %d %s", reloc_addr, r->r_offset,
          sym_idx, name);

    // Check if the address matches this relocation
    if (addr == reloc_addr) {
      if (name && name[0] != '\0') {
        if (r->r_addend != 0) {
          return g_strdup_printf("%s!%s+0x%lx@rela",
                                 soname ? soname : "unknown", name,
                                 r->r_addend);
        }
        return g_strdup_printf("%s!%s@rela", soname ? soname : "unknown", name);
      }
      if (r->r_addend != 0) {
        return g_strdup_printf("%s!0x%lx+0x%lx@rela",
                               soname ? soname : "unknown", r->r_offset,
                               r->r_addend);
      }
      return g_strdup_printf("%s!0x%lx@rela", soname ? soname : "unknown",
                             r->r_offset);
    }
  }

  return NULL;
}

static char *check_android_relocs(u64 addr, u64 base_addr, void *_packed_data,
                                  size_t packed_size, int is_rela,
                                  Elf_Sym *symtab, char *strtab,
                                  const char *soname) {
  const RELOCATION_GROUPED_BY_INFO_FLAG = 1;
  const RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG = 2;
  const RELOCATION_GROUPED_BY_ADDEND_FLAG = 4;
  const RELOCATION_GROUP_HAS_ADDEND_FLAG = 8;

  mklog("check_android_%s: 0x%lx-0x%lx | sym: 0x%lx str: 0x%lx",
        is_rela ? "rela" : "rel", (u64)_packed_data,
        (u64)_packed_data + (u64)packed_size, symtab, strtab);
  if (!_packed_data || !symtab || !strtab)
    return NULL;

  u8 **packed_data = (u8 **)_packed_data;
  u8 *current = (u8 *)_packed_data;
  u8 *end = (u8 *)(void *)((u64)_packed_data + (u64)packed_size);

  // 1. Read Header: Number of Relocations
  u64 num_relocs = (u64)read_uleb128(&current);
  mklog("check_android_%s: count = %d", is_rela ? "rela" : "rel", num_relocs);

  // 2. Read Initial Offset
  Elf64_Addr r_offset = (Elf64_Addr)read_sleb128(&current);

  size_t processed_count = 0;

  // 3. Iterate over Relocation Groups
  while (processed_count < num_relocs && current < end) {
    // Group Header
    size_t group_size = (size_t)read_sleb128(&current);
    size_t group_flags = (size_t)read_sleb128(&current);

    size_t group_r_offset_delta = 0;
    Elf64_Xword r_info = 0;
    int64_t r_addend = 0;

    // READ: Grouped Offset Delta (if applicable)
    if (group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) {
      group_r_offset_delta = (size_t)read_sleb128(&current);
    }

    // READ: Grouped Info (if applicable)
    if (group_flags & RELOCATION_GROUPED_BY_INFO_FLAG) {
      r_info = (Elf64_Sxword)read_sleb128(&current);
    }

    // READ: Grouped Addend (if applicable - ONLY for RELA)
    if (is_rela) {
      if ((group_flags & RELOCATION_GROUPED_BY_ADDEND_FLAG) &&
          (group_flags & RELOCATION_GROUP_HAS_ADDEND_FLAG)) {
        // Delta is global for the group
        r_addend += read_sleb128(&current);
      } else if ((group_flags & RELOCATION_GROUP_HAS_ADDEND_FLAG) == 0) {
        // No addend for this group
        r_addend = 0;
      }
    }

    // 4. Expand relocations within the group
    for (size_t i = 0; processed_count < num_relocs && i < group_size; i += 1) {
      // CALC: Offset
      if (group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) {
        r_offset += group_r_offset_delta;
      } else {
        r_offset += (Elf64_Addr)read_sleb128(&current);
      }

      // CALC: Info
      if ((group_flags & RELOCATION_GROUPED_BY_INFO_FLAG) == 0) {
        r_info = (Elf64_Sxword)read_sleb128(&current);
      }

      // CALC: Addend (only if RELA and not grouped)
      if (is_rela && (group_flags & RELOCATION_GROUP_HAS_ADDEND_FLAG)) {
        if ((group_flags & RELOCATION_GROUPED_BY_ADDEND_FLAG) == 0) {
          r_addend += read_sleb128(&current);
        }
      }

      // --- PROCESS THE RELOCATION HERE ---
      processed_count += 1;

      u64 reloc_addr = base_addr + r_offset;
      u32 sym_idx = ELF64_R_SYM(r_info);
      Elf_Sym *sym = &symtab[sym_idx];
      char *name = strtab + sym->st_name;
      mklog("android_%s: 0x%lx offset: 0x%lx sym_idx: %d %s",
            is_rela ? "rela" : "rel", reloc_addr, r_offset, sym_idx, name);
      if (addr == reloc_addr) {
        if (name && name[0] != '\0') {
          if (r_addend != 0) {
            return g_strdup_printf("%s!%s+0x%lx@android_%s",
                                   soname ? soname : "unknown", name, r_addend,
                                   is_rela ? "rela" : "rel");
          }
          return g_strdup_printf("%s!%s@android_%s",
                                 soname ? soname : "unknown", name,
                                 is_rela ? "rela" : "rel");
        }

        if (r_addend != 0) {
          return g_strdup_printf("%s!0x%lx+0x%lx@android_%s",
                                 soname ? soname : "unknown", r_offset,
                                 r_addend, is_rela ? "rela" : "rel");
        }
        return g_strdup_printf("%s!0x%lx@android_%s",
                               soname ? soname : "unknown", r_offset,
                               is_rela ? "rela" : "rel");
      }
      // (u64) r_offset, (unsigned long)ELF_R_TYPE(r_info),
      // (unsigned long)ELF_R_SYM(r_info));
      // printf(", Addend=%ld", (long)r_addend);
    }
  }

  return NULL;
}

static char *check_symbol(u64 addr, u64 base_addr, Elf_Sym *sym, int is_dyn,
                          char *strtab, const char *soname) {

  if (sym->st_value == 0)
    return NULL;

  u64 sym_start = base_addr + sym->st_value;
  u64 sym_end = sym_start + sym->st_size;
  u16 st_type = ELF64_ST_TYPE(sym->st_info);
  char *name = (char *)(void *)((u64)strtab + (u64)sym->st_name);
  mklog("%s: 0x%lx-0x%lx st_type: %2d st_size: %5d st_name: %s",
        is_dyn ? "dynsym" : "symbol", sym_start, sym_end, st_type, sym->st_size,
        name);
  if (st_type == 0)
    return NULL;

  if (addr >= sym_start && (sym_start == sym_end || addr < sym_end)) {
    u64 symoff = addr - sym_start;
    if (name && name[0] != '\0') {
      if (symoff != 0) {
        return g_strdup_printf("%s!%s+0x%lx@%s", soname ? soname : "unknown",
                               name, symoff, is_dyn ? "dynsym" : "sym");
      }
      return g_strdup_printf("%s!%s@%s", soname ? soname : "unknown", name,
                             is_dyn ? "dynsym" : "sym");
    }

    if (symoff != 0) {
      return g_strdup_printf("%s!0x%lx+0x%lx@%s", soname ? soname : "unknown",
                             sym->st_value, symoff, is_dyn ? "dynsym" : "sym");
    }
    return g_strdup_printf("%s!0x%lx@%s", soname ? soname : "unknown",
                           sym->st_value, is_dyn ? "dynsym" : "sym");
  }
  return NULL;
}

static char *parse_elf(MapEntry *m_entry, u64 find, MapList *list) {
  // Parse ELF
  u64 base_addr = m_entry->start;
  Elf_Ehdr *ehdr = (Elf_Ehdr *)base_addr;
  if (ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E' ||
      ehdr->e_ident[2] != 'L' || ehdr->e_ident[3] != 'F')
    return NULL;

  mklog("ehdr: 0x%lx ~ ph: %d * 0x%x @ +0x%lx ~ sh: %d * 0x%x @ +0x%lx",
        base_addr, ehdr->e_phnum, ehdr->e_phentsize, ehdr->e_phoff,
        ehdr->e_shnum, ehdr->e_shentsize, ehdr->e_shoff);

  Elf_Phdr *phdrs = (Elf_Phdr *)(base_addr + ehdr->e_phoff);

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
  char *soname = NULL;
  char *result = NULL;

  for (int i = 0; i < ehdr->e_phnum; i += 1) {
    Elf_Phdr *phdr = &phdrs[i];
    char *p_type_text = get_pt_type_text(phdr->p_type);
    char *addr_of = addressOf((void *)phdr);
    mklog("phdr: p_flags: %c%c%c p_offset: 0x%08lx p_vaddr: 0x%08lx p_paddr: "
          "0x%08lx "
          "p_filesz: "
          "%6d p_memsz: %6d p_align: 0x%04lx p_type: %s @ %s",
          phdr->p_flags & 4 ? 'r' : '-', phdr->p_flags & 2 ? 'w' : '-',
          phdr->p_flags & 1 ? 'x' : '-', (u64)phdr->p_offset,
          (u64)phdr->p_vaddr, (u64)phdr->p_paddr, (u64)phdr->p_filesz,
          (u64)phdr->p_memsz, (u64)phdr->p_align, p_type_text, addr_of);

    if ((int)phdr->p_type == PT_DYNAMIC) {
      Elf_Dyn *dyn = (Elf_Dyn *)(base_addr + phdr->p_offset);
      mklog("dyn: 0x%lx | %s", dyn, addressOf((void *)dyn));

      size_t syment = 0, relaent = 0, rela_size = 0;
      size_t relent = 0, rel_size = 0;
      size_t jmprel_size = 0;
      size_t relrent = 0, relr_size = 0;
      void *android_rel = 0;
      void *android_rela = 0;
      size_t android_rel_size = 0, android_rela_size = 0;
      u64 offsoname = 0;

      while (dyn->d_tag != DT_NULL) {
        mklog((dyn->d_tag > 100) ? "dyn->d_tag = 0x%08lx : 0x%08lx | %s"
                                 : "dyn->d_tag = 0x%08lx : %10d | %s",
              dyn->d_un, dyn->d_tag, get_dt_type_name(dyn->d_tag));
        switch (dyn->d_tag) {
        case DT_SONAME:
          offsoname = dyn->d_un.d_val;
          break;
        case DT_SYMTAB:
          symtab = (Elf_Sym *)(base_addr + dyn->d_un.d_ptr);
          break;
        case DT_STRTAB:
          strtab = (char *)(base_addr + dyn->d_un.d_ptr);
          break;
        case DT_SYMENT:
          syment = dyn->d_un.d_val;
          break;
        case DT_RELA:
          rela = (Elf_Rela *)(base_addr + dyn->d_un.d_ptr);
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
          rel = (Elf_Rel *)(base_addr + dyn->d_un.d_ptr);
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
          jmprel = (Elf_Rela *)(base_addr + dyn->d_un.d_ptr);
          break;
        case DT_PLTRELSZ:
          jmprel_size = dyn->d_un.d_val;
          break;
        case DT_PLTREL:
          pltrel_type = dyn->d_un.d_val; // DT_REL=17 or DT_RELA=7
          break;
        case DT_PLTGOT:
          pltgot = base_addr + dyn->d_un.d_ptr;
          break;
        case DT_RELR:
          relr = (Elf_Relr *)(base_addr + dyn->d_un.d_ptr);
          break;
        case DT_RELRSZ:
          relr_size = dyn->d_un.d_val;
          break;
        case DT_RELRENT:
          relrent = dyn->d_un.d_val;
          break;
        case DT_ANDROID_REL:
          android_rel = (void *)(base_addr + dyn->d_un.d_ptr);
          break;
        case DT_ANDROID_RELSZ:
          android_rel_size = dyn->d_un.d_val;
          break;
        case DT_ANDROID_RELA:
          android_rela = (void *)(base_addr + dyn->d_un.d_ptr);
          break;
        case DT_ANDROID_RELASZ:
          android_rela_size = dyn->d_un.d_val;
          break;
        case DT_GNU_HASH:
          dynsym_count = find_max_sym_index(base_addr + dyn->d_un.d_ptr);
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
          got_size = max_got_offset - (pltgot - base_addr) + 16;
          mklog("Calculated GOT size: 0x%lx (based on max offset 0x%lx)",
                got_size, max_got_offset);
        }
        if (rela && rela_count > 0) {
          for (int i = 0; i < rela_count; i++) {
            u64 reloc_offset = rela[i].r_offset;
            u64 reloc_addr = base_addr + reloc_offset;

            // If this relocation is in the GOT area, update size
            if (reloc_addr >= pltgot && reloc_offset > max_got_offset) {
              max_got_offset = reloc_offset;
              got_size = max_got_offset - (pltgot - base_addr) + 16;
            }
          }
        }
        if (rel && rel_count > 0) {
          for (int i = 0; i < rel_count; i++) {
            u64 reloc_offset = rel[i].r_offset;
            u64 reloc_addr = base_addr + reloc_offset;

            if (reloc_addr >= pltgot && reloc_offset > max_got_offset) {
              max_got_offset = reloc_offset;
              got_size = max_got_offset - (pltgot - base_addr) + 16;
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
        result = check_got_entry(find, base_addr, symtab, strtab, dynsym_count,
                                 soname);
        if (result)
          return result;

        // Check PLTGOT
        if (pltgot != 0 && jmprel && jmprel_count > 0) {
          result = check_pltgot(find, pltgot, got_size, symtab, strtab, jmprel,
                                jmprel_count, jmprel_type, base_addr, soname);
          if (result)
            return result;
        }

        // Check JMPREL
        mklog("jmp relocs: %d", jmprel_type);
        if (jmprel && jmprel_count > 0) {
          if (jmprel_type == 1) {
            result = check_relocations(find, base_addr, (Elf_Rel *)jmprel,
                                       jmprel_count, symtab, strtab, soname);
            if (result)
              return result;
          }
          if (jmprel_type == 2) {
            result = check_rela_relocations(
                find, base_addr, jmprel, jmprel_count, symtab, strtab, soname);
            if (result)
              return result;
          }
        }
        mklog("normal relocs: rel: 0x%lx rela: 0x%lx",
              MIN_ZERO((u64)rel, base_addr), MIN_ZERO((u64)rela, base_addr));

        // Check relocations (REL)
        result = check_relocations(find, base_addr, rel, rel_count, symtab,
                                   strtab, soname);
        if (result)
          return result;

        // Check RELA relocations
        result = check_rela_relocations(find, base_addr, rela, rela_count,
                                        symtab, strtab, soname);
        if (result)
          return result;

        mklog("android relocs: rel: 0x%lx rela: 0x%lx",
              MIN_ZERO((u64)android_rel, base_addr),
              MIN_ZERO((u64)android_rela, base_addr));

        result =
            check_android_relocs(find, base_addr, android_rel, android_rel_size,
                                 FALSE, symtab, strtab, soname);
        if (result)
          return result;

        result = check_android_relocs(find, base_addr, android_rela,
                                      android_rela_size, TRUE, symtab, strtab,
                                      soname);
        if (result)
          return result;

        // Check regular symbols
        for (u32 j = 0; j < dynsym_count; j += 1) {
          Elf_Sym *sym = &symtab[j];
          result = check_symbol(find, base_addr, sym, TRUE, strtab, soname);
          if (result)
            return result;
        }
      }
    }
  }

  mklog("%s", m_entry->pathname);
  Elf_Shdr *shdrs = malloc((size_t)ehdr->e_shnum * sizeof(Elf_Shdr));
  stat_t st;
  stat(m_entry->pathname, &st);
  FILE *elf_file = fopen(m_entry->pathname, "rb");
  if (!elf_file) {
    free(shdrs);
    return NULL;
  }
  if (fseek(elf_file, ehdr->e_shoff, 0) != 0) {
    mklog("fseek failed: %s @ +0x%lx", m_entry->pathname, ehdr->e_shoff);
    free(shdrs);
    fclose(elf_file);
    return NULL;
  }
  if (fread(shdrs, sizeof(Elf_Shdr), ehdr->e_shnum, elf_file) !=
      ehdr->e_shnum) {
    mklog("fread failed: %s @ +0x%lx", m_entry->pathname, ehdr->e_shoff);
    free(shdrs);
    fclose(elf_file);
    return NULL;
  }
  Elf_Shdr *shstr_shdr = &shdrs[ehdr->e_shstrndx];
  char *shstrtab = malloc(shstr_shdr->sh_size);
  if (fseek(elf_file, shstr_shdr->sh_offset, 0) != 0 ||
      fread(shstrtab, 1, shstr_shdr->sh_size, elf_file) !=
          shstr_shdr->sh_size) {
    mklog("shstrtab table failed: %s @ +0x%lx e_shstrndx: %d",
          m_entry->pathname, shstr_shdr->sh_offset, ehdr->e_shstrndx);
    free(shdrs);
    free(shstrtab);
    fclose(elf_file);
    return NULL;
  }

  char **shstrtab_copy = malloc(shstr_shdr->sh_size);
  size_t shstrname_max = 0, counting = 0;
  for (int i = 0; i < shstr_shdr->sh_size; i += 1) {
    char c = shstrtab[i];
    if (c == '\0') {
      shstrname_max = shstrname_max > counting ? shstrname_max : counting;
      counting = 0;
    } else {
      counting += 1;
    }
    ((char *)(shstrtab_copy))[i] = c == '\0' ? ' ' : c;
  }
  shstrtab_copy[shstr_shdr->sh_size - 1] = '\0';

  mklog("shstrtab: offset: 0x%lx ndx: %d sz: %d | %s", shstr_shdr->sh_offset,
        ehdr->e_shstrndx, shstr_shdr->sh_size, shstrtab_copy);

  Elf_Shdr *sh_sym = NULL;
  Elf_Shdr *sh_str = NULL;
  for (int i = 0; i < (int)ehdr->e_shnum; i += 1) {
    Elf_Shdr *shdr = &shdrs[i];
    char *sh_name = (char *)((u64)shstrtab + (u64)shdr->sh_name);
    char *sh_type = g_strdup_printf((int)shdr->sh_type > 100 ? "0x%lx" : "%d",
                                    (int)shdr->sh_type);
    mklog("shdr: %-*s sh_type: %10s sh_flags: %c%c%c%c%c%c sh_addr: %*s0x%lx "
          "sh_size: %*d sh_offset: %*s0x%lx",
          shstrname_max, sh_name, sh_type, shdr->sh_flags & 0x40 ? 'I' : ' ',
          shdr->sh_flags & 0x20 ? 'S' : ' ', shdr->sh_flags & 0x10 ? 'M' : ' ',
          shdr->sh_flags & 0x4 ? 'X' : ' ', shdr->sh_flags & 0x2 ? 'A' : ' ',
          shdr->sh_flags & 0x1 ? 'W' : ' ',
          hex_len(st.st_size) - hex_len(shdr->sh_addr), "", shdr->sh_addr,
          dec_len(st.st_size), shdr->sh_size,
          hex_len(st.st_size) - hex_len(shdr->sh_offset), "", shdr->sh_offset);

    // .symtab
    if (!sh_sym && shdr->sh_type == 2) {
      sh_sym = &shdrs[i];
    }

    // .strtab
    if (!sh_str && shdr->sh_type == 3 && shdr->sh_flags == 0 &&
        i != ehdr->e_shstrndx) {
      sh_str = &shdrs[i];
    }
  }

  if (sh_sym != NULL && sh_str != NULL) {
    // .symtab
    size_t sym_count = sh_sym->sh_size / sizeof(Elf_Sym);
    u64 sym_start = sh_sym->sh_offset;
    Elf_Sym *symtab = malloc(sh_sym->sh_size);
    if (fseek(elf_file, sym_start, 0) != 0 ||
        fread(symtab, sizeof(Elf_Sym), sym_count, elf_file) != sym_count) {
      mklog("symtab table failed: %s @ +0x%lx count: %d", m_entry->pathname,
            sym_start, sym_count);
      free(shdrs);
      free(shstrtab);
      free(symtab);
      fclose(elf_file);
      return NULL;
    }
    mklog("symtab: offset: 0x%lx count: %d", sym_start, sym_count);

    u64 staticstr_start = sh_str->sh_offset;
    char *staticstrtab = malloc(sh_str->sh_size);
    if (fseek(elf_file, staticstr_start, 0) != 0 ||
        fread(staticstrtab, 1, sh_str->sh_size, elf_file) != sh_str->sh_size) {
      mklog("strtab table failed: %s @ +0x%lx sz: %d", m_entry->pathname,
            staticstr_start, sh_str->sh_size);
      free(shdrs);
      free(shstrtab);
      free(symtab);
      free(staticstrtab);
      fclose(elf_file);
      return NULL;
    }
    mklog("strtab: offset: 0x%lx sz: %d", staticstr_start, sh_str->sh_size);
    for (int i = 0; i < sym_count; i += 1) {
      Elf_Sym *sym = &symtab[i];
      result = check_symbol(find, base_addr, sym, FALSE, staticstrtab, soname);
      if (result) {
        free(shdrs);
        free(shstrtab);
        free(symtab);
        free(staticstrtab);
        fclose(elf_file);
        return result;
      }
    }

    free(symtab);
    free(staticstrtab);
  }

  free(shdrs);
  free(shstrtab);
  fclose(elf_file);

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
    mklog("maps: %03d | 0x%lx-0x%lx %s", (int)i, entry->start, entry->end,
          entry->pathname);
    if (addr >= entry->start && addr < entry->end) {
      // Find the base mapping for this module
      int j = i;
      MapEntry *start = &list->entries[j];

      while (j > 0 && strncmp(start->pathname, list->entries[j - 1].pathname,
                              256) == 0) {
        j--;
        start = &list->entries[j];
      }

      mklog("base: %03d | 0x%lx-0x%lx %s", j, start->start, start->end,
            start->pathname);
      mklog("found: %03d | 0x%lx-0x%lx %s", (int)i, entry->start, entry->end,
            entry->pathname);

      result = parse_elf(start, addr, list);
      break;
    }
  }

  free_map_list(list);
  return result;
}

static void mklog(const char *format, ...) {
  if (DEBUG_LOG == 0)
    return;
  gchar *message;
  va_list args;
  va_start(args, format);
  message = g_strdup_vprintf(format, args);
  va_end(args);
  frida_log(message);
  g_free(message);
}
