#include "glib.h"
#include <gum/guminterceptor.h>
#include <gum/gumprocess.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long long u64;

extern void frida_log(void *str);
static void mklog(const char *format, ...) {
  gchar *message;
  va_list args;
  va_start(args, format);
  message = g_strdup_vprintf(format, args);
  va_end(args);
  frida_log(message);
  g_free(message);
}

typedef struct {
  const char *phdr;
  size_t phnum;
  uint64_t base;
  size_t size;
  void *dynamic;
  void *next;
} so_info;

typedef struct {
  so_info *info;
  const char *name;
} lib_info;

typedef struct {
  char *dli_fname;
  void *dli_fbase;
  char *dli_sname;
  void *dli_saddr;
} dl_info;

typedef struct {
  uint64_t start;
  uint64_t end;
  char mode[5];
  char name[256];
} mem_info;

typedef struct {
  mem_info *data;
  size_t size;
  size_t capacity;
} mem_list;

typedef struct {
  u64 base;
  u64 size;
} mem_range;

mem_list new_mem_list() {
  const size_t initial_capacity = 3200;
  mem_list list;
  list.data = g_malloc(initial_capacity * sizeof(mem_info));
  list.size = 0;
  list.capacity = initial_capacity;
  return list;
}

void mem_list_add(mem_list list, mem_info *element) {
  if (list.size == list.capacity) {
    list.capacity *= 2;
    list.data = g_realloc(list.data, list.capacity * sizeof(mem_info));
  };
  list.data[list.size += 1] = *element;
};

void mem_list_free(mem_list *list) {
  if (list) {
    g_free(list->data);
    g_free(list);
  }
}

typedef struct {
  uintptr_t *frames;
  size_t frame_count;
  size_t max_frames;
} backtrace_state;

#define MAX_FRAMES 32
#define LOG_TAG "FridaBacktracer"

extern void *getranges();
extern char *__cxa_demangle(const char *__mangled_name, char *__output_buffer,
                            size_t *__length, int *__status);
extern char *dl_soinfo_get_soname(so_info *info);
extern so_info *dl_solist_get_head();
extern int sprintf(char *str, const char *format, ...);
extern int isprint(int ch);
extern int close(int fd);
extern int fclose(FILE *stream);
extern FILE *fdopen(int fildes, const char *options);
extern char *fgets(char *str, int n, FILE *stream);
extern char *strchr(const char *str, int z);
extern char *strcpy(char *destination, const char *source);
extern char *strrchr(const char *, int);
extern size_t strlen(const char *str);
extern char *strtok_r(char *str, const char *delim, char **saveptr);
extern unsigned long strtoul(const char *__s, char **__end_ptr, int __base);
extern char *strdup(const char *str1);
extern long syscall(long __number, ...);
extern int dladdr(const void *addr, dl_info *info);

// Helper to find soinfo for an address
static so_info *find_soinfo_for_address(void *_addr) {
  if (_addr == NULL)
    return NULL;
  uint64_t addr = (uint64_t)_addr;
  for (so_info *si = dl_solist_get_head(); si != NULL; si = si->next) {
    if (addr >= si->base && addr < (si->base + si->size)) {
      return si;
    }
  }
  return NULL;
}

static lib_info *find_lib_info(void *_addr) {
  so_info *info = find_soinfo_for_address(_addr);
  if (!info)
    return NULL;
  lib_info *lib = g_malloc(sizeof(lib_info));
  lib->info = info;
  lib->name = dl_soinfo_get_soname(info);
  return lib;
}

static int mem_list_size = 0;
static mem_list *read_proc_maps() {
  register uint64_t start, end;
  char line[512];

  int fd = syscall(56, 0, "/proc/self/maps", 0, 0);
  FILE *fp = fdopen(fd, "r");
  if (!fp)
    return NULL;

  char *token, *saveptr;
  mem_list list = new_mem_list();
  while (fgets(line, 0x400, fp) != NULL) {
    token = strtok_r(line, "-", &saveptr);
    start = (uint64_t)strtoul(token, NULL, 16);

    token = strtok_r(NULL, " ", &saveptr);
    end = (uint64_t)strtoul(token, NULL, 16);

    token = strtok_r(NULL, " ", &saveptr);

    mem_info mem = list.data[list.size++];
    mem.start = start;
    mem.end = end;
    __builtin_memcpy(mem.mode, token, 4);
    mem.mode[4] = 0;

    char *nameptr = strchr(saveptr, '/');
    if (nameptr != NULL) {
      strcpy(mem.name, nameptr);
      mem.name[strlen(nameptr)] = 0;
    }
  }

  fclose(fp);
  close(fd);

  return &list;
}

static mem_info *find_mem_info(mem_list *list, void *_addr) {
  if (_addr == NULL)
    return NULL;
  uint64_t addr = (uint64_t)_addr;
  for (int i = 0; i < mem_list_size; i++) {
    mem_info entry = list->data[i];
    if (addr >= entry.start && addr < entry.end) {
      return &entry;
    }
  }
  return NULL;
}

static dl_info *find_dl_info(void *_addr) {
  if (_addr == NULL)
    return NULL;
  dl_info *info = g_malloc(sizeof(dl_info));
  int ret = dladdr(_addr, info);
  return (ret != 0) ? info : NULL;
}

void backtrace_v0() {
  uint64_t retaddr =
      (uint64_t)__builtin_extract_return_addr(__builtin_return_address(0));
  uintptr_t *frame_ptr = (uintptr_t *)__builtin_frame_address(0);

  mem_list *mem_list = read_proc_maps();
  int depth = 0;
  while (frame_ptr != NULL && depth < 10) {
    void *return_addr = (void *)*(frame_ptr + 1);
    if (!return_addr)
      break;

    lib_info *lib = find_lib_info(return_addr);
    mem_info *mem = find_mem_info(mem_list, return_addr);
    dl_info *dl = find_dl_info(return_addr);

    frame_ptr = (uintptr_t *)*frame_ptr;

    // Basic sanity check for frame pointer
    if ((uintptr_t)frame_ptr & 0x7)
      break;

    depth += 1;
  }
  mem_list_free(mem_list);
}

// init functios
void init(void) {}

void finalize(void) {}

// Export our main functios
char *get_backtrace(void *addr) {
  lib_info *lib = find_lib_info(addr);
  if (lib) {
    return g_strdup_printf("%p %s", lib, lib->name);
  }
  dl_info *dl = find_dl_info(addr);
  if (dl) {
    return g_strdup_printf("%s %s 0x%x 0x%x", dl->dli_fname, dl->dli_sname,
                           dl->dli_fbase, dl->dli_saddr);
  }
  mem_list *list = (mem_list *)read_proc_maps();
  mem_info *mem = find_mem_info(list, addr);
  if (mem) {
    mem_list_free(list);
    return g_strdup_printf("0x%x-0x%x %s %s", mem->start, mem->end, mem->mode,
                           mem->name);
  }
  mem_list_free(list);
  return "v0";
}

void hex_dump(const void *ptr, size_t x) {
  const unsigned char *p = ptr;
  size_t i, j;
  char line[100];

  // mklog("Offset    | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F |
  // ASCII");
  for (i = 0; i < x; i += 16) {
    char *pos = line;
    pos += sprintf(pos, "0x%08zx | ", i);

    for (j = 0; j < 16; j++) {
      if (i + j < x)
        pos += sprintf(pos, "%02x ", p[i + j]);
      else
        pos += sprintf(pos, "   ");
    }

    pos += sprintf(pos, "| ");
    for (j = 0; j < 16; j++) {
      if (i + j < x) {
        unsigned char c = p[i + j];
        pos += sprintf(pos, "%c", isprint(c) ? c : '.');
      } else {
        pos += sprintf(pos, " ");
      }
    }

    mklog("%s", line);
  }

  mklog("-----------+-------------------------------------------------+--------"
        "---------");
}

char *addressOf(void *addr) {
  dl_info *dl = find_dl_info(addr);
  if (dl) {
    uint64_t foffset = addr - dl->dli_fbase;
    uint64_t soffset = addr - dl->dli_saddr;
    char *name = strrchr(dl->dli_fname, '/');
    name = name ? name + 1 : dl->dli_fname;
    if ((uint64_t)addr != soffset) {
      char *sname = __cxa_demangle(dl->dli_sname, 0, 0, 0);
      sname = sname ? sname : dl->dli_sname;
      return g_strdup_printf(
          "\x1b[2m\x1b[38;2;180;190;254m%s\x1b[37m!\x1b[38;2;137;"
          "180;250m%s\x1b[37m+\x1b[38;2;250;179;135m0x%x\x1b[0m",
          name, sname, soffset);
    }
    return g_strdup_printf("\x1b[2m\x1b[38;2;180;190;254m%s\x1b[37m!"
                           "\x1b[38;2;250;179;135m0x%x\x1b[0m",
                           name, foffset);
  }

  return g_strdup_printf("\x1b[2m\x1b[38;2;250;179;135m0x%x\x1b[0m", addr);
}

int8_t isFridaAddress(void *addr) {
  lib_info *lib = find_lib_info(addr);
  if (lib) {
    char *result = strstr(lib->name, "frida");
    if (result != NULL)
      return 1;
    result = strstr(lib->name, "libc.so");
    if (result != NULL)
      return 1;
  }
  return 0;
}

gboolean inRange(void *ptr) {
  struct {
    size_t size;
  } *var = getranges();
  if (!var->size)
    return FALSE;

  int isize = (int)var->size;
  for (int i = 0; i < isize; i += 1) {
    mem_range *item = (mem_range *)((u64)var + (u64)4 + (u64)(16 * i));
    u64 base = (u64)item->base;
    u64 size = (u64)item->size;
    if (base <= (u64)ptr && base + size >= (u64)ptr) {
      return TRUE;
    }
  }
  return FALSE;
}
