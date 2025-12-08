#include <gum/guminterceptor.h>
#include <stdio.h>
typedef unsigned long long u64;
typedef void *pthread_t;

extern char* geton();
extern int sprintf(char *str, const char *format, ...);
extern int isprint(int ch);
extern char *addressOf(void *ptr);
extern gboolean inRange(void *ptr);
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

extern gboolean verbose;;

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

void onEnter(GumInvocationContext *ic) {
  void *a0 = gum_invocation_context_get_nth_argument(ic, 0);
  char *a1 = gum_invocation_context_get_nth_argument(ic, 1);
  size_t a2 = GPOINTER_TO_SIZE(gum_invocation_context_get_nth_argument(ic, 2));
  void *retaddr = (void *)gum_invocation_context_get_return_address(ic);
  guint threadId = gum_invocation_context_get_thread_id(ic);
  if (inRange(retaddr) && sprintf((char *) geton(), "%.100s", a1) > 8) {
    if (verbose) {
      mklog("%p %p %d %s \x1b[32m%d\x1b[0m", a0, a1, a2, addressOf(retaddr),
            threadId);
      hex_dump(a1, a2 > 1000 ? 1000 : a2);
    } else {
      mklog("%.100s %s", a1, addressOf(retaddr));
    }
  } else {
    // mklog("%p %p %p", BASE, SIZE, retaddr);
  }
}
