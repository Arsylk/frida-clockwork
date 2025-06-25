#include "glib.h"
#include <gum/guminterceptor.h>

extern int sprintf(char *str, const char *format, ...);
extern int isprint(int ch);
extern gboolean inRange(void *ptr);
extern char *addressOf(void *ptr);
static void mklog(const char *format, ...);
extern void frida_log(const gchar *messag, ...);

typedef struct _IcState IcState;
struct _IcState {
  gpointer arg0;
  gpointer arg1;
  size_t size;
};

void hex_dump(const void *ptr, size_t x) {
  const unsigned char *p = ptr;
  size_t i, j;
  char line[100];

  // mklog("Offset    | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F |
  // ASCII");
  for (i = 0; i < x; i += 16) {
    char *pos = line;
    pos += sprintf(pos, "0x%09zx | ", i);

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

  mklog(
      "------------+-------------------------------------------------+--------"
      "---------");
}

void onEnter(GumInvocationContext *ic) {
  IcState *is = GUM_IC_GET_INVOCATION_DATA(ic, IcState);
  is->arg0 = gum_invocation_context_get_nth_argument(ic, 0);
  is->arg1 = gum_invocation_context_get_nth_argument(ic, 1);
  is->size = (size_t)gum_invocation_context_get_nth_argument(ic, 2);
  // mklog("%p <> %p ? %d", is->arg0, is->arg1, is->size);
}

void onLeave(GumInvocationContext *ic) {
  IcState *is = GUM_IC_GET_INVOCATION_DATA(ic, IcState);
  size_t retval = GPOINTER_TO_SIZE(gum_invocation_context_get_return_value(ic));
  void *retaddr = (void *)gum_invocation_context_get_return_address(ic);

  if (inRange(retaddr)) {
    hex_dump(is->arg0, is->size > 500 ? 500 : is->size);
    hex_dump(is->arg1, is->size > 500 ? 500 : is->size);
    mklog("%p %p %d = 0x%x %s", is->arg0, is->arg1, is->size, retval,
          addressOf(retaddr));
  }
}

static void mklog(const char *format, ...) {
  gchar *message;
  va_list args;
  va_start(args, format);
  message = g_strdup_vprintf(format, args);
  va_end(args);
  frida_log(message);

  g_free(message);
}
