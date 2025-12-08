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
  gchar* arg0;
};


void onEnter(GumInvocationContext *ic) {
  IcState *is = GUM_IC_GET_INVOCATION_DATA(ic, IcState);
  is->arg0 = (gchar *) gum_invocation_context_get_nth_argument(ic, 0);
}


void onLeave(GumInvocationContext *ic) {
  IcState *is = GUM_IC_GET_INVOCATION_DATA(ic, IcState);
  size_t retval = GPOINTER_TO_SIZE(gum_invocation_context_get_return_value(ic));
  void *retaddr = (void *)gum_invocation_context_get_return_address(ic);

  if (inRange(retaddr) && retval > 4) {

    mklog("{ \x1b[33m\"%.100s%s\"\x1b[0m } ~ \x1b[32m%d\x1b[0m %s", is->arg0, retval > 100 ? "..." : "", retval,
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
