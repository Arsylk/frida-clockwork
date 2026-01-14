#include "glib.h"
#include <gum/guminterceptor.h>

char *read_fd_path(int fd);
char *escape_newlines(const char *str, size_t len);

extern long syscall(long number, ...);
extern char *strstr(const char *haystack, const char *needle);
extern int snprintf(char *s, size_t n, const char *format, ...);
extern int fileno(FILE *stream);
extern gboolean inRange(void *ptr);
extern char *addressOf(void *ptr);
static void mklog(const char *format, ...);
extern void frida_log(const gchar *messag, ...);
static void mklog(const char *format, ...) {
  gchar *message;
  va_list args;
  va_start(args, format);
  message = g_strdup_vprintf(format, args);
  va_end(args);
  frida_log(message);

  g_free(message);
}

typedef struct _IcState IcState;
struct _IcState {
  gchar *arg0;
  uint64_t arg1;
  void *arg2;
};

void onEnter(GumInvocationContext *ic) {
  IcState *is = GUM_IC_GET_INVOCATION_DATA(ic, IcState);
  is->arg0 = (gchar *)gum_invocation_context_get_nth_argument(ic, 0);
  is->arg1 = (uint64_t)gum_invocation_context_get_nth_argument(ic, 1);
  is->arg2 = (void *)gum_invocation_context_get_nth_argument(ic, 2);
}

void onLeave(GumInvocationContext *ic) {
  IcState *is = GUM_IC_GET_INVOCATION_DATA(ic, IcState);
  size_t retval = GPOINTER_TO_SIZE(gum_invocation_context_get_return_value(ic));
  void *retaddr = (void *)gum_invocation_context_get_return_address(ic);

  if (inRange(retaddr) && is->arg0) {
    int fd = fileno((FILE *)is->arg2);
    char *path = read_fd_path(fd);
    char *fmt = escape_newlines(is->arg0, 200);
    mklog("\x1b[33m\"%s\"\x1b[0m @ \x1b[35m%s\x1b[0m %s", fmt, path,
          addressOf(retaddr));
    g_free(fmt);
    g_free(path);
  }
}

char *read_fd_path(int fd) {
  char strpath[64];
  snprintf(strpath, sizeof(strpath), "/proc/self/fd/%d", fd);

  size_t bufsize = 4096;
  char *buf = (char *)g_malloc(bufsize);
  syscall(78, 0, strpath, buf, bufsize);
  g_free(strpath);

  return buf;
}

char *escape_newlines(const char *str, size_t len) {
  if (!str)
    return NULL;

  size_t nl_count = 0;
  for (size_t i = 0; i < len; i += 1) {
    if (str[i] == '\n') {
      nl_count += 1;
    }
  }

  char *newstr = (char *)g_malloc((len + nl_count + 1) * sizeof(char));
  size_t j = 0;
  for (size_t i = 0; i < len; i += 1) {
    if (str[i] == '\n') {
      newstr[j++] = '\\';
      newstr[j++] = 'n';
    } else {
      newstr[j++] = str[i];
    }
  }
  newstr[j] = '\0';

  return newstr;
}
