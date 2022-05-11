#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((constructor, visibility("hidden"))) void init(void)
{
  char *syscall_list = getenv("NOSYS_SYSCALLS");
  if (syscall_list == NULL) {
    fputs("NOSYS_SYSCALLS is not set\n", stderr);
    exit(EXIT_FAILURE);
  }

  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (ctx == NULL) {
    fputs("seccomp_init failed\n", stderr);
    goto out;
  }

  char *syscall_name;
  while ((syscall_name = strtok(syscall_list, ",")) != NULL) {
    syscall_list = NULL;

    int syscall = seccomp_syscall_resolve_name(syscall_name);
    if (syscall == __NR_SCMP_ERROR) {
      fprintf(stderr, "Unknown syscall: %s, ignoring it\n", syscall_name);
      continue;
    }

    int rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), syscall, 0);
    if (rc < 0) {
      fprintf(stderr, "seccomp_rule_add failed: %s\n", strerror(-rc));
      goto out;
    }
  }

  int rc = seccomp_load(ctx);
  if (rc < 0) {
    fprintf(stderr, "seccomp_rule_add failed: %s\n", strerror(-rc));
    goto out;
  }

out:
  seccomp_release(ctx);
  return;
}
