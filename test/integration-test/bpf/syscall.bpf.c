// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

SEC("syscall")
int my_syscall(void *ctx) {
  int *my_value = (int *)ctx;
  *my_value = *my_value + *my_value;
  return 0;
}

char _license[] SEC("license") = "GPL";
