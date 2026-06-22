#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct vm_area_struct;

SEC("lsm/file_mprotect")
int BPF_PROG(aos_lsm_file_mprotect,
             struct vm_area_struct *vma,
             unsigned long reqprot,
             unsigned long prot,
             int ret)
{
  (void)vma;
  (void)reqprot;
  (void)prot;
  return ret;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
