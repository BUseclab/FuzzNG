<p align="center">
<img src="media/fuzzng.svg">
</p>

FuzzNG is a system-call fuzzer for the Linux Kernel, designed to minimize the
need for system-call descriptions. For details, see our
[NDSS 2023 paper](https://www.ndss-symposium.org/ndss-paper/no-grammar-no-problem-towards-fuzzing-the-linux-kernel-without-system-call-descriptions/).

FuzzNG is composed of 4 main components.

 * **agent-ng** is the user-space process that executes fuzzing system-calls. Located in `agent/`
 * **mod-ng** is the set of kernel modifications that "reshape" the pointer and
   file-descriptor input spaces. Located in `kernel-patches/`
 * **qemu-ng** is the full-vm snapshot fuzzer which places new inputs into ng-agent
   and resets the entire VM after each input. Located in `qemu-patches/`
 * **libfuzzer-ng** is a modified version of libfuzzer used for input generation. Located in `libfuzzer-ng`

# Instructions
These instructions were tested on Debian 12. A CPU with VT-x support is
preferable.
The user needs rw permissions for /dev/kvm

Install Requirements:
```bash
# QEMU:
sudo apt-get install git libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev ninja-build

# Kernel:
sudo apt-get install build-essential linux-source bc kmod cpio flex libncurses5-dev libelf-dev libssl-dev dwarves bison

# Misc:
sudo apt install llvm deboostrap qemu-img
```

Build Kernel + FuzzNG (mod-ng/qemu-ng/libfuzzer-ng/agent-ng)

Note that clang is required.
```bash
NPROC=4 CC=clang-15 CXX=clang++15 make
# This may ask for your password to set up the disk-image for the fuzzing VM.
```

Now pick a fuzzing-config from `configs/` and start the fuzzer:

```bash
# Fuzz KVM with 4 workers
./scripts/fuzz.sh 4 configs/kvm.h
```

Or, to run a single worker with serial-output from the VM enabled:
```bash
# Manually copy the KVM config:
cp configs/kvm.h agent/fuzz_config.h

# Run a fuzzer
EXTRA_ARGS="-serial stdio" PROJECT_ROOT="./" ./scripts/run.sh
```

If you use FuzzNG for your publication, please consider citing the paper:
```bibtex
@inproceedings{fuzzng,
  title={{No Grammar, No Problem: Towards Fuzzing the Linux Kernel without System-Call Descriptions}},
  author={Bulekov, Alexander and Das, Bandan and Hajnoczi, Stefan, and Egele, Manuel},
  booktitle={Symposium on Network and Distributed System Security (NDSS)},
  year={2023}
}
```
