+++
date = '2025-09-28T11:13:46+02:00'
author = "alarmfox"
draft = false
title = 'The true power of Python-GDB: automating RISC-V security firmware testing'
keywords = ["qemu", "riscv", "gdb", "python", "firmware", "testing", "confidential-computing"]
tags = ["gdb", "python", "firmware", "riscv", "security", "testing"]
readingTime = true
toc = true
+++

## Introduction

> Source code can be found [here](https://github.com/HiSA-Team/shadowfax/tree/feature/create-tvm).
> References are at the [bottom of the page](#references).

Currently, my main research focus is on writing a RISC-V CoVE [1](#references) compliant firmware. I will not go in
detail here, but I will just introduce the topic. Major CPU manufacturers (Intel, ARM, AMD, NVIDIA, ecc)
are proposing _hardware-supported_ **Trusted Execution Environment (TEE)** (which is a fancy way to 
say "very strong isolation including cryptography in-memory and anti-tamper supported by 
attestation services").
Recent trends (like Intel TDX, ARM CCA, AMD SEV) propose the creation of Virtual Machine based TEE. 
So we are not just isolating processes, but entire operating systems. RISC-V proposed CoVE
(Confidential Virtual Extension) and so here I am trying to implementing it.

CoVE introduces Trusted Virtual Machine (TVM), the TSM (which is something like a "trusted-hypervisor";
TSM stands for TEE Security Manager) and the TSM-driver (firmware level component which manages 
different TSMs). The TSM-driver is part of the firmware and runs at the highest privilege level.

Every interaction between the untrusted world and the TSM has to be validated by the firmware and 
this happens through context switches using TEECALL/TEERET. TEECALL/TEERET are just a name to indicate
the ECALL instruction which stands for _environment call_ and acts as a synchronous trap for the user
creating it. The idea is: the Host OS issues ECALL towards the TSM which performs operations and responds
back. Every ECALL has a context switch:

* TEECALL: a context switch towards the firmware, the firmware makes checks and perform another context
switch to the TSM
* TEERET: the same backwards

## The mess

> **TLDR**: writing a firmware with lots of context switches is hard. Testing each modification you do is
even harder. Combine these two with cryptography and security and soon, you will start thinking
"I need a way to test all of this quickly and jump right into bug/feature I am focusing on."

How do we create a TVM according to CoVE? We need to create at least **10** (lol!) TEECALL/TEERET.
All these calls make sense, thus we need to:

- search support for confidential supervisor domain
- check for TSM state and capabilities
- donate some memory to make it become _confidential_ memory
- create the TVM: specify the *Guest Page Table* (GPT) address
- create memory regions: the TVM will see this as Guest Physical Address (GPA)
- map the memory regions: once created the memory regions we need to copy TVM data in it (code, data etc.)
and create entries into the GPT
- measure data: calculate some hashes and stuff like that
- create the vCPU: which just a way to say save somewhere registers of the CPU when running the TVM
- mark the TVM as ready to run: no more modifications are allowed
- run the vCPU: boot the processor with the TVM state (configure interrupt forwarding etc.)

My setup is QEMU + GDB.

If I wanted to be realistic about this, I would need a CoVE aware Operating System or an hypervisor
which issues consistently `ECALL` towards the TSM. In Linux, the support is premature and
I don't know any system that performs this kind of service (booting a kernel to make a simple test
does not seem ideal). I need something focusing on control and speed.

During the `create_tvm` implementation, it was taking more than **20 minutes** to setup a test.
It was really frustrating. Setting up registers can be done from the GDB CLI (pretty slow), but how
would I setup memory?
Also, another problem came out: how can I inspect the memory and registers to understand what was
the result of each operation? Doing `x <memory address>` is not _fun_.
Persisting the state between ECALLs (TEECALL/TEERET are supposed to be stateless) is also not simple:

- you create a TVM, the id is returned and you have to remember it
- you create a mapping and you have to remember it
- etc.

When I reached the crucial point, I usually **forgot** what I was testing!

## Scripting in GDB
GDB supports scripting. I was using it to save some commands, loading an ELF, connecting to QEMU
with something like this:

```
set confirm off
set breakpoint pending on
set pagination off
set arch riscv:rv64

target remote localhost:1234

file target/riscv64imac-unknown-none-elf/debug/shadowfax

# load tsm elf file for debug symbols
add-symbol-file target/riscv64imac-unknown-none-elf/debug/tsm 0x81400000

break tsm::main

define qemu-reset
  delete breakpoint
  shell echo "system_reset" | socat - unix-connect:/tmp/shadowfax-qemu-monitor | tail --lines=+2 | grep -v '^(qemu)'
end
```

So, I started tweaking creating a bunch of macros/commands/function (I still don't know the
difference in GDB), but the problem persisted: I needed an "extra test program", modify it according
to my test case, find a way to load it (my firmware has a small ELF loader, but global variables
and relocations are a pain), it would need to be a "bare metal program", so **NO**. I wanted easy
reproducible state.

In the `Embedded Systems` I took in University, the Professor mentioned about Python bindings for GDB.
So it came to my mind: what if I can specify the `create_tvm flow` as steps?

For each step, I would need a function to setup (both memory and registers) and one to assert the
result. But what about the instruction? Well, instructions are just "numbers in memory" right?
Let's write them as needed.

### Python-GDB API crash course

> **NOTE**: we are heavily relying on the single-core assumption. Otherwise we will be talking about
_inferiors_ (software threads mapping QEMU hardware threads), PLIC, CLIC etc. ~Sounds like the
classic "future me problem"~.

The API is really simple [3](#references): one can read/write from registers and memory. The script is sourced in
the current GDB process with something like `source script.py`. For example, I setup some utility
function to interact with memory and registers:

```py
def read_reg(name: str) -> int:
    """Return integer value of a register (e.g. 'a0', 'pc')."""
    return int(gdb.parse_and_eval(f"${name}"))


def read_regs(names: List[str]) -> Dict[str, int]:
    return {n: read_reg(n) for n in names}


def read_mem(addr: int, size: int) -> bytes:
    """Read memory from selected inferior. Returns bytes."""
    inf = gdb.selected_inferior()
    return inf.read_memory(addr, size).tobytes()
```

A breakpoint can be used by creating a class extending `gdb.Breakpoint` and providing a `stop()`
method which will be executed when the breakpoint will be triggered (**before** running the actual instruction).
In the example below, `PreBP` sets up the memory and registers before an ECALL and snapshots the
state allowing the `PostBP` to read input arguments and perform asserts.

```py
class PreBP(gdb.Breakpoint):
    """
    Temporary breakpoint placed at the ECALL address.
    On hit it:
      - captures a 'prev' snapshot (regs+mem) and stores it in runner.pending_prev[step_index]
      - runs step.setup_mem_fn() and writes step.regs
      - installs a temporary PostBP at addr + 4 (the instruction after the ecall)
      - returns False so the inferior continues and executes the ECALL
    """

    def __init__(self, addr: int, step_index: int, runner: "TestRunner"):
        super().__init__(f"*0x{addr:x}", type=gdb.BP_BREAKPOINT, temporary=True)
        self.addr = addr
        self.step_index = step_index
        self.runner = runner

    def stop(self) -> bool:
        # some sanity checks omitted...
        step = self.runner.steps[self.step_index]

        # Allow step to set up memory/registers before the ECALL executes
        if step.regs is not None:
            for reg, val in step.regs.items():
                gdb.execute(f"set ${reg} = {val}")

        if step.setup_mem_fn is not None:
            try:
                step.setup_mem_fn()
            except Exception as e:
                print(
                    f"  step[{self.step_index}] '{step.name}': setup_mem_fn exception: {e}"
                )
                # stop so the user can inspect if setup failed
                return True

        # Capture "prev" snapshot (state before ECALL executes)
        prev_snapshot = {"regs": read_regs(self.runner.regs_to_snapshot), "mem": {}}
        for label, (addr_reg, size) in self.runner.mem_snapshot_spec.items():
            if isinstance(addr_reg, str):
                addr = prev_snapshot["regs"].get(addr_reg, read_reg(addr_reg))
            else:
                addr = int(addr_reg)
            try:
                prev_snapshot["mem"][label] = read_mem(addr, size)
            except Exception as e:
                prev_snapshot["mem"][label] = f"<mem read failed: {e}>"

        # store pending prev snapshot for this step (consumed by PostBP)
        self.runner.pending_prev[self.step_index] = prev_snapshot

        # print registers for debugging
        gdb.execute(
            "info registers "
            + " ".join(self.runner.regs_to_snapshot)
            + " pc sepc scause stval mepc mcause mtval"
        )

        # return False so the inferior continues (ECALL instruction will execute)
        return False
```

### Synthetic approach
The CoVE flow will be made by steps. Each step will be a TEECALL/TEERET towards the TSM.

Let's see a simple program. This program will get supervisor domains (the active TSMs, it's not
exactly like that, but this is OK for now) and will get the TSM capabilities (from the spec these are
the preliminary steps that must be performed by an untrusted OS and happens with 2 TEECALL/TEERET):

> **Backstory**: in RISC-V a0-a5 registers contain ECALL parameters. `a7` contains the _extension_ (think 
of it like a service we are calling) and `a6` contains a _function_ id (for the specific extension).
Additionally, CoVE says that we must encode the target TSM identifier in bits [31:26] of the `a6` register.

```py
def run() -> None:
    print("=== GDB Get TSM Info Program ===")
    payload_address: int = int(os.environ["SHADOWFAX_JUMP_ADDRESS"], 16)
    print(f"S-Mode address 0x{payload_address:x}")

    runner = TestRunner(payload_address)

    runner.add_step(
        Step(
            name="enumerate_supervisor_domains",
            regs={
                "a0": 0,
                "a1": 0,
                "a2": 0,
                "a3": 0,
                "a4": 0,
                "a5": 0,
                "a6": SUPD_GET_ACTIVE_DOMAINS,
                "a7": EID_SUPD_ID,
            },
            setup_mem_fn=None,
            assert_fn=assert_get_active_domains,
        )
    )

    runner.add_step(
        Step(
            name="get_tsm_info",
            regs={
                "a0": payload_address + 0x1000,
                "a1": 48,
                "a2": 0,
                "a3": 0,
                "a4": 0,
                "a5": 0,
                "a6": (1 << 26) | (COVH_GET_TSM_INFO & 0xFFFF),
                "a7": EID_COVH_ID,
            },
            setup_mem_fn=None,
            assert_fn=assert_get_tsm_info,
        )
    )

    runner.install_breakpoints()
    print("=== Test harness ready; continue from gdb to run ===")
```

For each step, we will automatically generate the "program": an ECALL and a NOP. But what are
"ECALL" and "NOP"? They are numbers (RISC-V is a little endian architecture) and their OPCODE are
stated in the specification (I used this small reference I found online [2](#references). Also, I am using the
_compressed_ instructions). The `runner.add_step()` just appends things to a list.

The `runner.install_breakpoints()` function loops through the steps and for each one writes an
ECALL/NOP couple and terminates the _synthetic program_ with a classic **loop: jump loop** to
prevent the program counter (PC) exploding.

```py
# Instruction words
ECALL_WORD = struct.pack("<I", 0x00000073)  # ecall
EBREAK_WORD = struct.pack("<I", 1 << 20 | 0x00000073)  # ebreak
NOP_WORD = struct.pack("<I", 0x00000013)  # addi x0,x0,0 -> nop
JAL_LOOP_WORD = struct.pack("<I", 0x0000006F)  # jal x0, 0  -> tight infinite loop

class TestRunner:
    # other methods
    def install_breakpoints(self, install_ebreak=False) -> None:
    """
    For each step:
     - write ECALL_WORD at payload_address + 8*i
     - write NOP_WORD at payload_address + 8*i + 4
     - install a temporary PreBP breakpoint at ecall addr
     - install a temporary PostBP breakpoint at nop addr

    After all steps:
     - (optional) write EBREAK_WORD after the ECALL/NOP "program"
     - write JAL_LOOP_WORD after the EBREAK_WORD to prevent the pc growing to infinite
    """
    inf = gdb.selected_inferior()
    # install step ecall words and PreBP breakpoints
    for i, step in enumerate(self.steps):
        ecall_addr = self.payload_address + 8 * i
        nop_addr = ecall_addr + 4

        inf.write_memory(ecall_addr, ECALL_WORD)
        print(f"Wrote ecall at 0x{ecall_addr:x}")
        inf.write_memory(nop_addr, NOP_WORD)
        print(f"Wrote nop at 0x{nop_addr:x}")

        PreBP(ecall_addr, i, self)self.payload_address + (8 + 1) * len(self.steps)
        print(f"Installed PreBP (step {i} - {step.name}) at 0x{ecall_addr:x}")

        PostBP(nop_addr, i, self)
        print(f"Installed PostBP (step {i} - {step.name}) at 0x{nop_addr:x}")

    # write an ebreak
    next_addr = self.payload_address + 8 * len(self.steps)
    if install_ebreak:
        ebreak_addr = next_addr
        inf.write_memory(ebreak_addr, EBREAK_WORD)
        print(f"Wrote ebreak instruction at 0x{ebreak_addr:x}")
        next_addr += 4

    # write infinite loop to ensure the program to hang
    loop_addr = next_addr
    inf.write_memory(loop_addr, JAL_LOOP_WORD)
    print(f"Wrote loop instruction at 0x{loop_addr:x}")
```

The "untrusted program" will look like this:

```
(gdb) x/i 0x82000000
   0x82000000:  ecall
(gdb)
   0x82000004:  nop
(gdb)
   0x82000008:  ecall
(gdb)
   0x8200000c:  nop
(gdb)
   0x82000010:  j       0x82000010
```

The two step program shown before has no memory setup, just registers. Now, I can easily check
for the result simply reading from the memory. The `assert_fn` signature is:

```py
assert_fn(prev_ctx, curr_ctx)
```

> **NOTE**: each ECALL returns the error (`0` for success) in `a0` register and a value in `a1` register.

For example, the `get_active_domains` returns in `a1` register the bitmask of the active supervisor domain
id. I am expecting `0x3` (`id=0, first bit because of the untrusted domain always active` and `id=1, my TSM`).
So the check will be:

```py
def assert_get_active_domains(prev: Optional[Dict], curr: Dict) -> None:
    regs = curr["regs"]
    a0 = regs["a0"]
    a1 = regs["a1"]
    assert a0 == 0, f"ecall returned non-zero in a0 ({a0})"
    assert a1 & 0x3 == 3, (
        f"a1 must be contains tsm (id=1) and the root domain (id=0) bit set (0x3) (current {a1})"
    )
```

A more complicated check will happen for the `struct TSMInfo`. The TSM will write its state into an address
provided by the Host. With "my API", this can be easily done as follows:

```py
def assert_get_tsm_info(prev: Optional[Dict], curr: Dict) -> None:
    # ensure the ECALL returned successfully in a0 and left a1 = 48 (the number of bytes written)
    regs = curr["regs"]
    a0 = regs["a0"]
    a1 = regs["a1"]
    assert a0 == 0, f"ecall returned non-zero in a0 ({a0})"
    assert a1 == 48, f"a1 must contain size 48 (current {a1})"

    assert prev is not None, "expecting the previous context not None"
    tsm_info_addr = prev["regs"]["a0"]

    # read TsmInfo as bytes in one shot. The TsmInfo struct is defined in "common/src/lib.rs" as follows:
    # Due to the memory alignement (TsmState is a u32), there is an extra u32 before the `tsm_capabilities`
    # struct TsmInfo {
    #     pub tsm_state: TsmState,
    #     pub tsm_impl_id: u32,
    #     pub tsm_version: u32,
    #     _padding: u32: extra 32-bit added by Rust because YES (alignment stuff).
    #     pub tsm_capabilities: usize,
    #     pub tvm_state_pages: usize,
    #     pub tvm_max_vcpus: usize,
    #     pub tvm_vcpu_state_pages: usize,
    # }
    tsm_info_bytes = (4 * 4) + (8 * 4)
    raw = read_mem(tsm_info_addr, tsm_info_bytes)
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < tsm_info_bytes:
        raise AssertionError(
            f"failed to read {tsm_info_bytes} bytes at {hex(tsm_info_addr)}: {raw!r}"
        )

    (
        tsm_state,
        tsm_impl_id,
        tsm_version,
        _padding,
        tsm_capabilities,
        tvm_state_pages,
        tvm_max_vcpus,
        tvm_vcpu_state_pages,
    ) = struct.unpack("<IIIIQQQQ", raw)

    assert tsm_state == 2, f"tsm_state must be 2; current {tsm_state}"
    assert tsm_impl_id == 69, f"tsm_impl_id must be 69; current {tsm_impl_id}"
    assert tsm_version == 69, f"tsm_version must be 0; current  {tsm_version}"
    assert tsm_capabilities == 0, (
        f"tsm_capabilities must be 0; current {tsm_capabilities}"
    )
    assert tvm_state_pages == 1, f"tvm_state_pages must be 0; current {tvm_state_pages}"
    assert tvm_max_vcpus == 1, f"tvm_max_vcpus must be 1; current {tvm_max_vcpus}"
    assert tvm_vcpu_state_pages == 0, (
        f"tvm_vcpu_state_pages must be 0; current {tvm_vcpu_state_pages}"
    )
```

### Preparing and examining processor and memory state
The API defines 2 types of breakpoints:

- `PreBP`: to setup ECALL parameters and memory
- `PostBP`: to test the result of the previous ECALL (on the NOP instruction)

The `PostBP` runs the assert function popping the `prev_ctx` (pushed by the `PreBP`) and using
the `curr_ctx`.

```py
class PostBP(gdb.Breakpoint):
    """
    Temporary breakpoint installed at addr+4 (the instruction after ECALL).
    On hit it:
      - captures the 'curr' snapshot (state after ECALL has been handled)
      - pulls the 'prev' saved by PreBP and calls step.assert_fn(prev, curr)
      - appends curr to runner.history for record-keeping
      - on assert failure, returns True so inferior stops for inspection
      - on success, returns False so the test continues to the next PreBP
    """

    def __init__(self, addr: int, step_index: int, runner: "TestRunner"):
        super().__init__(f"*0x{addr:x}", type=gdb.BP_BREAKPOINT, temporary=True)
        self.addr = addr
        self.step_index = step_index
        self.runner = runner

    def stop(self) -> bool:
        # some sanity checks omitted
        step = self.runner.steps[self.step_index]

        # snapshot current regs/mem: this is the post-ecall state
        curr_snapshot = {"regs": read_regs(self.runner.regs_to_snapshot), "mem": {}}
        for label, (addr_reg, size) in self.runner.mem_snapshot_spec.items():
            if isinstance(addr_reg, str):
                addr = curr_snapshot["regs"].get(addr_reg, read_reg(addr_reg))
            else:
                addr = int(addr_reg)
            try:
                curr_snapshot["mem"][label] = read_mem(addr, size)
            except Exception as e:
                curr_snapshot["mem"][label] = f"<mem read failed: {e}>"

        prev_snapshot = self.runner.pending_prev.pop(self.step_index, None)

        # call assertion if present
        if step.assert_fn is not None:
            try:
                step.assert_fn(prev_snapshot, curr_snapshot)
                print(f"  step[{self.step_index}] '{step.name}': assert PASS")
            except AssertionError as e:
                print(f"  step[{self.step_index}] '{step.name}': assert FAIL: {e}")
                # append curr for completeness then stop so user can inspect
                self.runner.history.append(curr_snapshot)
                return True
            except Exception as e:
                print(f"  step[{self.step_index}] '{step.name}': assert EXCEPTION: {e}")
                self.runner.history.append(curr_snapshot)
                return True

        # append the post-ecall snapshot to history
        self.runner.history.append(curr_snapshot)
        return True
```

## A more complicated example: create TVM flow
The example presented before just discovers the TSM capabilities. The next step is to setup
a `create_tvm` test. The API is the same, we just need to focus on the memory setup, register values and
implement the desired functionalities in the TSM (just!). The program will look like this (lots of steps!):

```py
def run() -> None:
    print("=== GDB Create TVM Program ===")
    print(f"S-Mode address 0x{payload_address:x}")

    runner = TestRunner(payload_address)

    runner.add_step(
        Step(
            name="enumerate_supervisor_domains",
            regs={
                "a0": 0,
                "a1": 0,
                "a2": 0,
                "a3": 0,
                "a4": 0,
                "a5": 0,
                "a6": SUPD_GET_ACTIVE_DOMAINS,
                "a7": EID_SUPD_ID,
            },
            setup_mem_fn=None,
            assert_fn=assert_get_active_domains,
        )
    )

    runner.add_step(
        Step(
            name="get_tsm_info",
            regs={
                "a0": payload_address + 0x1000,
                "a1": 48,
                "a2": 0,
                "a3": 0,
                "a4": 0,
                "a5": 0,
                "a6": (1 << 26) | (COVH_GET_TSM_INFO & 0xFFFF),
                "a7": EID_COVH_ID,
            },
            setup_mem_fn=None,
            assert_fn=assert_get_tsm_info,
        )
    )

    runner.add_step(
        Step(
            name="convert_pages",
            regs={
                "a0": confidential_memory_start_addr,
                "a1": NUM_PAGES_TO_DONATE,
                "a2": 0,
                "a3": 0,
                "a4": 0,
                "a5": 0,
                "a6": (1 << 26) | (COVH_CONVERT_PAGES & 0xFFFF),
                "a7": EID_COVH_ID,
            },
            setup_mem_fn=None,
            assert_fn=assert_convert_pages,
        )
    )

    runner.add_step(
        Step(
            name="create_tvm",
            regs={
                "a0": payload_address + 0x1000,
                "a1": 16,
                "a2": 0,
                "a3": 0,
                "a4": 0,
                "a5": 0,
                "a6": (1 << 26) | (COVH_CREATE_TVM & 0xFFFF),
                "a7": EID_COVH_ID,
            },
            setup_mem_fn=setup_create_tvm_mem,
            assert_fn=assert_create_tvm,
        )
    )

    runner.add_step(
        Step(
            name="add_tvm_memory_region",
            regs={
                "a0": 1,
                # Guest Physical Address (GPA)
                "a1": GPA_BASE,
                "a2": 0x1000,
                "a3": 0,
                "a4": 0,
                "a5": 0,
                "a6": (1 << 26) | (COVH_ADD_MEMORY_REGION & 0xFFFF),
                "a7": EID_COVH_ID,
            },
            setup_mem_fn=setup_create_tvm_mem,
            assert_fn=assert_create_tvm,
        )
    )

    runner.add_step(
        Step(
            name="add_tvm_measured_pages",
            regs={
                "a0": 1,
                # i will write at this address the loop jump loop instruction
                "a1": tvm_source_code_addr,
                # the address of the physical confidential memory
                # START_CONFIDENTIAL_REGION + 16 kb +
                "a2": tvm_page_start_addr,
                # 0 for 4kb page
                "a3": 0,
                # num pages just one page
                "a4": 1,
                "a5": GPA_BASE,
                "a6": (1 << 26) | (COVH_ADD_TVM_MEASURED_PAGES & 0xFFFF),
                "a7": EID_COVH_ID,
            },
            setup_mem_fn=setup_add_tvm_measured_pages,
            assert_fn=None,
        )
    )
    # other steps...

    runner.install_breakpoints()
    print("=== Test harness ready; continue from gdb to run ===")


if __name__ == "__main__":
    run()
```

The goal is to create a simple process, but in reality we can have bigger memory regions
and even a "for loop" to map all the pages. This way I can assert that the GPT is fully zero after the
`create_tvm`. The `create_tvm` accepts a pointer to a struct which contains the `page_table_address` and
the `state_address`. The following function writes the addresses in memory at the `ŧvm_params_addr`
pointer.

```py
def setup_create_tvm_mem() -> None:
    """
    The sbi_covh_create_tvm(address, size) accepts a pointer to a structure containing the GPT
    base address and the state_base_address.
    """
    # parameter where to store the addresses
    tvm_params_addr = read_reg("a0")

    tvm_directory_addr = confidential_memory_start_addr
    tvm_state_addr = confidential_memory_start_addr + PAGE_DIRECTORY_SIZE

    print(f"tvm_params is at 0x{tvm_params_addr:x}")
    print(f"tvm_page_directory_addr (0x{tvm_params_addr:x}): 0x{tvm_directory_addr:x}")
    print(f"tvm_state_addr (0x{(tvm_params_addr + 8):x}): 0x{(tvm_state_addr):x}")

    # page table address in confidential memory
    tvm_directory_addr = struct.pack("<Q", tvm_directory_addr)
    tvm_state_addr = struct.pack("<Q", tvm_state_addr)

    inf = gdb.selected_inferior()

    inf.write_memory(tvm_params_addr, tvm_directory_addr)
    inf.write_memory(tvm_params_addr + 8, tvm_state_addr)
```


Finally, the function below checks 2 things:
- the `ECALL` went successfully,
- the `tvm_create` correctly zeroed the GPT

```py
def assert_create_tvm(prev: Optional[Dict], curr: Dict) -> None:
    regs = curr["regs"]
    a0 = regs["a0"]
    assert a0 == 0, f"ecall returned non-zero in a0 ({a0})"

    # assert that the pagetable is zero
    params_addr = prev["regs"]["a0"]

    # read two 64-bit words (page_table_addr, state_addr)
    raw = read_mem(params_addr, 16)
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 16:
        raise AssertionError(f"failed to read 16 bytes at {hex(params_addr)}: {raw!r}")

    page_table_addr, state_addr = struct.unpack("<QQ", raw)

    raw = read_mem(page_table_addr, PAGE_DIRECTORY_SIZE)
    if not isinstance(raw, (bytes, bytearray)):
        raise AssertionError(
            f"failed to read {PAGE_DIRECTORY_SIZE} bytes at {hex(page_table_addr)}: {raw!r}"
        )
    assert raw == b"\x00" * PAGE_DIRECTORY_SIZE, (
        "page table must be zero after TVM creation"
    )
```

## Running a test
Now the question is how does one run everything? If you have a firmware, your QEMU command will
look something like this:

```sh
qemu-system-riscv64 -monitor unix:/tmp/shadowfax-qemu-monitor,server,nowait \
    -nographic \
    -M virt \
    -m 64M \
    -dtb bin/device-tree.dtb \
    -smp 1 \
    -bios target/riscv64imac-unknown-none-elf/debug/shadowfax \
    -s -S
```

The command tells QEMU to create a `64Mb` ram single core RISC-V machine using the `virt` platform with
the provided device tree blob (DTB). The `-s -S` tells the emulator to start a **gdb server process**
on TCP port `1234` and to stop on the first instruction. The `-bios` tells the path to the firmware
ELF. Finally, the `-monitor` tells to expose the monitor over a Unix socket (this allows to reset from
outside).

After spawning the process, we can attach with GDB (in another terminal) and source the script:

```sh
gdb -x gdb_settings
(gdb) source test_get_tsm_info.py
```

This will result in some installed breakpoints and with a couple of `continue` commands I can easily
test a complex functionalities.

```
=== GDB Get TSM Info Program ===
S-Mode address 0x82000000
Wrote ecall at 0x82000000
Wrote nop at 0x82000004
Temporary breakpoint 2 at 0x82000000
Installed PreBP (step 0 - enumerate_supervisor_domains) at 0x82000000
Temporary breakpoint 3 at 0x82000004
Installed PostBP (step 0 - enumerate_supervisor_domains) at 0x82000004
Wrote ecall at 0x82000008
Wrote nop at 0x8200000c
Temporary breakpoint 4 at 0x82000008
Installed PreBP (step 1 - get_tsm_info) at 0x82000008
Temporary breakpoint 5 at 0x8200000c
Installed PostBP (step 1 - get_tsm_info) at 0x8200000c
Wrote loop instruction at 0x82000010
=== Test harness ready; continue from gdb to run ===
```

After continue, we can see the program successfully reaching the breakpoints and running asserts.

```
(gdb) c
Continuing.
a0             0x0      0
a1             0x0      0
a2             0x0      0
a3             0x0      0
a4             0x0      0
a5             0x0      0
a6             0x0      0
a7             0x53555044       1398100036
pc             0x82000000       0x82000000
sepc           0x0      0
scause         0x0      0
stval          0x0      0
mepc           0x82000000       2181038080
mcause         0x2      2
mtval          0x32102573       839918963
  step[0] 'enumerate_supervisor_domains': assert PASS
Temporary breakpoint 3, 0x0000000082000004 in ?? ()
(gdb) c
Continuing.
a0             0x82001000       2181042176
a1             0x30     48
a2             0x0      0
a3             0x0      0
a4             0x0      0
a5             0x0      0
a6             0x4000000        67108864
a7             0x434f5648       1129272904
pc             0x82000008       0x82000008
sepc           0x0      0
scause         0x0      0
stval          0x0      0
mepc           0x82000004       2181038084
mcause         0x9      9
mtval          0x0      0
(gdb) c
Continuing.
  step[1] 'get_tsm_info': assert PASS
Temporary breakpoint 5, 0x000000008200000c in ?? ()
```

Mission accomplished! One could also run an entire directory of these tests resetting the CPU using 
the `unix` monitor!

## Conclusions
I was feared to test new things in the firmware. Now the setup is just instant, but this unlocked
something new that I will cover in another post: creating tools helps understanding problems.

Some more use for this "tool" (just a Python API) could be to put in action some security exploitation
scenarios by mixing steps and TEECALL/TEERET in a malicious way.

Another useful thing that could be made is to enable something like a `noninteractive` mode to perform
all the tests in CI.

I am planning to create something more clear with like a `static class` with all the result value
to avoid hard-coding things in the `assert` statements. For now this works fine, don't jump into
pre-mature optimizations!

## References

[1] CoVE specification https://github.com/riscv-non-isa/riscv-ap-tee

[2] RISC-V https://www.cs.sfu.ca/~ashriram/Courses/CS295/assets/notebooks/RISCV/RISCV_CARD.pdf

[3] Python-GDB API documentation https://sourceware.org/gdb/current/onlinedocs/gdb.html/Python.html#Python
