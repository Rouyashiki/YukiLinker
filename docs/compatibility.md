# Supported configurations

The SDK supports ARM64, ARM32, x86 and x86_64 Android processes on API 26 and
newer, and `riscv64` Android processes on API 37 and newer. Each build handles
its native ELF class and machine. The two 32-bit ABIs share the v1 public
record layouts, including eight-byte alignment for 64-bit fields. Runtime page
size comes from the host. Libraries use 16 KiB maximum LOAD alignment.

## Backend selection

PRIVATE manages ELF mappings, private dependency scopes, constructors and
supported dynamic TLS. SYSTEM delegates loading and symbol resolution to
HostServices and Bionic. Use SYSTEM for a component closure sharing Bionic TLS,
libc++, cross-DSO exceptions or CFI.

The host coordinates code-pointer lifetime, thread exit, callbacks and Core
retirement. PRIVATE call barriers contain escaping exceptions where required by
the ABI. C API callbacks must obey their declared signatures.

## TLS and executable mappings

For an API 26 target, the NDK implements C and C++ thread-local variables with
compiler-rt emulated TLS (emutls). Bionic supports native ELF TLS from API 29.
Core's PRIVATE runtime supports both the NDK's default emutls output and its
existing native ELF TLS relocation models. The reduced bootstrap stage has no
thread storage of its own. SYSTEM follows the Android version of the process.

When an emutls accessor can be rebound, Core supplies one accessor for the
private dependency group. A versioned accessor import still resolves through
the normal ELF scope. An unversioned lookup selects the default ELF definition,
including when the caller imported an older version. A PRIVATE lookup selecting
the relocation's provider returns the same Core accessor. A control lookup
through a PRIVATE handle, `RTLD_DEFAULT` or `RTLD_NEXT` checks the default
accessor selected in that same scope. `RTLD_NEXT` starts after the calling
module. The lookup reports `UNSUPPORTED` if the selected accessor uses a
different control-index space. A trusted PRIVATE image can expose its control
when the lookup selects the accessor it actually bound, including a system provider.
An ordinary PRIVATE image and a trusted PRIVATE image can share a control
in either direction when both bind the same accessor. Core checks their
actual bindings before private resolvers or constructors run. A reader
that binds Core's accessor can import controls only from PRIVATE providers
that also use Core storage, including trusted providers.
Controls resolved through Bionic or a namespace host import belong to the
system provider. A trusted PRIVATE reader can look up a system control it
imported when the same scope selects its relocated native accessor.
A Core reader importing one receives `UNSUPPORTED` during
relocation, as does a reader whose private resolver would be needed to prove
the pairing safe.
When both bind Core's accessor, Core provides per-thread storage for the
reader's own controls as well. A reader that relies on Core storage or an
ordinary PRIVATE control provider is ineligible for `release_host`.
PRIVATE rejects a reader that binds Core's accessor and can also call a native
accessor through a locally bound symbol version or a second callable name for
the same ELF address. With a versioned import and the services used to read
or grow a local compiler-rt pthread array, a stripped module can still call
a hidden unversioned accessor. PRIVATE declines the Core binding in that case.
An explicit system handle returns the accessor and control Bionic selects for it.
A control shared by two managed libraries names one object per thread.
A library can also export a thread-local variable for another library to read
without calling an accessor itself. Ordinary pthread key use in the provider is
compatible with this case, including after stripping.
A trusted PRIVATE reader can look up a control it imported from such a trusted
provider when the same scope selects the reader's relocated native accessor.

A library that binds compiler-rt locally can use its own controls. PRIVATE
tracks the pthread key values and destructors that keep that code live.
When PRIVATE identifies independent accessors, it reports `UNSUPPORTED` for
cross-library access before initialization. A provider with no visible accessor
can share a control only if it has no relocation referencing an emutls control.
When any pthread key creation, read or write is visible, PRIVATE also declines
to share if controls can bind locally or if at least two compiler-rt services
are visible among one-time initialization, mutex operations and allocation.
Use SYSTEM for cross-library TLS if custom linking conceals both control
references and the imports that identify the local runtime.

When a PRIVATE module creates a key with a destructor in a private image,
Bionic's `pthread_getspecific` still returns its original value.
Set and delete that key through a PRIVATE module of the creating Core so it
can track its lifetime. Direct imports in ordinary PRIVATE modules and Core's
`dlsym` or `dlvsym` lookups through
`RTLD_DEFAULT`, `RTLD_NEXT` or a PRIVATE handle use Core wrappers when their
scope and symbol version select Bionic's key functions. A dependency can supply
its own version, and an unresolved weak import stays null. Lookups through an
explicit libc handle use Bionic's functions. Hosts that need to set or delete
a key can call a module function or create their own system key.
Trusted PRIVATE relocations to Bionic's `pthread_setspecific` or
`pthread_key_delete` also bind Core's wrappers. Close these modules normally
so that the wrapper addresses stay valid for the lifetime of the mapping.
Trusted code calling Bionic's own `dlsym` uses the system scope.
This tracking also covers a trusted PRIVATE destructor registered by an
ordinary PRIVATE module. A live value retains the destructor's mapping through
the callback. Delete the key before transferring that mapping with `release_host`.
After the destructor's image finishes finalization, setting a non-null value
returns `EINVAL` even if unmapping needs a retry. The public key stays reserved
until its holder explicitly deletes it. A surviving module can clear or delete
the key after the destructor's image has unloaded.
If a destructor sets its value again on Bionic's final pass, later destructors
on that thread can still read it. Core retains the owning image until the
value is cleared, the key is deleted or the thread exits.

Releasing a module while another thread owns emutls storage can report TLS
retention. After those threads and their destructors finish, the host can
complete the existing close and shutdown sequence. If TLS was first touched
in the last pthread destructor round, close can report retention after
`pthread_join` wakes. A collector on another thread checks the old numeric
TID. If the kernel has already reused it, retention can last until the
replacement thread exits. Retry the released handle until it reports unmapping.

A PRIVATE ELF finalizer or C++ global destructor can initialize thread-local
storage during ordinary close or namespace destruction. While a finalizer is
running, its workers can also acquire TLS in the image or its live dependencies.
A live TLS value or thread destructor keeps those mappings available. The runtime
resumes the remaining global destructors and ELF finalizers in order after
those holds drain. Each destructor runs once. Ordinary close returns a retained
handle with its open reference released. Namespace destruction can return
`IO_ERROR` after finalization has begun. Keep the handle or namespace token and
retry the operation after the thread exits. Both TLS destructors and resumed
global destructors can enumerate program headers and look up functions and data
in the module and its live dependencies. Lookups by name skip native ELF TLS
definitions (`STT_TLS`) in images in the `Closing` phase, even when the calling
thread already has storage for the variable.
A new emutls block allocated during pthread key cleanup stays live through
the next key callbacks, including when the thread already has other blocks.
Core keeps the thread's TLS storage while any of its managed pthread key
callbacks are pending or running. A callback can pass an existing variable's
address to another key and read the same object in a later destructor round.
A C++ thread destructor registered during pthread key cleanup retains its
record, Core-managed thread storage and code until the callback runs or the thread exits.
This lets Bionic run the callback if another key destructor calls `exit()`.

After a controlled fork, the child can resume a suspended close when the
threads holding TLS are gone. Even when a third thread called fork, the child
releases the pins for C++ thread and pthread key destructors that were running
on the vanished threads. A destructor that called fork keeps its pin until it
returns in the child.

Bionic runs atfork handlers under its atfork mutex. Core calls libc's
destructor registration directly, so on Android 8.x an earlier prepare
handler can first-touch a PRIVATE C++ thread-local object. On Android 9 and later,
libc also takes the system linker mutex to pin the destructor's DSO. A
concurrent DSO constructor can hold that mutex while registering an atfork
handler. Initialize the object on the forking thread before fork on these
versions, or drain system linker operations and keep them quiescent through
fork to allow first use inside a handler. The host owns this synchronization
even with controlled fork brackets.

If another thread is initializing a local compiler-rt inside `pthread_once`,
it can finish creating its key before fork proceeds. The object's destructor
is registered for the surviving thread in both processes. If an earlier child
handler calls the module's `pthread_once`, its first Core operation restores
the fork state before acquiring the recursive operation mutex. On its next
call the child retries a control in a PRIVATE image left running by a vanished thread.
Previously published side effects remain visible. Fork recovery leaves
application-supplied control storage untouched, including shared mappings and
pages excluded from fork. If the child needs a control outside a PRIVATE
image that another thread is initializing, let that initializer finish
before fork. An initializer on the thread that called fork continues in
both processes.

Locally bound NDK compiler-rt also uses its own mutex to assign an index on
the first access to each variable. This mutex can live entirely inside a
stripped module. Before a fork whose child will use that runtime, the host
must stop admitting calls that could first-touch its TLS and let in-flight
calls finish, including module callbacks and thread destructors. Keep those
callers quiescent through fork, including when using the runtime's registered
atfork handlers alone. The child can then first-touch a new variable, including
in an atfork handler. Core-managed emutls already serializes allocation with fork.

Normal process exit runs the remaining global destructors
even when the exiting thread still has pthread key values.
If another thread is already running a finalizer for the image, it continues
the remaining steps in order when its current callback returns.

Traditional AArch64 dynamic TLS relocation numbers differ between the pinned NDK
and some Bionic releases. PRIVATE rejects the ambiguous pair before resolvers or
constructors run. AArch64 TLSDESC and supported ARM32 dynamic TLS are available.
On `riscv64`, PRIVATE requires the Android LP64D calling convention. The ELF
header must specify `EF_RISCV_FLOAT_ABI_DOUBLE` and leave `EF_RISCV_RVE`,
`EF_RISCV_RV64ILP32`, and `EF_RISCV_RVY` clear.
An image marked `EF_RISCV_TSO` requires the Ztso CPU mask from `riscv_hwprobe`
to cover every CPU in `/sys/devices/system/cpu/possible`. An offline CPU, a
CPU without Ztso, an ID outside the probe mask, or an unreadable CPU list
causes PRIVATE to return `UNSUPPORTED` before execution.
PRIVATE supports the default `R_RISCV_TLSDESC` and traditional dynamic TLS
(`__tls_get_addr` with the psABI `0x800` `TLS_DTV_OFFSET`). The descriptor
resolver preserves caller-saved GPRs, floating-point state, all 32 RVV
registers, `vl`, `vtype`, `vcsr`, and `vstart` on both initial and repeated lookups. Clang
in the Android NDK can keep vector registers live across TLSDESC calls. At VLEN
up to 256 bits, the resolver uses up to 1,376 bytes of stack. At larger widths,
it uses a 400-byte frame and borrows a separate register file from its Core when
one is available. Trusted PRIVATE images that bind Core-backed TLSDESC entries
remain owned by Core and cannot be transferred with `release_host`.
The Core reuses these files across bursts of calls. Each bank reserves files for
the forking thread, including earlier child handlers. Eight separate files serve
nested signals on the thread holding the bank's last ordinary slot. Each thread
with native TLS storage also has an eight-file reserve for lookups when other
threads occupy every ordinary slot. Core reassigns the reserve after the native
TLS tag and every outstanding file have been released. If ordinary callers are
waiting for the Core's operation mutex, its owner can use eight files reserved
for that owner in each bank.

The first wide TLSDESC binding reserves a Core-owned, anonymous, demand-zero
virtual address range. It requests one ordinary file per possible Linux TID.
With 4 KiB pages, each Core requests 11.25 GiB at VLEN 512 or 22.25 GiB at VLEN
1024. Core retries smaller ranges down to one bank if the address space cannot
accommodate the request. The successful reservation bounds simultaneous shared
borrows. Only touched pages acquire private backing. On slot exhaustion the
resolver links the next bank by address within this reservation using integer
instructions. The successor is deterministic, so another thread can link it if
the first borrower is preempted or exits. When a caller cannot borrow a file,
the resolver uses an additional `32 * vlenb` bytes on the current stack.
Applications that can exhaust the reserve need this space for each such lookup,
including on an alternate signal stack.

Before binding the first wide-vector descriptor, Core verifies the Bionic
thread ID, recursive mutex owner and pthread key layout against the running libc
without allocating file descriptors. An incompatible layout returns
`UNSUPPORTED` with the TLSDESC relocation's type and offset.
Wide descriptors use a 32 MiB thread-pointer index alongside the 4 MiB pin
table. Each borrower writes the entry for its kernel TID.
The resolver arms a thread-exit key before borrowing a file. After a
`siglongjmp` during vector save or restore, another lookup at the same frame
address can reclaim its file. Files abandoned at other depths can remain
until thread exit, including when a signal handler jumps over an inner lookup
and returns to the outer resolver. Thread exit releases the remaining files.
If an application abandons a lookup in the final pthread destructor pass,
module collection or a stats query reclaims its files after the kernel confirms
exit, even if the thread never acquired a native TLS block.
The application's pthread cleanup chain survives the jump. A live peer with
an abandoned lookup keeps the Core available through its thread-exit callback.
When that callback can obtain a thread pidfd, Core verifies the original
thread's exit even if its kernel TID is reused. A later descriptor enrollment
can replace this watch. If the callback is missed or a thread pidfd is
unavailable, Core retains the pin until it can confirm exit by TID; a reused
TID in the same process can delay that confirmation.
After a fork, the child keeps the surviving thread's borrows and scans only
the pin-table chunks reached by borrowers. It inherits the Core's reservation,
and only banks reached by a borrower need inspection. Growth uses that same
reservation in each process and can proceed with the fd table full. The runtime's
`mapped_bytes` includes the reservation and per-thread mappings until each unmap
succeeds. If the first save area cannot be mapped,
loading reports the mapping's errno and the TLSDESC relocation's type and offset.
If the first pool setup fails, Core releases the provisional pthread key,
TID tables and thread reserves. Existing native TLS blocks remain usable.
Core also discards a provisional pool if the first load fails after setup and
no image or live borrower still needs it. Failed unmaps remain accounted for
and can be retried.
If a direct TLS symbol lookup cannot map its thread's reserve, the lookup
reports the mapping's errno at the metadata stage and identifies the requested symbol.
The Core passes `(AT_HWCAP, __riscv_hwprobe, nullptr)` to IFUNC resolvers and
rejects non-zero `GNU_PROPERTY_RISCV_FEATURE_1_AND` bits before execution.
On x86 and x86_64, PRIVATE handles traditional dynamic TLS. The i386 accessor
is `___tls_get_addr` with a register argument and the x86_64 accessor is
`__tls_get_addr`. PRIVATE refuses x86 TLS descriptors and initial-exec references
to dynamically allocated private TLS blocks. SYSTEM follows its host's relocation
conventions.

PRIVATE validates load-segment permissions and rejects writable executable
mappings. Writable file-backed segments can clear their last file page through
the writable mapping. Executable segments needing a writable zero-tail view are
subject to host mapping permissions and policy. SELinux and executable-memory
policy can cause refusal with the corresponding error detail.

## Instrumentation

Cross-DSO CFI requires API 27 or newer, where the NDK exposes the Bionic CFI
slow path. The CFI runtime belongs to its containing system-loaded Core. Compile
Core and system modules with compatible cross-DSO CFI settings. A CFI runtime refuses PRIVATE
loading before execution. Use the ordinary private bootstrap route with its
matching Core configuration.

The sanitizer option selects NDK instrumentation. The containing host and module
closure must supply compatible runtime services. Instrumented execution depends
on the target Android environment.

## Validation boundaries

The API 26 builds ran the three Native hosts and the four C/C++ archive and
source consumers under QEMU user mode on all four ABIs. Both ARM runtimes came
from the Nexus 5X Android 8.0 factory image OPR6.170623.013 (build 4283548).
The x86 and x86_64 runtimes came from their respective Android SDK default
images, revision 1 (build 4931640). The same API 26 executables and modules
also ran on the API 31 x86 and API 34 ARM Bionic runtimes. These runs exercised
the Android userspace linker and libc with the Linux host kernel.

Native hosts cover C/C++ consumption, retained cleanup, callback and fork lifetime,
and actual two-stage unloading. Earlier builds on both x86 ABIs ran all three hosts and the four
C/C++ archive and source consumers in full Android emulators on API 31, 34 and
36. The 32-bit tests used native x86 Android TV images. The 64-bit tests used
AOSP images on API 31 and 34 and a Google APIs image on API 36. All six guests
used 4 KiB kernel pages.

The same x86_64 binaries also passed on the API 36 Google APIs experimental
16 KiB image (revision 7, build 13894323). Both `getconf PAGE_SIZE` and
`AT_PAGESZ` reported 16384 for userspace. The underlying x86_64 kernel and MMU
reported 4 KiB pages in `/proc/self/smaps`. The C++ host verified read-only RELRO
pages for anonymous and file-backed loads, then verified that both unloaded.
All 19 bootstrap handoff cases passed, along with the four-thread load/close
test and the C and C++ hosts built with cross-DSO CFI.

API 31 Bionic under QEMU user mode also covered repeated bootstrap handoffs,
concurrent PRIVATE and SYSTEM loading in one runtime, and the CFI configuration
on both x86 ABIs. ARM regression runs used a dual-ABI AOSP API 34 Bionic build
under QEMU.

The initial `riscv64` implementation ran on Android 17 (`riscv64`, API 37) in the
AOSP Cuttlefish emulator (`16968706`,
`generic/aosp_cf_riscv64_phone/vsoc_riscv64:17/CP2A.260605.016/16968706:userdebug/test-keys`,
Linux `6.19.0-mainline-g365b87b792fe-ab15017353`, 4096-byte page size, SELinux `Enforcing`,
`uid=2000(shell)` with zero capabilities) under bundled QEMU (`-cpu rva23s64`). The Cuttlefish
run verified `c_host`, `cpp_host`, `bootstrap_host`, all five C/C++ archive, source and `noexcept`
`--system` consumer Cores, and the cross-DSO CFI `c_host`, `cpp_host` and `--system` consumer
Core, including RVV/FP/GPR-preserving `TLSDESC`, `__riscv_hwprobe` IFUNC, `IRELATIVE`, `trad`
TLS, `caller_stub`, `call_barrier`, `GNU_PROPERTY_RISCV_FEATURE_1_AND` rejection and
`libemutls_runtime.so` support. Under the same Cuttlefish guest, all 45 project-built `riscv64`
shared objects link with `PT_LOAD` alignment `0x4000`, and re-running the entire 11-target host,
consumer and CFI suite with `yukilinker_c_host_services.page_size = 16384` passed (`EXIT=0`),
verifying 16 KiB `load_bias` alignment, `host_services_bind` validation, 4 KiB-aligned ELF
rejection, 16 KiB `RELRO` mapping/sharing and `android_dlopen_ext` `LIBRARY_FD_OFFSET` and
`RESERVED_ADDRESS` enforcement on top of the 4 KiB kernel.

The anonymous spill reservation was tested on the same Cuttlefish image with
VLEN 1024. All 11 Native host, SDK consumer and cross-DSO CFI cases passed with
both the default and 16 KiB loader page sizes on the 4 KiB kernel. Wide TLS
coverage included growth with a full fd table, fork with an active borrow in
the second bank, nested signals, thread exit and shutdown retry. QEMU user-mode
TLS tests covered VLEN 128, 256, 512 and 1024 at both loader page sizes.

Physical `riscv64` hardware and a native 16 KiB-kernel / `AT_PAGESZ=16384`
`riscv64` Android guest remain unverified. Record the image, emulator version,
linker and library hashes when reproducing results. Device policy, Java VM
lifecycle and application integration require verification in the consuming
application's environment.
