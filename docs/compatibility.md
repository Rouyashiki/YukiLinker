# Supported configurations

The SDK supports ARM64, ARM32, x86 and x86_64 Android processes on API 31 and
newer. Each build handles its native ELF class and machine. The two 32-bit ABIs
share the v1 public record layouts, including eight-byte alignment for 64-bit
fields. Runtime page size comes from the host. Libraries use 16 KiB maximum LOAD
alignment.

## Backend selection

PRIVATE manages ELF mappings, private dependency scopes, constructors and
supported dynamic TLS. SYSTEM delegates loading and symbol resolution to
HostServices and Bionic. Use SYSTEM for a component closure sharing Bionic TLS,
libc++, cross-DSO exceptions or CFI.

The host coordinates code-pointer lifetime, thread exit, callbacks and Core
retirement. PRIVATE call barriers contain escaping exceptions where required by
the ABI. C API callbacks must obey their declared signatures.

## TLS and executable mappings

Traditional AArch64 dynamic TLS relocation numbers differ between the pinned NDK
and some Bionic releases. PRIVATE rejects the ambiguous pair before resolvers or
constructors run. AArch64 TLSDESC and supported ARM32 dynamic TLS are available.
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

CFI runtime belongs to its containing system-loaded Core. Compile Core and system
modules with compatible cross-DSO CFI settings. A CFI runtime refuses PRIVATE
loading before execution. Use the ordinary private bootstrap route with its
matching Core configuration.

The sanitizer option selects NDK instrumentation. The containing host and module
closure must supply compatible runtime services. Instrumented execution depends
on the target Android environment.

## Validation boundaries

Native hosts cover C/C++ consumption, retained cleanup, callback and fork lifetime,
and actual two-stage unloading. Both x86 ABIs ran all three hosts and the four
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
under QEMU. Record the image, emulator version, linker and library hashes when
reproducing results. Device policy, Java VM lifecycle and application integration
require verification in the consuming application's environment.
