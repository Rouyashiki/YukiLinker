# Ownership and bootstrap handoff

Every Core contains its own runtime, linked from the archive or compiled from
sources. Core owns HostServices callbacks, module handles and runtime state.
An external caller loads `libyloaderXX.so` through Bionic and transfers its one
loader reference through the bootstrap protocol.

## Module retirement

Stop new calls and drain users before releasing module code or callback storage.
A returned function pointer can outlive the lookup that produced it. Execution,
unwind, CFI and bridge leases protect the corresponding image lifetime. TLS
blocks and callbacks can also retain an image.

SYSTEM close releases a Bionic reference. PRIVATE close also reports mapping
removal. Inspect `handle_valid`, reference state, retention reasons and cleanup
diagnostics. A released PRIVATE wrapper can remain valid while the image is
retained, and close can retry incomplete cleanup. `forget` drops an eligible
released wrapper while other owners protect the image.

Shutdown can refuse before it begins or return a resumable state after crossing
its admission boundary. Finish outstanding modules and observations, retry
cleanup, destroy runtime, then retire Core from an external continuation.

## Bootstrap protocol

The normal entry is `yuki_bootstrap(int core_fd, int early_packet_fd_plus1)`.
ARM32 also exposes the five-argument `yuki_bootstrap_tango` declared in the C
header. Tango restores the injected GOT slot and page protection and transfers
the stub through the Core protocol.

1. Bootstrap validates inputs and claims one operation. The reduced loader maps
   Core and validates its handoff exports before initialization.
2. Core adopts its anonymous image and the original loader reference, receives
   `zygisk_core_entry`, and initializes its embedded runtime.
3. `zygisk_bootstrap_handoff_ready` confirms that long-lived callbacks and runtime
   state belong to Core. `zygisk_bootstrap_take_dependencies` accepts the exact
   system dependency references acquired while loading it.
4. Bootstrap releases loading metadata and completes
   `zygisk_bootstrap_finish_handoff`.
5. A forced tail call enters the matching Core finalizer. Core releases the
   original Bionic reference with `dlclose`. Execution returns through the Core
   continuation after loader removal.

The caller transfers its sole application loader reference. Additional references
would keep bootstrap mapped. Core must own all code pointers and storage needed
after its finalizer releases loader.

| Resource | Owner after successful handoff | Final release |
| --- | --- | --- |
| Core mapping | Core | External continuation after Core shutdown |
| Original loader reference | Core | Core finalizer calls Bionic `dlclose` |
| Accepted system dependencies | Core | After runtime and callback teardown |
| Loading metadata | Bootstrap until release | Before handoff completion |
| Runtime and HostServices | Core | While Core code is callable |

Early-packet wire version is 3. Its layout and constants are in `yukilinker.h`.
The transport transfers descriptors and cleans up failed loads. Endpoint
connections and application configuration belong to Core.

## Failure and fork

A failure before Core execution can admit retry after complete rollback.
Execution followed by rejected handoff or incomplete cleanup retains required
mappings and references. Core must accept dependencies before bootstrap clears
its ownership. Reentrant and concurrent calls refuse duplicate transfer.
Inputs rejected at admission stay with their caller.

The loader claim includes process identity. A fork child rejects inherited
incomplete handoff and checks descriptor identity during cleanup so a reused
fd number retains its current resource.

Coordinate host activity, call `prepare_fork`, fork, then call `after_fork` in
both processes with the corresponding child flag. Destroy runtime before
unloading Core so TLS keys and libc callback registrations can retire while
their code is still callable.
