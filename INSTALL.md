# Installing Azzurra IRC Services

This document describes how to build and deploy the services binary from
source on a Debian/Ubuntu system.  Other distros work too — only the
package names change.

## 1. Build dependencies

Services is C89 with no third-party library dependencies beyond the
standard C runtime and the system resolver.  On Debian/Ubuntu:

    apt install build-essential libc6-dev

That is all.  (Historical INSTALL notes mentioned `libssl-dev`; services
does not use OpenSSL — password hashing is done internally via
`crypt_shs1.c` — so it can be omitted.)

## 2. Configure

From the repository root:

    ./configure

The configure script probes for a compiler (gcc preferred), detects
whether the system is 32-bit or 64-bit via `getconf LONG_BIT`, checks
for `sys/resource.h`, `strerror` / `sys_errlist`, `snprintf`,
`strsignal`, `gethostbyname`, and tries a handful of link libraries
(`-lnsl`, `-lsocket`, `-lresolv`, `-lbsd`) to see which are needed.

Output: `inc/sysconf.h` and `Makefile.inc`.  The latter sets
`-DOS_32BIT` or `-DOS_64BIT` automatically based on `LONG_BIT`, which
selects the on-disk layout for `.clng` language files and the database
format.

Options (all optional):

    ./configure -cc gcc            # pin a specific compiler
    ./configure -cflags "-O2"      # override default CFLAGS
    ./configure -lflags "-Wl,..."  # extra linker flags
    ./configure -libs  "-l..."     # extra link libraries

## 3. Build

    make

Produces the `services` binary in the repo root.  To force a full
rebuild use `make distclean && ./configure && make`.

## 4. Runtime layout

The repository ships a ready-to-run tree under `run/`:

    run/
      bin/             <-- drop the compiled binary here
      data/
        helpfiles/     <-- user-facing help, per language (us/it/es/fr)
        ohelpfiles/    <-- oper-only help
        lang/          <-- compiled .clng language files

Install the binary:

    cp services run/bin/services

Compile the language files (if you modified `lang/*.lang`):

    cd lang && ./langcomp && cd ..

`lang/langcomp` is a 32-bit ELF binary shipped with the repository.  On
a 64-bit host you need multilib to run it:

    apt install libc6-i386

It reads `lang/{English,Italian,Spanish,French}.lang`, emits
`run/data/lang/svc{0..3}.clng` and regenerates `inc/lang_msg_svc.h`.

## 5. Configuration

Copy the example configs and edit them to match your ircd:

    cd run/data
    cp ../../doc/services.conf.example ./services.conf
    cp ../../doc/lang.conf.example     ./lang.conf
    cp ../../doc/services.motd.example ./services.motd
    cp ../../doc/crypt.key.example     ./crypt.key    # only if encryption is enabled

Edit `services.conf` — at minimum the `C:` line (services name, link
password, remote server IP, port) and the `D:` / `U:` / `O:` lines.
The example file documents every directive inline.

`crypt.key` contains the symmetric key used to encrypt password and
e-mail fields in the on-disk database.  Generate a fresh one per
deployment; never reuse the example.

## 6. Running

From `run/`:

    ./bin/services

Services links to the IRC network on startup using the `C:` line.  Logs
land in `run/data/logs/` and the database in `run/data/*.db`.

On first start, services will create an empty database.  Register the
network founder nick via `/msg NickServ REGISTER`, then use `/msg
RootServ ...` to set up the initial oper list (see `SECURITY
CHEATSHEET`).

## 7. Upgrading

1. Stop services.
2. `git pull` (or swap in the new source tree).
3. `make distclean && ./configure && make`.
4. `cp services run/bin/services`.
5. `python3 lang/langcomp.py` if any `lang/*.lang` changed.
6. Start services.

The on-disk database format has been stable across the 64-bit
transition; a backup before upgrading is still advised.

## Troubleshooting

* `configure` aborts on `snprintf` — your libc is too old, upgrade.
* `make` warnings about shadowed locals are expected; `-Wshadow` is on
  by default and the codebase has a few surviving hits.
* Services refuses to start with a corrupt `.clng` — rerun
  `lang/langcomp.py` to regenerate.
* `sysconf.h` out of sync after a kernel/libc upgrade — `make
  distclean && ./configure && make`.

See also `SECURITY CHEATSHEET` (in-tree) for operational security
notes.
