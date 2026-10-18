# Captured fixtures

Every file here was **copied from a real machine**, never written from memory. The rule in
`AGENTS.md` §10 is that a collector's parser has a fixture and the fixture is sanitised; this
file is the record of where each one came from and what was changed.

## `linux/`

Captured inside **Ubuntu on WSL2** (kernel `5.15.133.1-microsoft-standard-WSL2`) on
2026-10-18, from the distribution's own files. Nothing was edited: the files are byte copies,
and a `rg`-free reading of them shows no personal data.

| File | Source | What it proves |
|---|---|---|
| `crontab` | `/etc/crontab` | a system crontab line has five schedule fields, a user, then the command — and `run-parts` lines are the ordinary case |
| `cron.d/e2scrub_all` | `/etc/cron.d/e2scrub_all` | the same shape in a drop-in file |
| `profile.d/apps-bin-path.sh` | `/etc/profile.d/` | a shell startup file that only sets `PATH` |
| `profile.d/Z99-cloudinit-warnings.sh` | `/etc/profile.d/` | a startup file that prints a warning |
| `modprobe.d/blacklist.conf` | `/etc/modprobe.d/` | a distribution's module configuration with **no** `install` line, which is the ordinary case |
| `udev/50-apport.rules` | `/usr/lib/udev/rules.d/` | a udev rule that runs a program on a device event (`RUN+=`) |
| `ld.so.conf.d/libc.conf`, `ld.so.conf.d/x86_64-linux-gnu.conf` | `/etc/ld.so.conf.d/` | a loader configuration that names directories, not libraries |
| `bashrc` | `~/.bashrc` of the capture user | a login script a person owns |

**Captured absences**, which are facts too: `/etc/ld.so.preload` does not exist on this
machine, `/etc/udev/rules.d` is empty (the distribution's rules live in `/usr/lib/udev`), and
no `modprobe.d` file on it has an `install` line. The parser tests treat those as the ordinary
case rather than as an error.

## `registry/`

Captured on **Windows** from the maintainer's own machine with `reg query`. Sanitised: the
user's profile path is `C:\Users\user`, unrelated entries were removed, and each file says in
its own JSON what it is and what was changed.

## `tasks/`

One scheduled task captured with `schtasks /query /xml`, re-encoded from UTF-16 to UTF-8, with
the machine's `SecurityDescriptor` replaced by a generic one. The file carries the same note in
an XML comment.

## Adding a fixture

Copy the file, keep it small, replace anything that identifies a person or a machine, and add
a row to this table. A parser without a row here is a parser nobody has checked against a
real machine, and the collector that uses it should say so in its status instead.