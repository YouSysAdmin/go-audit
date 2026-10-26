# go-audit

![go-audit](/docs/logo/go-audit-logo-color.svg)

[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)

go-audit is an alternative to the auditd daemon. It reads kernel audit records over
netlink, groups the records of one event together and writes each event as a single
JSON line.

- Talks to the kernel directly over `NETLINK_AUDIT`, no auditd daemon is needed
- One JSON line per event, ready for Fluent Bit, Vector or any log shipper
- Outputs: stdout, a local file (reopened on `SIGUSR1`) or syslog
- Optional enrichment with usernames, the cgroup path and the container id
- Regex filters to drop noisy events before they are written

## IMPORTANT
Audit logs may contain sensitive data.

Care should be taken regarding who has access to a location where these logs are stored.


## Event format

Every event is one JSON line. The common fields are lifted to the top and parsed,
every record is kept in `records` with its fields decoded:

```json
{
  "time": "2016-03-30T22:27:46.885Z",
  "sequence": 1222763,
  "host": "web-1",
  "tags": { "env": "prod" },
  "key": "user-commands",
  "syscall": {
    "nr": 59,
    "name": "execve",
    "arch": "x86_64",
    "success": true,
    "exit": 0
  },
  "process": {
    "pid": 11623,
    "ppid": 11552,
    "comm": "ls",
    "exe": "/bin/ls",
    "cwd": "/home/ubuntu",
    "args": ["ls", "--color=auto", "-alF"],
    "title": "ls --color=auto -alF",
    "tty": "pts0",
    "session": 35
  },
  "user": {
    "auid": 1000,
    "auid_name": "ubuntu",
    "uid": 1000,
    "uid_name": "ubuntu",
    "euid": 1000,
    "euid_name": "ubuntu",
    "suid": 1000,
    "fsuid": 1000,
    "gid": 1000,
    "gid_name": "ubuntu",
    "egid": 1000,
    "sgid": 1000,
    "fsgid": 1000
  },
  "paths": [
    {
      "item": 0,
      "name": "/bin/ls",
      "inode": 262316,
      "dev": "ca:01",
      "mode": "0100755",
      "ouid": 0,
      "ogid": 0,
      "nametype": "NORMAL"
    }
  ],
  "container": {
    "id": "5c69ff1a4edf85228df5153f36cacbdee440ad6fd585704e77f50f54d3e58249"
  },
  "cgroup": "/system.slice/ssh.service",
  "records": [
    {
      "type": "SYSCALL",
      "type_id": 1300,
      "fields": {
        "arch": "c000003e",
        "syscall": "59",
        "success": "yes",
        "pid": "11623",
        "comm": "ls",
        "...": "..."
      }
    },
    {
      "type": "EXECVE",
      "type_id": 1309,
      "fields": { "argc": "3", "a0": "ls", "a1": "--color=auto", "a2": "-alF" }
    },
    { "type": "CWD", "type_id": 1307, "fields": { "cwd": "/home/ubuntu" } },
    {
      "type": "PATH",
      "type_id": 1302,
      "fields": { "item": "0", "name": "/bin/ls", "...": "..." }
    },
    {
      "type": "PROCTITLE",
      "type_id": 1327,
      "fields": { "proctitle": "ls --color=auto -alF" }
    }
  ]
}
```

| Field                 | Source                                                                                       |
| --------------------- | -------------------------------------------------------------------------------------------- |
| `time`                | kernel timestamp, RFC 3339 in UTC with milliseconds                                          |
| `sequence`            | kernel event sequence number, gaps mean lost events                                          |
| `host`, `tags`        | `event.host` and `tags` in the config                                                        |
| `key`                 | the `-k` key of the matching rule, several keys are joined with `,`                          |
| `syscall`             | SYSCALL record, `name` resolved for x86_64, i386, aarch64 and arm                            |
| `process`             | SYSCALL, EXECVE (`args`), PROCTITLE (`title`) and CWD records                                |
| `user`                | ids from the SYSCALL record, `*_name` when the id is in `/etc/passwd` or `/etc/group`       |
| `paths`               | one entry per PATH record                                                                    |
| `network`             | decoded SOCKADDR: `family` (`inet`, `inet6`, `unix`, `netlink`), `address`, `port` or `path` |
| `container`, `cgroup` | `extras.containers` and `extras.cgroups`                                                     |
| `records`             | every record with `type`, `type_id` and parsed `fields`, plus `raw` with `event.raw: true`   |

Sections are left out when the event has no record they come from, for example a
CONFIG_CHANGE event only has `time`, `sequence`, `host`, `tags` and `records`.
Hex encoded values (`proctitle`, `exe`, `name`, EXECVE arguments and others) are
decoded in both the top level fields and `records[].fields`.

## Install

Download a deb, rpm or tar.gz package for linux amd64 or arm64 from the
[releases](https://github.com/yousysadmin/go-audit/releases) page.

### Requirements

- Linux kernel 3.2 or later with `CONFIG_AUDIT` and `CONFIG_AUDITSYSCALL`, which
  common distributions enable
- Any x86-64 or ARMv8 CPU
- Root, or at least `CAP_AUDIT_CONTROL`. In a container go-audit needs the host
  PID namespace (`--pid=host`) and the audit capabilities
- `auditctl` to install the rules

The binary is static, it does not depend on the glibc version and also runs on
musl based systems such as Alpine. Because of that, user and group names are
resolved from `/etc/passwd` and `/etc/group` only. Users that come from LDAP,
SSSD or FreeIPA keep their numeric ids in the event but get no `*_name` field.

The packages install:

| Path                                       |                                                 |
| ------------------------------------------ | ----------------------------------------------- |
| `/usr/local/bin/go-audit`                  | the binary                                      |
| `/etc/go-audit.example.yaml`               | example config, copy it to `/etc/go-audit.yaml` |
| `/usr/lib/systemd/system/go-audit.service` | systemd unit, not enabled automatically         |
| `/etc/logrotate.d/go-audit`                | rotation for the file output                    |
| `/var/log/go-audit`                        | directory for the file output                   |

`auditctl` (package `auditd` on Debian and Ubuntu, `audit` on RHEL) is required to
install the rules. The auditd service itself must not run, only one process can be
the audit daemon.

```sh
sudo cp /etc/go-audit.example.yaml /etc/go-audit.yaml
sudo systemctl disable --now auditd
sudo systemctl enable --now go-audit
```

The unit restarts go-audit when it fails and runs it sandboxed: the file system
is read only apart from `/var/log/go-audit`. Variables for `${VAR}` in `tags` go to
`/etc/default/go-audit` or `/etc/sysconfig/go-audit`. To write the output or the
logs somewhere else, allow the directory with `systemctl edit go-audit`:

```ini
[Service]
ReadWritePaths=/data/audit
```

## Running

```sh
go-audit --config /etc/go-audit.yaml
go-audit version
```

go-audit needs root, or at least `CAP_AUDIT_CONTROL`. At startup it flushes the
existing audit rules and installs the ones from the config.

| Signal              |                                           |
| ------------------- | ----------------------------------------- |
| `SIGTERM`, `SIGINT` | write the pending events and exit         |
| `SIGUSR1`           | reopen the output file, used by logrotate |

Exit codes: `0` on success, `2` on a usage error (unknown flag, missing `--config`),
`1` on any other error.

## Configuration

See [go-audit.example.yaml](go-audit.example.yaml) for every option and
[examples/go-audit.yaml](examples/go-audit.yaml) for a server profile with a CIS style
rule set, checked against `auditctl` on amd64 and arm64. The main sections:

| Section            |                                                                                      |
| ------------------ | ------------------------------------------------------------------------------------ |
| `output`           | where events go, exactly one of `stdout`, `file` or `syslog`                         |
| `logging`          | go-audit's own log lines: level, `json` or `text`, `stderr`, `stdout` or a file path |
| `rules`            | `auditctl` rules, installed in order at startup                                      |
| `filters`          | drop events by syscall name or number, record type and a regex on the record data    |
| `events`           | range of record types to keep, 1300 to 1399 by default                               |
| `message_tracking` | report sequence gaps, which mean lost events                                         |
| `socket_buffer`    | netlink receive buffer size                                                          |
| `extras`           | `cgroups` adds the cgroup path, `containers` adds the container id                   |
| `tags`             | key value pairs added to every event, `${VAR}` is expanded from the environment      |
| `event`            | `host` adds the hostname (on by default), `raw` keeps the raw record text            |

Audit events and go-audit's own logs are separate streams. With `output.stdout`
enabled, `logging.output` must not be `stdout`.

### Shipping with Fluent Bit

Write events to a file and tail it:

```yaml
# /etc/go-audit.yaml
output:
  file:
    enabled: true   # /var/log/go-audit/go-audit.log, mode 0600, owned by root
```

```ini
# fluent-bit.conf, the json parser comes from the default parsers.conf
[INPUT]
    Name    tail
    Path    /var/log/go-audit/go-audit.log
    Parser  json
    Tag     go-audit
```

## Development

Linux only, the code uses netlink. Requires Go 1.27 and [task](https://taskfile.dev).

| Task                           |                                                                                            |
| ------------------------------ | ------------------------------------------------------------------------------------------ |
| `task build`                   | build a static Linux `bin/go-audit`                                                                       |
| `task test`                    | unit tests with the race detector                                                          |
| `task check`                   | gofmt, vet, golangci-lint and tests, the same gate CI runs                                 |
| `task vulncheck`               | govulncheck against the Linux build                                                        |
| `task modernize`               | show the `go fix` modernizations that would apply                                          |
| `task cover`                   | tests with an HTML coverage report                                                         |
| `task bench`, `task bench-cpu` | benchmarks, `BENCHTIME=60s task bench-cpu` for a long profile                              |
| `task release-snapshot`        | local [GoReleaser](https://goreleaser.com) build of the archives and packages into `dist/` |

Releases are published by GoReleaser when a `v*` tag is pushed.

## FAQ

#### The logs show `failed to receive message` with `no buffer space available`

go-audit is not reading as fast as the kernel produces events. Reduce the number of
events with more specific rules or filters, or raise `socket_buffer.receive`:

```yaml
socket_buffer:
  receive: 16777216
```

The kernel caps the buffer at `net.core.rmem_max`, raise it too:

```sh
sudo sysctl -w net.core.rmem_max=16777216
```

#### Some records have no file `name`, only an `inode`

The kernel does not always know the file name. An inode can be mapped back to a
name, though not necessarily the one that was used:

```sh
sudo debugfs -R "ncheck <inode>" /dev/<block device>
```

#### PAM records show `hostname="?"` or `addr="?"`

That is how PAM and libaudit write an unknown value. Local sessions such as cron,
su or sudo have no remote host, so both fields are `?`.

#### Every cron job adds a burst of USER_* events

With `events.min` below 1300, PAM records are kept, and every cron run writes
USER_ACCT, CRED_ACQ, LOGIN, USER_START, CRED_DISP and USER_END. A filter without
`syscall` and `message_type` tests every record of events that have no SYSCALL
record, one entry drops them all:

```yaml
filters:
  - regex: terminal=cron
```

#### Which syslog priority should I use?

`priority = facility * 8 + severity`. The default 132 is `local0` (16) and
`warning` (4). See the [syslog](https://en.wikipedia.org/wiki/Syslog) page for the
facility and severity numbers.

#### Every event shows up twice in syslog

journald also reads audit events. Disable that with:

```sh
sudo systemctl mask systemd-journald-audit.socket
```
