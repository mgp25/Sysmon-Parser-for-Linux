# Sysmon Parser for Linux

Python script for parsing logs generated by Sysinternals Sysmon for Linux.

## Usage

```
usage: sysmonviewer.py [-h] -f FILE [-e EVENT] [-u USER] [-p PROCESS] [-pg PROCESSG] [-ppg PPROCESSG] [-ep] [-c] [-eu]

Sysmon parser

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  File to parse.
  -e EVENT, --event EVENT
                        Event type to filter.
  -u USER, --user USER  User to filter.
  -p PROCESS, --process PROCESS
                        Process ID to filter.
  -pg PROCESSG, --processg PROCESSG
                        Process GUID to filter.
  -ppg PPROCESSG, --pprocessg PPROCESSG
                        Parent Process GUID to filter.
  -ep, --elevated       Elevated processes to filter.
  -c, --commands        Commands only.
  -eu, --enumusers      Enumerate users.
  ```

## Examples

- Shows all events of type `ProcessCreate` and user `nelson`:

```
❯ python sysmonviewer.py -f syslog -e ProcessCreate -u nelson

 EventId: 1
 Version: 5
 EventType: ProcessCreate
 Computer: PanicMode
 EventRecordID: 16096
 UtcTime: 2022-06-25 06:45:24.272
 ProcessGuid: {2bb2bf27-af04-62b6-7d16-af3f41560000}
 ProcessId: 12411
 Image: /usr/lib/systemd/systemd
 FileVersion: /usr/lib/systemd/systemd
 Description: -
 Product: -
 Company: -
 OriginalFileName: -
 CurrentDirectory: /
 User: nelson
 LogonGuid: {2bb2bf27-0000-0000-ea03-000000000000}
 LogonId: 1002
 TerminalSessionId: 15
 IntegrityLevel: no level
 Hashes: -
 ParentProcessGuid: {2bb2bf27-a42e-62b6-7d86-733018560000}
 ParentProcessId: 1
 ParentImage: /usr/lib/systemd/systemd
 CommandLine: /lib/systemd/systemd --user
 ParentCommandLine: /lib/systemd/systemd --system --deserialize 24
 ParentUser: root

 ... 
 ```

 - Shows all events whose privileges were elevated:

```
❯ python sysmonviewer.py -f syslog -ep

 EventId: 1
 Version: 5
 EventType: ProcessCreate
 Computer: PanicMode
 EventRecordID: 68
 UtcTime: 2022-06-25 06:40:12.653
 ProcessGuid: {2bb2bf27-adcc-62b6-dddb-5ea21e560000}
 ProcessId: 3926
 Image: /usr/bin/bash
 FileVersion: /usr/bin/bash
 Description: -
 Product: -
 Company: -
 OriginalFileName: -
 CurrentDirectory: /home/kali
 User: root
 LogonGuid: {2bb2bf27-0000-0000-0000-000001000000}
 LogonId: 0
 TerminalSessionId: 2
 IntegrityLevel: no level
 Hashes: -
 ParentProcessGuid: {2bb2bf27-adcb-62b6-2dba-0dcfe0550000}
 ParentProcessId: 3925
 ParentImage: /usr/bin/sudo
 CommandLine: /bin/bash
 ParentCommandLine: sudo
 ParentUser: kali

 ...
 ```

 - Show commands only in timeline format with EventType filter:

 ```
 ❯ python sysmonviewer.py -f syslog -e ProcessCreate -c

2022-06-25 06:39:31.358 (kali): /usr/bin/zsh
2022-06-25 06:39:31.405 (kali): grep -q ^ID.*=.*ubuntu /etc/os-release
2022-06-25 06:39:31.494 (kali): tput setaf 1
2022-06-25 06:39:31.535 (kali): dircolors -b
2022-06-25 06:39:44.393 (kali): su dillan
2022-06-25 06:39:46.422 (dillan): bash
2022-06-25 06:39:46.426 (dillan): tput setaf 1
2022-06-25 06:39:46.427 (dillan): dircolors -b
2022-06-25 06:40:08.828 (kali): /usr/bin/zsh
2022-06-25 06:40:08.842 (kali): grep -q ^ID.*=.*ubuntu /etc/os-release
2022-06-25 06:40:08.902 (kali): tput setaf 1
2022-06-25 06:40:08.947 (kali): dircolors -b
2022-06-25 06:40:11.217 (kali): sudo /bin/bash
2022-06-25 06:40:12.653 (root): /bin/bash
2022-06-25 06:40:12.656 (root): tput setaf 1
2022-06-25 06:40:12.659 (root): dircolors -b
...
```

