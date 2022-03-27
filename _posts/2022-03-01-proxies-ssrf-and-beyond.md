---
title:  "Proxies, SSRF and beyond! (TSJ CTF 2022 nimja writeup)"
layout: post
categories: ctf, web security
---


At the end of February this year, [TSJ CTF 2022](https://chal.ctf.tsj.tw/) was released with many interesting challenges including Web and Binary Exploits, RE, Crypto and Misc! Our team had fun solving this challenge as it was interesting and unique.


![alt text](https://miro.medium.com/max/700/0*9wzFESUQlnv3TwnS.jpg)
## Approaching the challenge

In this challenge we were given the source of **2 web servers**, one written in **nim language**, and the other in **node.js**. On top of that, we saw that there is a proxy server running, redirecting some requests:

```sh
# remap.config
map /hello-from-the-world/key http://127.0.0.1:80/forbidden
map /hello-from-the-world/    http://127.0.0.1:80
map /service-info/admin       http://127.0.0.1:5000/forbidden
map /service-info/            http://127.0.0.1:5000/
```

Looking at the source of the first nim web server on **port 80**, we saw some interesting snippets. Firstly, a potential **SSRF** function:

```nim
proc hello_from_the_world(host: string): string =
  var client = newHTTPClient(timeout=1000)
  var uri = host & "hello"
  var response = ""
  try:
    response = client.getContent(uri)
  except:
    response = "Cannot fetch hello from your designated host.\n"
  return response
```

We just have to get rid of that annoying “hello” string concat, but we will get back to that later on.

Looking at the router for the server, we see some more interesting endpoints:

```nim
router myrouter:
  get "/":
    var jsonheader = parseJson($request.headers.toJson)
    var ip = $request.ip

    # If x-forwarded-for exists
    if haskey(jsonheader["table"], "x-forwarded-for"):
      var ips = jsonheader["table"]["x-forwarded-for"]
      ip = ips[ips.len-1].str
    
    if ip == "127.0.0.1":
      resp getkey()
    else:
      resp "This is the index page.\nOnly local user can get the key.\n"
  get "/hello":
    resp "Hello from myself\n"
  get "/forbidden":
    resp "Only local user can access it.\n"
  get "/key":
    resp getkey()
  post "/get_hello":
    var jsonheader = parseJson($request.params.toJson)
    var host = ""
    if haskey(jsonheader, "host"):
      host = jsonheader["host"].str

    if host != "":
      var response = hello_from_the_world(host)
      resp response
    else:
      resp "Please provide the host so that they can say hello to you.\n"
```

**A key endpoint!** easy-peasy, or is it? GET-ing that key returns a **forbidden** page. oof, we forgot about that damn proxy.

> After writing, I also figured we could bypass the proxy with the same way we did on the second stage (//key), without using SSRF, but who cares D:

When we read further we can see a new **POST** endpoint called `get_hello`, which calls the dangerous function `hello_from_the_world` we can use that to bypass the **ip == "127.0.0.1"** check!

> Don’t forget to bypass the weird “hello” string added to your URL, use # to “comment” that out.


### First stage exploit:
![](https://miro.medium.com/max/700/1*ti-ICOBZ6QtVKamx-e1vjA.png)

`T$J_CTF_15_FUN_>_<_bY_Th3_wAy_IT_is_tHE_KEEEEEEEY_n0t_THE_flag`

Hmmm, that’s not the flag, damn. Then what can we do with that? Let’s read the other web server source.

```js
http.createServer((request, response) => {
    let body = [];
    request.on('error', (err) => {
        response.end("Error while parsing request: " + err)
    }).on('data', (chunk) => {
        if(request.method == "POST") body.push(chunk);
    }).on('end', async () => {
        response.on('error', (err) => {
            response.end("Error while sending response: " + err)
        });
        
        if (request.url == "/admin") {
            if (request.method == "POST") {
  ...
```

Okay, another **POST** endpoint, looks like its expecting some data:

```js
var jsonData = JSON.parse(body);
var service = jsonData.service;
var client_key = jsonData.key;
```

After that, **a key check** comes in (Phew, we didn’t work hard for nothing):

```js
if (client_key == KEY) {
    let return_data = await get_services(service);
    response.end(return_data);
}
```

This leads us to `get_services`:

```js
function get_services(service) {
    return new Promise((res, reject) => {
        si.services(service)
        .then(data => {
            console.log(data);
            if (data != null) res(data.toString());
            else res("Failed");
        }).catch(error => {
            console.error("Error: " + error);
            reject("There is an error when fetching services.");
        })
    });
}
```

This is weird, I can’t find a way that this is exploitable within the current code, we have to read more about that [systeminformation.services](https://www.npmjs.com/package/systeminformation) function.

Looking at source, we saw that the lib is using **systemctl** to view service information, which lead us to look for **command injection** vulns. Searching CVE’s for the current package version (5.2.6), We find a few vulnerabilities in [synk](https://snyk.io/vuln/npm:systeminformation):

![](https://miro.medium.com/max/700/1*bfT7Fdz-_mKetSz0yDxB_A.png)

In the current version of the lib, simply injecting commands as strings is **not enough** to pass sanitization.

> This will fail, because of string sanitization. As said in CVE details “sanitization works as expected, reject any arrays […]”

We find a very nice and detailed [writeup](https://github.com/ForbiddenProgrammer/CVE-2021-21315-PoC) by ForbiddenProgrammer on CVE-2021–21315.

### Before exploiting, you have to remember a few important points:
- Remember you have to bypass the proxy again (We can do that by adding another Forward Slash to our request): `map /service-info/admin       http://127.0.0.1:5000/forbidden`

- You need to pass the data as JSON, as its being parsed as JSON.

- This is a blind injection, you can’t see command output, so you need to send it back to your end using a server of your own.

## Final payload
![](https://miro.medium.com/max/700/1*NbU_bLyGs8aP0LdqKl4Lbw.png)