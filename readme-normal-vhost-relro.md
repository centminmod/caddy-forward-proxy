A guide on building Caddy with the `forwardproxy` plugin and hardened compiler options on [Centmin Mod LEMP stack server](https://centminmod.com) running AlmaLinux 9.

### Step 1: Install Dependencies
First, ensure you have the necessary tools for building software, as well as Go, which is required to build Caddy.

1. **Update your system**:
   ```bash
   sudo dnf update -y
   sudo dnf install clang llvm-devel lld -y
   ```
   ```bash
   clang --version
   clang version 17.0.6 (AlmaLinux OS Foundation 17.0.6-5.el9)
   Target: x86_64-redhat-linux-gnu
   Thread model: posix
   InstalledDir: /usr/bin
   ```

2. **Install Go**:
   Download and install the latest Go version (replace with the latest version link if necessary).

   ```
   export CC=clang
   export CXX=clang++

   /usr/local/src/centminmod/addons/golang.sh install
   grep -qxF 'export PATH=$PATH:/root/go/bin' ~/.bashrc || echo 'export PATH=$PATH:/root/go/bin' >> ~/.bashrc
   source /root/.bashrc
   ```

   Verify Go installation:
   ```bash
   go version
   ```
   ```
   go version
   go version go1.23.1 linux/amd64
   ```

### Step 2: Build Caddy with Forward Proxy Plugin

1. **Install xcaddy**:
   `xcaddy` is a command-line tool that makes it easy to build custom versions of Caddy with plugins. Install it with the following command:

   ```bash
   go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
   ```

2. **Build Caddy with `forwardproxy` Plugin**:
   Now, use `xcaddy` to build Caddy with the `forwardproxy` plugin:

   ```bash
   mkdir -p /home/caddybuild
   cd /home/caddybuild
   # Set compiler and linker flags for enhanced security
   export CGO_CFLAGS="-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2"
   export CGO_LDFLAGS="-Wl,-z,relro,-z,now -fuse-ld=lld"
   export GOFLAGS="-buildmode=pie"
   CGO_ENABLED=1 CC=clang CXX=clang++ xcaddy build --with github.com/caddyserver/forwardproxy@latest
   strip caddy
   ```

   This will download the Caddy source code and build it with the forward proxy plugin.

   For upgrades:

   ```bash
    caddy upgrade
    2024/09/07 13:56:49.811 INFO    this executable will be replaced        {"path": "/usr/local/bin/caddy"}
    2024/09/07 13:56:49.811 INFO    requesting build        {"os": "linux", "arch": "amd64", "packages": ["github.com/caddyserver/forwardproxy"]}
    2024/09/07 13:56:49.881 INFO    build acquired; backing up current executable   {"current_path": "/usr/local/bin/caddy", "backup_path": "/usr/local/bin/caddy.tmp"}
    2024/09/07 13:56:49.881 INFO    downloading binary      {"destination": "/usr/local/bin/caddy"}
    2024/09/07 13:56:50.335 INFO    download successful; displaying new binary details      {"location": "/usr/local/bin/caddy"}

    Module versions:

    http.handlers.forward_proxy v0.0.0-20240718200834-02be81e69669

      Non-standard modules: 1

      Unknown modules: 0

    Version:
    v2.8.4 h1:q3pe0wpBj1OcHFZ3n/1nl4V4bxBrYoSoab7rL9BMYNk=

    2024/09/07 13:56:50.396 INFO    upgrade successful; please restart any running Caddy instances  {"executable": "/usr/local/bin/caddy"}
   ```

3. **Setup Caddy**:
   Once the build is complete, move the Caddy binary to `/usr/local/bin`:

   ```bash
   sudo mv -f caddy /usr/local/bin/caddy
   sudo chmod +x /usr/local/bin/caddy
   ls -lah $(which caddy)
   ```

   You can verify Caddy with:

   ```bash
   caddy version
   ```
   ```
   caddy version
   v2.8.4 h1:q3pe0wpBj1OcHFZ3n/1nl4V4bxBrYoSoab7rL9BMYNk=
   ```

   Create `caddy` user:
   ```bash
   sudo useradd -r -d /home/caddy -s /sbin/nologin caddy
   ```

   Setup Caddy directories:
   ```bash
   sudo mkdir -p /home/caddy/.config/caddy
   sudo mkdir -p /home/caddy/.local/share/caddy/locks
   sudo chown -R caddy:caddy /home/caddy
   sudo chmod 755 /home/caddy
   ```

4. **Setup Logging & Logrotation**:
   Setup logging directory and logrotation:

   ```bash
   sudo mkdir -p /var/log/caddy
   sudo chown -R caddy:caddy /var/log/caddy
   sudo chmod 755 /var/log/caddy
   ```
   ```bash
   cat > /etc/logrotate.d/caddy <<EOF
   /var/log/caddy/*.log {
       daily
       missingok
       rotate 7
       compress
       delaycompress
       notifempty
       create 0640 caddy caddy
       sharedscripts
       postrotate
           systemctl reload caddy > /dev/null 2>/dev/null || true
       endscript
   }
   EOF
   ```

### Step 3: Configure Caddy with Forward Proxy

1. **Create Caddyfile**:
   Create a `Caddyfile` configuration file to set up the proxy. You can place this file in `/etc/caddy/Caddyfile`.

   ```bash
   sudo mkdir -p /etc/caddy
   sudo mkdir -p /etc/caddy/ssl/domain.com /home/caddy/domains/domain.com/public
   sudo nano /etc/caddy/Caddyfile
   ```
   ```bash
   sudo cp /usr/local/nginx/conf/ssl/domain.com/domain.com.crt /etc/caddy/ssl/domain.com/
   sudo cp /usr/local/nginx/conf/ssl/domain.com/domain.com.key /etc/caddy/ssl/domain.com/
 
   sudo chown caddy:caddy /etc/caddy/ssl/domain.com/domain.com.crt
   sudo chown caddy:caddy /etc/caddy/ssl/domain.com/domain.com.key
 
   sudo chmod 600 /etc/caddy/ssl/domain.com/domain.com.crt
   sudo chmod 600 /etc/caddy/ssl/domain.com/domain.com.key

   sudo cp -a /home/nginx/domains/domain.com/public/* /home/caddy/domains/domain.com/public
   sudo chown -R caddy:caddy /home/caddy/domains/domain.com/public
   ```

   Here is an example of a `Caddyfile` configured for forward proxying with non-HTTPS:

```caddy
{
        log {
                output file /var/log/caddy/caddy_errors.log
                level ERROR
        }
        auto_https off
}

:8081 {
        route {
                forward_proxy {
                        basic_auth yourusername yourpassword
                        hide_ip
                        hide_via
                        probe_resistance secret_token
                }
        }
        log {
                output file /var/log/caddy/forward_proxy_access_8081.log
                format json
                level INFO
        }
}

domain.com:8088 {
        root * /home/caddy/domains/domain.com/public
        encode gzip

        #php_fastcgi 127.0.0.1:9000 {
            #split .php
            #pool www
        #}
        file_server {
          #precompressed gzip
          hide .git
        }

        header Server "caddy centminmod"
        header X-Powered-By "caddy"
        header X-Xss-Protection "1; mode=block"
        header X-Content-Type-Options "nosniff"
        header ?Accept-Ranges bytes
        header Content-Type "text/html; charset=utf-8"
        header Connection "keep-alive"
        #header Vary "Accept-Encoding"

        log {
                output file /var/log/caddy/domain.com_access.log
                format json
                level INFO
        }
}

domain.com:8443 {
        root * /home/caddy/domains/domain.com/public
        encode gzip

        #php_fastcgi 127.0.0.1:9000 {
            #split .php
            #pool www
        #}
        file_server {
          #precompressed gzip
          hide .git
        }

        # TLS configuration using Nginx certificates
        tls /etc/caddy/ssl/domain.com/domain.com.crt /etc/caddy/ssl/domain.com/domain.com.key  {
          ciphers TLS_AES_128_GCM_SHA256 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_256_GCM_SHA384 TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
          curves x25519 secp256r1
        }

        header Server "caddy centminmod"
        header X-Powered-By "caddy"
        header X-Xss-Protection "1; mode=block"
        header X-Content-Type-Options "nosniff"
        header ?Accept-Ranges bytes
        header Content-Type "text/html; charset=utf-8"
        header Connection "keep-alive"
        #header Vary "Accept-Encoding"

        log {
                output file /var/log/caddy/domain.com_tls_access.log
                format json
                level INFO
        }
}
```

   This configuration makes Caddy listen on port 81 and act as a forward proxy and dummy non-HTTPS and HTTPS vhost.

```bash
curl -Ik https://domain.com:8443
HTTP/2 200 
accept-ranges: bytes
alt-svc: h3=":8443"; ma=2592000
content-type: text/html; charset=utf-8
etag: "d3ywcl78i2wg4wk"
last-modified: Fri, 06 Sep 2024 03:55:25 GMT
server: caddy centminmod
vary: Accept-Encoding
x-content-type-options: nosniff
x-powered-by: caddy
x-xss-protection: 1; mode=block
content-length: 6356
date: Sat, 07 Sep 2024 19:32:46 GMT

curl -Ik http://domain.com:8088
HTTP/1.1 200 OK
Connection: keep-alive
Content-Type: text/html; charset=utf-8
Server: caddy centminmod
X-Content-Type-Options: nosniff
X-Powered-By: caddy
X-Xss-Protection: 1; mode=block
Date: Sat, 07 Sep 2024 17:13:21 GMT
```
```bash
curl -Ik https://domain.com:443
HTTP/2 200 
date: Sat, 07 Sep 2024 17:14:13 GMT
content-type: text/html; charset=utf-8
content-length: 6356
last-modified: Fri, 06 Sep 2024 03:55:25 GMT
vary: Accept-Encoding
etag: "66da7d2d-18d4"
server: nginx centminmod
x-powered-by: centminmod
x-xss-protection: 1; mode=block
x-content-type-options: nosniff
accept-ranges: bytes

curl -Ik http://domain.com:80
HTTP/1.1 200 OK
Date: Sat, 07 Sep 2024 17:14:18 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 6356
Last-Modified: Fri, 06 Sep 2024 03:55:25 GMT
Connection: keep-alive
Vary: Accept-Encoding
ETag: "66da7d2d-18d4"
Server: nginx centminmod
X-Powered-By: centminmod
X-Xss-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Accept-Ranges: bytes
```

```
nginx -V
nginx version: nginx/1.27.1 (060924-044706-almalinux9-kvm-95a2688)
built by gcc 13.3.1 20240611 (Red Hat 13.3.1-2) (GCC) 
built with OpenSSL 1.1.1 (compatible; AWS-LC 1.34.2) (running with AWS-LC 1.34.2)
TLS SNI support enabled
```
> configure arguments: --with-ld-opt='-Wl,-E -L/usr/local/zlib-cf/lib -L/opt/aws-lc-install/lib64 -lcrypto -lssl -L/usr/local/nginx-dep/lib -lrt -ljemalloc -Wl,-z,relro,-z,now -Wl,-rpath,/usr/local/zlib-cf/lib:/opt/aws-lc-install/lib64:/usr/local/nginx-dep/lib -pie -flto=2 -flto-compression-level=1 -fuse-ld=gold' --with-cc-opt='-I/opt/aws-lc-install/include -I/usr/local/zlib-cf/include -I/usr/local/nginx-dep/include -m64 -march=native -fPIC -g -O3 -fstack-protector-strong -flto=2 -flto-compression-level=1 -fuse-ld=gold --param=ssp-buffer-size=4 -Wformat -Wno-pointer-sign -Wimplicit-fallthrough=0 -Wno-implicit-function-declaration -Wno-cast-align -Wno-builtin-declaration-mismatch -Wno-deprecated-declarations -Wno-int-conversion -Wno-unused-result -Wno-vla-parameter -Wno-maybe-uninitialized -Wno-return-local-addr -Wno-array-parameter -Wno-alloc-size-larger-than -Wno-address -Wno-array-bounds -Wno-discarded-qualifiers -Wno-stringop-overread -Wno-stringop-truncation -Wno-missing-field-initializers -Wno-unused-variable -Wno-format -Wno-error=unused-result -Wno-missing-profile -Wno-stringop-overflow -Wno-free-nonheap-object -Wno-discarded-qualifiers -Wno-bad-function-cast -Wno-dangling-pointer -Wno-array-parameter -fcode-hoisting -Wno-cast-function-type -Wno-format-extra-args -Wp,-D_FORTIFY_SOURCE=2' --prefix=/usr/local/nginx --sbin-path=/usr/local/sbin/nginx --conf-path=/usr/local/nginx/conf/nginx.conf --build=060924-044706-almalinux9-kvm-95a2688 --with-compat --without-pcre2 --with-http_stub_status_module --with-http_secure_link_module --with-libatomic --with-http_gzip_static_module --with-http_sub_module --with-http_addition_module --with-http_image_filter_module=dynamic --with-http_geoip_module --with-stream_geoip_module --with-stream_realip_module --with-stream_ssl_preread_module --with-threads --with-stream --with-stream_ssl_module --with-http_realip_module --add-dynamic-module=../ngx-fancyindex-0.5.2 --add-module=../ngx_cache_purge-2.5.3 --add-dynamic-module=../ngx_devel_kit-0.3.2 --add-dynamic-module=../set-misc-nginx-module-0.33 --add-dynamic-module=../echo-nginx-module-0.63 --add-module=../redis2-nginx-module-0.15 --add-module=../ngx_http_redis-0.4.0-cmm --add-module=../memc-nginx-module-0.20 --add-module=../srcache-nginx-module-0.33 --add-dynamic-module=../headers-more-nginx-module-0.37 --with-pcre-jit --with-zlib=../zlib-cloudflare-1.3.3 --with-zlib-opt=-fPIC --with-http_ssl_module --with-http_v2_module --with-http_v3_module

```
caddy version
v2.8.4 h1:q3pe0wpBj1OcHFZ3n/1nl4V4bxBrYoSoab7rL9BMYNk=
```

## h2load benchmarks

### Nginx vs Caddy HTTPS Performance Comparison

| Metric                   | Nginx (c200, n5000, m100) | Caddy (c200, n5000, m100) | Nginx (c300, n5000, m100) | Caddy (c300, n5000, m100) | Nginx (c500, n10000, m100) | Caddy (c500, n10000, m100) | Nginx (c600, n50000, m100) | Caddy (c600, n50000, m100) |
|--------------------------|---------------------------|---------------------------|---------------------------|---------------------------|----------------------------|----------------------------|----------------------------|----------------------------|
| Total Time               | 136.36ms                  | 135.66ms                  | 152.96ms                  | 160.81ms                  | 271.58ms                   | 304.81ms                   | 1.11s                      | 1.04s                      |
| Requests per second      | 36,668.18                 | 36,857.66                 | 32,689.35                 | 31,091.82                 | 36,821.97                  | 32,807.21                  | 44,867.03                  | 47,899.33                  |
| Data transfer rate       | 79.27MB/s                 | 74.87MB/s                 | 70.70MB/s                 | 63.32MB/s                 | 79.62MB/s                  | 66.72MB/s                  | 96.94MB/s                  | 96.95MB/s                  |
| Total traffic            | 10.81MB                   | 10.16MB                   | 10.81MB                   | 10.18MB                   | 21.62MB                    | 20.34MB                    | 108.03MB                   | 101.20MB                   |
| Header size              | 1010.74KB                 | 114.38KB                  | 1010.74KB                 | 136.45KB                  | 1.97MB                     | 248.54KB                   | 9.87MB                     | 857.04KB                   |
| Header space savings     | 26.86%                    | 93.62%                    | 26.86%                    | 92.39%                    | 26.86%                     | 93.07%                     | 26.86%                     | 95.22%                     |
| Data size                | 9.73MB                    | 9.95MB                    | 9.73MB                    | 9.95MB                    | 19.45MB                    | 19.89MB                    | 97.27MB                    | 99.47MB                    |
| Min request time         | 11.28ms                   | 1.34ms                    | 1.49ms                    | 514µs                     | 8.44ms                     | 247µs                      | 29.57ms                    | 486µs                      |
| Max request time         | 96.89ms                   | 105.81ms                  | 92.72ms                   | 131.07ms                  | 122.85ms                   | 241.83ms                   | 787.24ms                   | 974.05ms                   |
| Mean request time        | 43.93ms                   | 40.40ms                   | 39.64ms                   | 63.51ms                   | 55.67ms                    | 78.92ms                    | 329.38ms                   | 327.67ms                   |
| Request time std dev     | 22.94ms                   | 21.30ms                   | 19.19ms                   | 27.13ms                   | 24.41ms                    | 58.16ms                    | 189.16ms                   | 280.40ms                   |
| Min connect time         | 5.48ms                    | 8.68ms                    | 7.50ms                    | 10.42ms                   | 11.22ms                    | 17.65ms                    | 22.73ms                    | 26.56ms                    |
| Max connect time         | 38.78ms                   | 71.80ms                   | 110.90ms                  | 114.19ms                  | 161.34ms                   | 270.80ms                   | 381.14ms                   | 1.02s                      |
| Mean connect time        | 20.52ms                   | 37.17ms                   | 41.50ms                   | 41.96ms                   | 71.70ms                    | 90.03ms                    | 196.48ms                   | 271.04ms                   |
| Connect time std dev     | 8.88ms                    | 14.06ms                   | 20.74ms                   | 13.20ms                   | 42.37ms                    | 47.32ms                    | 137.78ms                   | 251.16ms                   |
| Min time to 1st byte     | 25.20ms                   | 47.90ms                   | 38.11ms                   | 40.55ms                   | 46.95ms                    | 70.36ms                    | 52.83ms                    | 103.26ms                   |
| Max time to 1st byte     | 131.55ms                  | 134.20ms                  | 144.60ms                  | 159.51ms                  | 254.00ms                   | 299.01ms                   | 1.09s                      | 1.03s                      |
| Mean time to 1st byte    | 62.99ms                   | 73.23ms                   | 80.25ms                   | 94.68ms                   | 126.03ms                   | 153.86ms                   | 520.12ms                   | 537.79ms                   |
| Time to 1st byte std dev | 30.20ms                   | 24.47ms                   | 29.36ms                   | 29.95ms                   | 56.04ms                    | 62.06ms                    | 294.40ms                   | 266.34ms                   |
| Min requests/sec         | 184.58                    | 184.84                    | 114.24                    | 101.51                    | 77.79                      | 66.35                      | 75.20                      | 79.98                      |
| Max requests/sec         | 982.30                    | 519.99                    | 418.33                    | 393.76                    | 424.24                     | 283.74                     | 1569.15                    | 810.41                     |
| Mean requests/sec        | 480.92                    | 326.53                    | 230.91                    | 145.70                    | 196.66                     | 122.00                     | 283.74                     | 126.96                     |
| Requests/sec std dev     | 236.54                    | 109.99                    | 78.24                     | 52.68                     | 102.71                     | 59.88                      | 313.41                     | 85.16                      |
| TLS Protocol             | TLSv1.3                   | TLSv1.3                   | TLSv1.3                   | TLSv1.3                   | TLSv1.3                    | TLSv1.3                    | TLSv1.3                    | TLSv1.3                    |
| Cipher                   | TLS_AES_256_GCM_SHA384    | TLS_AES_128_GCM_SHA256    | TLS_AES_256_GCM_SHA384    | TLS_AES_128_GCM_SHA256    | TLS_AES_256_GCM_SHA384     | TLS_AES_128_GCM_SHA256     | TLS_AES_256_GCM_SHA384     | TLS_AES_128_GCM_SHA256     |
| Server Temp Key          | X25519 253 bits           | X25519 253 bits           | X25519 253 bits           | X25519 253 bits           | X25519 253 bits            | X25519 253 bits            | X25519 253 bits            | X25519 253 bits            |
| Application protocol     | h2                        | h2                        | h2                        | h2                        | h2                         | h2                         | h2                         | h2                         |

# Nginx vs Caddy Binary Security and Performance Comparison

### Security Features Comparison

| Feature          | Nginx            | Caddy            | Performance Impact                                |
|------------------|------------------|------------------|---------------------------------------------------|
| RELRO            | Full             | Partial          | Minimal impact, slight load time increase for full|
| Canary           | Yes              | No               | Slight performance overhead for canary            |
| NX               | Yes              | Yes              | Negligible impact                                 |
| PIE              | Yes              | Yes              | Small performance overhead for PIE                |
| Clang CFI        | No               | No               | N/A                                               |
| SafeStack        | No               | No               | N/A                                               |
| RPATH            | No               | No               | N/A                                               |
| RUNPATH          | Yes              | No               | Negligible impact                                 |
| Symbols          | No               | No               | N/A (stripped binaries are smaller)               |
| Fortify Source   | Yes              | Yes              | Minimal performance impact                        |
| Fortified        | 4                | 2                | Minimal performance impact                        |
| Fortify-able     | 11               | 2                | N/A                                               |

## Analysis and Implications

1. **RELRO (RELocation Read-Only)**: 
   - Nginx has full RELRO, while Caddy now has partial RELRO.
   - Full RELRO provides better security against certain types of attacks, but partial RELRO is still an improvement.
   - Performance impact: Minimal difference between full and partial RELRO.

2. **Stack Canary**:
   - Nginx uses stack canaries, Caddy still does not.
   - Canaries add a small overhead but provide protection against stack buffer overflows.
   - Performance impact: Nginx might have a slight performance penalty due to canary checks.
   - Note: Go (used by Caddy) has built-in memory safety features that may provide similar protections through different mechanisms.

3. **NX (No-Execute)**:
   - Both binaries have NX enabled, which is good for security.
   - Performance impact: Negligible.

4. **PIE (Position Independent Executable)**:
   - Both Nginx and Caddy are now compiled as PIE.
   - PIE can have a small performance overhead but enhances security through ASLR.
   - Performance impact: Similar for both, with a small overhead for enhanced security.

5. **Fortify Source**:
   - Both Nginx and Caddy now have Fortify Source enabled.
   - Fortify Source adds runtime checks to prevent buffer overflows.
   - Performance impact: Minimal and similar for both servers.

6. **Compilation Method**:
   - Caddy was compiled with Clang, which can sometimes produce more optimized code compared to GCC.
   - The use of `CGO_ENABLED=1` for Caddy allows it to use C libraries, which can impact performance both positively (through optimized C code) and negatively (through CGo overhead).

7. **Fortified Functions**:
   - Nginx has 4 fortified functions, while Caddy has 2.
   - This difference is likely due to the different languages and code structures used.
   - Performance impact: Minimal, with potentially slightly less overhead for Caddy.

8. **RUNPATH**:
   - Nginx uses RUNPATH, while Caddy does not.
   - The absence of RUNPATH in Caddy can be seen as a security advantage, reducing the risk of library hijacking.
   - Performance impact: Negligible.

Nginx HTTPS port 443

```
checksec --format=json --file=/usr/local/sbin/nginx --extended | jq -r
{
  "/usr/local/sbin/nginx": {
    "relro": "full",
    "canary": "yes",
    "nx": "yes",
    "pie": "yes",
    "clangcfi": "no",
    "safestack": "no",
    "rpath": "no",
    "runpath": "yes",
    "symbols": "no",
    "fortify_source": "yes",
    "fortified": "4",
    "fortify-able": "11"
  }
}
```
```
echo -n | openssl s_client -connect domain.com:443 -servername domain.com
CONNECTED(00000003)
depth=0 C = US, ST = California, L = Los Angeles, O = domain.com, OU = domain.com, CN = domain.com
verify error:num=18:self-signed certificate
verify return:1
depth=0 C = US, ST = California, L = Los Angeles, O = domain.com, OU = domain.com, CN = domain.com
verify return:1
---
Certificate chain
 0 s:C = US, ST = California, L = Los Angeles, O = domain.com, OU = domain.com, CN = domain.com
   i:C = US, ST = California, L = Los Angeles, O = domain.com, OU = domain.com, CN = domain.com
   a:PKEY: id-ecPublicKey, 256 (bit); sigalg: ecdsa-with-SHA256
   v:NotBefore: Sep  6 03:55:35 2024 GMT; NotAfter: Aug 13 03:55:35 2124 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIC9zCCApygAwIBAgIUKHrcCcXPxJXBZnkBoFIPiSWzuHAwCgYIKoZIzj0EAwIw
dzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFDASBgNVBAcMC0xv
cyBBbmdlbGVzMRMwEQYDVQQKDApkb21haW4uY29tMRMwEQYDVQQLDApkb21haW4u
Y29tMRMwEQYDVQQDDApkb21haW4uY29tMCAXDTI0MDkwNjAzNTUzNVoYDzIxMjQw
ODEzMDM1NTM1WjB3MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEU
MBIGA1UEBwwLTG9zIEFuZ2VsZXMxEzARBgNVBAoMCmRvbWFpbi5jb20xEzARBgNV
BAsMCmRvbWFpbi5jb20xEzARBgNVBAMMCmRvbWFpbi5jb20wWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAARRyp52igUh+rJmG3UbuVg0PZmUPodPsWbex+HrotEyUJh7
2tBiPjqokOADcR2jInj+kP6Ur8W3gpo8o+3Hx2G5o4IBAjCB/zCBngYDVR0jBIGW
MIGToXukeTB3MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEUMBIG
A1UEBwwLTG9zIEFuZ2VsZXMxEzARBgNVBAoMCmRvbWFpbi5jb20xEzARBgNVBAsM
CmRvbWFpbi5jb20xEzARBgNVBAMMCmRvbWFpbi5jb22CFCh63AnFz8SVwWZ5AaBS
D4kls7hwMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgTwMCUGA1UdEQQeMByCCmRvbWFp
bi5jb22CDnd3dy5kb21haW4uY29tMB0GA1UdDgQWBBR6al324gfYcQH7IUnzfvCw
95hLfjAKBggqhkjOPQQDAgNJADBGAiEA3mmvE/rkJLqK32ZjjHLFOZ+uIPFiXNp2
+l2TA+5BEQoCIQC4ThTKewmZiuTEu33Aq4pfqTSDQ8mCwmWSXgaIfjRbYA==
-----END CERTIFICATE-----
subject=C = US, ST = California, L = Los Angeles, O = domain.com, OU = domain.com, CN = domain.com
issuer=C = US, ST = California, L = Los Angeles, O = domain.com, OU = domain.com, CN = domain.com
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: ECDSA
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1073 bytes and written 394 bytes
Verification error: self-signed certificate
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Server public key is 256 bit
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 18 (self-signed certificate)
---
DONE
```

```
h2load -t4 -c200 -n5000 -m100 -H "Accept-Encoding: gzip" https://domain.com:443
starting benchmark...
spawning thread #0: 50 total client(s). 1250 total requests
spawning thread #1: 50 total client(s). 1250 total requests
spawning thread #2: 50 total client(s). 1250 total requests
spawning thread #3: 50 total client(s). 1250 total requests
TLS Protocol: TLSv1.3
Cipher: TLS_AES_256_GCM_SHA384
Server Temp Key: X25519 253 bits
Application protocol: h2
progress: 10% done
progress: 20% done
progress: 30% done
progress: 40% done
progress: 50% done
progress: 60% done
progress: 70% done
progress: 80% done
progress: 90% done
progress: 100% done

finished in 136.36ms, 36668.18 req/s, 79.27MB/s
requests: 5000 total, 5000 started, 5000 done, 5000 succeeded, 0 failed, 0 errored, 0 timeout
status codes: 5000 2xx, 0 3xx, 0 4xx, 0 5xx
traffic: 10.81MB (11334800) total, 1010.74KB (1035000) headers (space savings 26.86%), 9.73MB (10200000) data
                     min         max         mean         sd        +/- sd
time for request:    11.28ms     96.89ms     43.93ms     22.94ms    54.76%
time for connect:     5.48ms     38.78ms     20.52ms      8.88ms    62.50%
time to 1st byte:    25.20ms    131.55ms     62.99ms     30.20ms    58.00%
req/s           :     184.58      982.30      480.92      236.54    62.50%
```
```
h2load -t4 -c300 -n5000 -m100 -H "Accept-Encoding: gzip" https://domain.com:443
starting benchmark...
spawning thread #0: 75 total client(s). 1250 total requests
spawning thread #1: 75 total client(s). 1250 total requests
spawning thread #2: 75 total client(s). 1250 total requests
spawning thread #3: 75 total client(s). 1250 total requests
TLS Protocol: TLSv1.3
Cipher: TLS_AES_256_GCM_SHA384
Server Temp Key: X25519 253 bits
Application protocol: h2
progress: 10% done
progress: 20% done
progress: 30% done
progress: 40% done
progress: 50% done
progress: 60% done
progress: 70% done
progress: 80% done
progress: 90% done
progress: 100% done

finished in 152.96ms, 32689.35 req/s, 70.70MB/s
requests: 5000 total, 5000 started, 5000 done, 5000 succeeded, 0 failed, 0 errored, 0 timeout
status codes: 5000 2xx, 0 3xx, 0 4xx, 0 5xx
traffic: 10.81MB (11339700) total, 1010.74KB (1035000) headers (space savings 26.86%), 9.73MB (10200000) data
                     min         max         mean         sd        +/- sd
time for request:     1.49ms     92.72ms     39.64ms     19.19ms    70.26%
time for connect:     7.50ms    110.90ms     41.50ms     20.74ms    80.67%
time to 1st byte:    38.11ms    144.60ms     80.25ms     29.36ms    62.33%
req/s           :     114.24      418.33      230.91       78.24    50.67%
```
```
h2load -t4 -c500 -n10000 -m100 -H "Accept-Encoding: gzip" https://domain.com:443
starting benchmark...
spawning thread #0: 125 total client(s). 2500 total requests
spawning thread #1: 125 total client(s). 2500 total requests
spawning thread #2: 125 total client(s). 2500 total requests
spawning thread #3: 125 total client(s). 2500 total requests
TLS Protocol: TLSv1.3
Cipher: TLS_AES_256_GCM_SHA384
Server Temp Key: X25519 253 bits
Application protocol: h2
progress: 10% done
progress: 20% done
progress: 30% done
progress: 40% done
progress: 50% done
progress: 60% done
progress: 70% done
progress: 80% done
progress: 90% done
progress: 100% done

finished in 271.58ms, 36821.97 req/s, 79.62MB/s
requests: 10000 total, 10000 started, 10000 done, 10000 succeeded, 0 failed, 0 errored, 0 timeout
status codes: 10000 2xx, 0 3xx, 0 4xx, 0 5xx
traffic: 21.62MB (22674500) total, 1.97MB (2070000) headers (space savings 26.86%), 19.45MB (20400000) data
                     min         max         mean         sd        +/- sd
time for request:     8.44ms    122.85ms     55.67ms     24.41ms    59.69%
time for connect:    11.22ms    161.34ms     71.70ms     42.37ms    62.40%
time to 1st byte:    46.95ms    254.00ms    126.03ms     56.04ms    56.60%
req/s           :      77.79      424.24      196.66      102.71    73.20%
```
```
h2load -t4 -c600 -n50000 -m100 -H "Accept-Encoding: gzip" https://domain.com:443
starting benchmark...
spawning thread #0: 150 total client(s). 12500 total requests
spawning thread #1: 150 total client(s). 12500 total requests
spawning thread #2: 150 total client(s). 12500 total requests
spawning thread #3: 150 total client(s). 12500 total requests
TLS Protocol: TLSv1.3
Cipher: TLS_AES_256_GCM_SHA384
Server Temp Key: X25519 253 bits
Application protocol: h2
progress: 10% done
progress: 20% done
progress: 30% done
progress: 40% done
progress: 50% done
progress: 60% done
progress: 70% done
progress: 80% done
progress: 90% done
progress: 100% done

finished in 1.11s, 44867.03 req/s, 96.94MB/s
requests: 50000 total, 50000 started, 50000 done, 50000 succeeded, 0 failed, 0 errored, 0 timeout
status codes: 50000 2xx, 0 3xx, 0 4xx, 0 5xx
traffic: 108.03MB (113279400) total, 9.87MB (10350000) headers (space savings 26.86%), 97.27MB (102000000) data
                     min         max         mean         sd        +/- sd
time for request:    29.57ms    787.24ms    329.38ms    189.16ms    63.44%
time for connect:    22.73ms    381.14ms    196.48ms    137.78ms    50.83%
time to 1st byte:    52.83ms       1.09s    520.12ms    294.40ms    57.83%
req/s           :      75.20     1569.15      283.74      313.41    88.50%
```

Caddy HTTPS port 8443:

```
checksec --format=json --file=/usr/local/bin/caddy --extended | jq -r
{
  "/usr/local/bin/caddy": {
    "relro": "partial",
    "canary": "no",
    "nx": "yes",
    "pie": "yes",
    "clangcfi": "no",
    "safestack": "no",
    "rpath": "no",
    "runpath": "no",
    "symbols": "no",
    "fortify_source": "yes",
    "fortified": "2",
    "fortify-able": "2"
  }
}
```
```
echo -n | openssl s_client -connect domain.com:8443 -servername domain.com
CONNECTED(00000003)
depth=0 C = US, ST = California, L = Los Angeles, O = domain.com, OU = domain.com, CN = domain.com
verify error:num=18:self-signed certificate
verify return:1
depth=0 C = US, ST = California, L = Los Angeles, O = domain.com, OU = domain.com, CN = domain.com
verify return:1
---
Certificate chain
 0 s:C = US, ST = California, L = Los Angeles, O = domain.com, OU = domain.com, CN = domain.com
   i:C = US, ST = California, L = Los Angeles, O = domain.com, OU = domain.com, CN = domain.com
   a:PKEY: id-ecPublicKey, 256 (bit); sigalg: ecdsa-with-SHA256
   v:NotBefore: Sep  6 03:55:35 2024 GMT; NotAfter: Aug 13 03:55:35 2124 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIC9zCCApygAwIBAgIUKHrcCcXPxJXBZnkBoFIPiSWzuHAwCgYIKoZIzj0EAwIw
dzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFDASBgNVBAcMC0xv
cyBBbmdlbGVzMRMwEQYDVQQKDApkb21haW4uY29tMRMwEQYDVQQLDApkb21haW4u
Y29tMRMwEQYDVQQDDApkb21haW4uY29tMCAXDTI0MDkwNjAzNTUzNVoYDzIxMjQw
ODEzMDM1NTM1WjB3MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEU
MBIGA1UEBwwLTG9zIEFuZ2VsZXMxEzARBgNVBAoMCmRvbWFpbi5jb20xEzARBgNV
BAsMCmRvbWFpbi5jb20xEzARBgNVBAMMCmRvbWFpbi5jb20wWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAARRyp52igUh+rJmG3UbuVg0PZmUPodPsWbex+HrotEyUJh7
2tBiPjqokOADcR2jInj+kP6Ur8W3gpo8o+3Hx2G5o4IBAjCB/zCBngYDVR0jBIGW
MIGToXukeTB3MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEUMBIG
A1UEBwwLTG9zIEFuZ2VsZXMxEzARBgNVBAoMCmRvbWFpbi5jb20xEzARBgNVBAsM
CmRvbWFpbi5jb20xEzARBgNVBAMMCmRvbWFpbi5jb22CFCh63AnFz8SVwWZ5AaBS
D4kls7hwMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgTwMCUGA1UdEQQeMByCCmRvbWFp
bi5jb22CDnd3dy5kb21haW4uY29tMB0GA1UdDgQWBBR6al324gfYcQH7IUnzfvCw
95hLfjAKBggqhkjOPQQDAgNJADBGAiEA3mmvE/rkJLqK32ZjjHLFOZ+uIPFiXNp2
+l2TA+5BEQoCIQC4ThTKewmZiuTEu33Aq4pfqTSDQ8mCwmWSXgaIfjRbYA==
-----END CERTIFICATE-----
subject=C = US, ST = California, L = Los Angeles, O = domain.com, OU = domain.com, CN = domain.com
issuer=C = US, ST = California, L = Los Angeles, O = domain.com, OU = domain.com, CN = domain.com
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: ECDSA
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1117 bytes and written 378 bytes
Verification error: self-signed certificate
---
New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256
Server public key is 256 bit
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 18 (self-signed certificate)
---
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_128_GCM_SHA256
    Session-ID: F1CD1E0388D225EE43208995D7F06D44550CB787CDE4B4A2ED1463FF81CFEEDA
    Session-ID-ctx: 
    Resumption PSK: 178083B894C8A7A2555E5F32729ED449523CEE54CC9EB0331A50576A0A872024
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 604800 (seconds)
    TLS session ticket:
    0000 - b8 76 cc 4c 6f f6 99 60-2a 15 c4 09 fd 25 ff 95   .v.Lo..`*....%..
    0010 - 0a 36 d1 99 01 01 9b 98-e1 5a 7d 88 2f c1 9b b8   .6.......Z}./...
    0020 - 56 24 46 4e 59 48 55 7e-26 de 7f f3 99 15 bf ed   V$FNYHU~&.......
    0030 - d0 a2 63 cf 54 ee 8f fd-df 0a f1 07 cf 1a 65 41   ..c.T.........eA
    0040 - 85 42 f7 9c 31 4d 24 b5-15 4c 85 e9 ec 8a 76 fa   .B..1M$..L....v.
    0050 - f4 51 6b e8 cc f3 43 86-68 1b 3b bf 6d 56 3c c3   .Qk...C.h.;.mV<.
    0060 - 77 d8 5a 5a bb 75 e9 81-c4                        w.ZZ.u...

    Start Time: 1725735451
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
DONE
```

```
h2load -t4 -c200 -n5000 -m100 -H "Accept-Encoding: gzip" https://domain.com:8443
starting benchmark...
spawning thread #0: 50 total client(s). 1250 total requests
spawning thread #1: 50 total client(s). 1250 total requests
spawning thread #2: 50 total client(s). 1250 total requests
spawning thread #3: 50 total client(s). 1250 total requests
TLS Protocol: TLSv1.3
Cipher: TLS_AES_128_GCM_SHA256
Server Temp Key: X25519 253 bits
Application protocol: h2
progress: 10% done
progress: 20% done
progress: 30% done
progress: 40% done
progress: 50% done
progress: 60% done
progress: 70% done
progress: 80% done
progress: 90% done
progress: 100% done

finished in 135.66ms, 36857.66 req/s, 74.87MB/s
requests: 5000 total, 5000 started, 5000 done, 5000 succeeded, 0 failed, 0 errored, 0 timeout
status codes: 5000 2xx, 0 3xx, 0 4xx, 0 5xx
traffic: 10.16MB (10649322) total, 114.38KB (117122) headers (space savings 93.62%), 9.95MB (10430000) data
                     min         max         mean         sd        +/- sd
time for request:     1.34ms    105.81ms     40.40ms     21.30ms    60.92%
time for connect:     8.68ms     71.80ms     37.17ms     14.06ms    63.50%
time to 1st byte:    47.90ms    134.20ms     73.23ms     24.47ms    77.50%
req/s           :     184.84      519.99      326.53      109.99    61.50%
```
```
h2load -t4 -c300 -n5000 -m100 -H "Accept-Encoding: gzip" https://domain.com:8443
starting benchmark...
spawning thread #0: 75 total client(s). 1250 total requests
spawning thread #1: 75 total client(s). 1250 total requests
spawning thread #2: 75 total client(s). 1250 total requests
spawning thread #3: 75 total client(s). 1250 total requests
TLS Protocol: TLSv1.3
Cipher: TLS_AES_128_GCM_SHA256
Server Temp Key: X25519 253 bits
Application protocol: h2
progress: 10% done
progress: 20% done
progress: 30% done
progress: 40% done
progress: 50% done
progress: 60% done
progress: 70% done
progress: 80% done
progress: 90% done
progress: 100% done

finished in 160.81ms, 31091.82 req/s, 63.32MB/s
requests: 5000 total, 5000 started, 5000 done, 5000 succeeded, 0 failed, 0 errored, 0 timeout
status codes: 5000 2xx, 0 3xx, 0 4xx, 0 5xx
traffic: 10.18MB (10678024) total, 136.45KB (139724) headers (space savings 92.39%), 9.95MB (10430000) data
                     min         max         mean         sd        +/- sd
time for request:      514us    131.07ms     63.51ms     27.13ms    59.16%
time for connect:    10.42ms    114.19ms     41.96ms     13.20ms    74.00%
time to 1st byte:    40.55ms    159.51ms     94.68ms     29.95ms    60.67%
req/s           :     101.51      393.76      145.70       52.68    89.33%
```
```
h2load -t4 -c500 -n10000 -m100 -H "Accept-Encoding: gzip" https://domain.com:8443
starting benchmark...
spawning thread #0: 125 total client(s). 2500 total requests
spawning thread #1: 125 total client(s). 2500 total requests
spawning thread #2: 125 total client(s). 2500 total requests
spawning thread #3: 125 total client(s). 2500 total requests
TLS Protocol: TLSv1.3
Cipher: TLS_AES_128_GCM_SHA256
Server Temp Key: X25519 253 bits
Application protocol: h2
progress: 10% done
progress: 20% done
progress: 30% done
progress: 40% done
progress: 50% done
progress: 60% done
progress: 70% done
progress: 80% done
progress: 90% done
progress: 100% done

finished in 304.81ms, 32807.21 req/s, 66.72MB/s
requests: 10000 total, 10000 started, 10000 done, 10000 succeeded, 0 failed, 0 errored, 0 timeout
status codes: 10000 2xx, 0 3xx, 0 4xx, 0 5xx
traffic: 20.34MB (21325000) total, 248.54KB (254500) headers (space savings 93.07%), 19.89MB (20860000) data
                     min         max         mean         sd        +/- sd
time for request:      247us    241.83ms     78.92ms     58.16ms    67.55%
time for connect:    17.65ms    270.80ms     90.03ms     47.32ms    79.20%
time to 1st byte:    70.36ms    299.01ms    153.86ms     62.06ms    63.60%
req/s           :      66.35      283.74      122.00       59.88    80.80%
```
```
h2load -t4 -c600 -n50000 -m100 -H "Accept-Encoding: gzip" https://domain.com:8443
starting benchmark...
spawning thread #0: 150 total client(s). 12500 total requests
spawning thread #1: 150 total client(s). 12500 total requests
spawning thread #2: 150 total client(s). 12500 total requests
spawning thread #3: 150 total client(s). 12500 total requests
TLS Protocol: TLSv1.3
Cipher: TLS_AES_128_GCM_SHA256
Server Temp Key: X25519 253 bits
Application protocol: h2
progress: 10% done
progress: 20% done
progress: 30% done
progress: 40% done
progress: 50% done
progress: 60% done
progress: 70% done
progress: 80% done
progress: 90% done
progress: 100% done

finished in 1.04s, 47899.33 req/s, 96.95MB/s
requests: 50000 total, 50000 started, 50000 done, 50000 succeeded, 0 failed, 0 errored, 0 timeout
status codes: 50000 2xx, 0 3xx, 0 4xx, 0 5xx
traffic: 101.20MB (106114208) total, 857.04KB (877608) headers (space savings 95.22%), 99.47MB (104300000) data
                     min         max         mean         sd        +/- sd
time for request:      486us    974.05ms    327.67ms    280.40ms    64.15%
time for connect:    26.56ms       1.02s    271.04ms    251.16ms    78.83%
time to 1st byte:   103.26ms       1.03s    537.79ms    266.34ms    59.67%
req/s           :      79.98      810.41      126.96       85.16    98.33%
```

   Here is an example of a `Caddyfile` configured for forward proxying with HTTPS:

```caddy
{
        log {
                output file /var/log/caddy/caddy_errors.log
                level ERROR
        }
}

:8444 {
        tls /etc/ssl/certs/your_cert.pem /etc/ssl/private/your_key.pem

        route {
                forward_proxy {
                        basic_auth yourusername yourpassword
                        hide_ip
                        hide_via
                        probe_resistance secret_token
                }
        }

        log {
                output file /var/log/caddy/forward_proxy_access_8444.log
                format json
        }
}
```

   This configuration makes Caddy listen on port 443 and act as a forward proxy. You can secure it with basic authentication and add other options like hiding the client's IP and Via header. You’ll need to provide your own SSL certificate and private key for the `tls` directive.

   If you don’t have SSL certificates, you can use Caddy's automatic Let's Encrypt integration by simply specifying a domain name:

```caddy
{
        log {
                output file /var/log/caddy/caddy_errors.log
                level ERROR
        }
}

yourdomain.com:8444 {
        tls {
                dns cloudflare # Optional: Use only if using DNS challenge, otherwise remove this line for HTTP-01 challenge
        }

        route {
                forward_proxy {
                        basic_auth yourusername yourpassword
                        hide_ip
                        hide_via
                        probe_resistance secret_token
                }
        }

        log {
                output file /var/log/caddy/forward_proxy_access_8444.log
                format json
        }
}
```

   In this case, Caddy will automatically generate and manage the SSL certificate for your domain.

### Step 4: Set Up Caddy as a Systemd Service

1. **Create a Caddy Systemd Service**:
   Create a systemd service file for Caddy at `/etc/systemd/system/caddy.service`:

   ```bash
   sudo nano /etc/systemd/system/caddy.service
   ```

   Add the following content:

   ```ini
   [Unit]
   Description=Caddy web server
   After=network.target

   [Service]
   User=caddy
   Group=caddy
   ExecStart=/usr/local/bin/caddy run --config /etc/caddy/Caddyfile
   ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile
   Restart=on-failure
   LimitNOFILE=1048576

   [Install]
   WantedBy=multi-user.target
   ```

2. **Reload Systemd and Start Caddy**:
   Reload the systemd daemon and start Caddy:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl start caddy
   sudo systemctl enable caddy
   sudo systemctl status caddy --no-pager -l
   sudo journalctl -u caddy.service --no-pager -l
   ```

3. **Check Caddy Status**:
   Ensure Caddy is running without issues:

   ```bash
   sudo systemctl status caddy
   ```
   ```bash
   sudo systemctl status caddy --no-pager -l
   ● caddy.service - Caddy web server
        Loaded: loaded (/etc/systemd/system/caddy.service; enabled; preset: disabled)
        Active: active (running) since Sat 2024-09-07 14:47:29 UTC; 3min 15s ago
      Main PID: 1902173 (caddy)
         Tasks: 18 (limit: 48720)
        Memory: 11.5M
           CPU: 58ms
        CGroup: /system.slice/caddy.service
                └─1902173 /usr/local/bin/caddy run --config /etc/caddy/Caddyfile
   
   Sep 07 14:47:29 almalinux9dev1 systemd[1]: Started Caddy web server.
   Sep 07 14:47:29 almalinux9dev1 caddy[1902173]: {"level":"info","ts":1725720449.1528602,"msg":"using config from file","file":"/etc/caddy/Caddyfile"}
   Sep 07 14:47:29 almalinux9dev1 caddy[1902173]: {"level":"info","ts":1725720449.1533403,"msg":"adapted config to JSON","adapter":"caddyfile"}
   Sep 07 14:47:29 almalinux9dev1 caddy[1902173]: {"level":"info","ts":1725720449.1535723,"msg":"redirected default logger","from":"stderr","to":"/var/log/caddy/caddy_errors.log"}
   ```

### Step 5: Test Your Proxy

1. **Testing**: 
   You can now test your Caddy forward proxy by configuring your browser or curl command to use the proxy.

   **Example** for using the proxy with `curl` with non-HTTPS:
   ```bash
   curl -x http://yourusername:yourpassword@your_domain.com:8081 http://example.com
   ```

   **Example** for using the proxy with `curl` with HTTPS:
   ```bash
   curl -x https://yourusername:yourpassword@your_domain.com:8444 http://example.com
   ```

   If the forward proxy is working correctly, you should be able to browse the web through Caddy.

   Example output for non-HTTPS Caddy HTTP forward proxy curl test:

   ```
   curl -x http://yourusername:yourpassword@192.168.122.60:8081 -Iv https://centminmod.com
   *   Trying 192.168.122.60:8081...
   * Connected to 192.168.122.60 (192.168.122.60) port 8081 (#0)
   * allocate connect buffer!
   * Establish HTTP proxy tunnel to centminmod.com:443
   * Proxy auth using Basic with user 'yourusername'
   > CONNECT centminmod.com:443 HTTP/1.1
   > Host: centminmod.com:443
   > Proxy-Authorization: Basic eW91cnVzZXJuYW1lOnlvdXJwYXNzd29yZA==
   > User-Agent: curl/7.76.1
   > Proxy-Connection: Keep-Alive
   > 
   < HTTP/1.1 200 OK
   HTTP/1.1 200 OK
   < Server: Caddy
   Server: Caddy
   < Content-Length: 0
   Content-Length: 0
   * Ignoring Content-Length in CONNECT 200 response
   < 

   * Proxy replied 200 to CONNECT request
   * CONNECT phase completed!
   * ALPN, offering h2
   * ALPN, offering http/1.1
   *  CAfile: /etc/pki/tls/certs/ca-bundle.crt
   * TLSv1.0 (OUT), TLS header, Certificate Status (22):
   * TLSv1.3 (OUT), TLS handshake, Client hello (1):
   * CONNECT phase completed!
   * CONNECT phase completed!
   * TLSv1.2 (IN), TLS header, Certificate Status (22):
   * TLSv1.3 (IN), TLS handshake, Server hello (2):
   * TLSv1.2 (IN), TLS header, Finished (20):
   * TLSv1.2 (IN), TLS header, Unknown (23):
   * TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
   * TLSv1.3 (IN), TLS handshake, Certificate (11):
   * TLSv1.3 (IN), TLS handshake, CERT verify (15):
   * TLSv1.3 (IN), TLS handshake, Finished (20):
   * TLSv1.2 (OUT), TLS header, Finished (20):
   * TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
   * TLSv1.2 (OUT), TLS header, Unknown (23):
   * TLSv1.3 (OUT), TLS handshake, Finished (20):
   * SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
   * ALPN, server accepted to use h2
   * Server certificate:
   *  subject: CN=centminmod.com
   *  start date: Sep  5 22:26:26 2024 GMT
   *  expire date: Dec  4 22:26:25 2024 GMT
   *  subjectAltName: host "centminmod.com" matched cert's "centminmod.com"
   *  issuer: C=US; O=Let's Encrypt; CN=E5
   *  SSL certificate verify ok.
   * Using HTTP2, server supports multi-use
   * Connection state changed (HTTP/2 confirmed)
   * Copying HTTP/2 data in stream buffer to connection buffer after upgrade: len=0
   * TLSv1.2 (OUT), TLS header, Unknown (23):
   * TLSv1.2 (OUT), TLS header, Unknown (23):
   * TLSv1.2 (OUT), TLS header, Unknown (23):
   * Using Stream ID: 1 (easy handle 0x55e879b41d80)
   * TLSv1.2 (OUT), TLS header, Unknown (23):
   > HEAD / HTTP/2
   > Host: centminmod.com
   > user-agent: curl/7.76.1
   > accept: */*
   > 
   * TLSv1.2 (IN), TLS header, Unknown (23):
   * TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
   * TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
   * old SSL session ID is stale, removing
   * TLSv1.2 (IN), TLS header, Unknown (23):
   * TLSv1.2 (OUT), TLS header, Unknown (23):
   * TLSv1.2 (IN), TLS header, Unknown (23):
   * TLSv1.2 (IN), TLS header, Unknown (23):
   < HTTP/2 200 
   HTTP/2 200 
   < date: Fri, 06 Sep 2024 11:18:54 GMT
   date: Fri, 06 Sep 2024 11:18:54 GMT
   < content-type: text/html; charset=utf-8
   content-type: text/html; charset=utf-8
   < vary: Accept-Encoding
   vary: Accept-Encoding
   < x-powered-by: centminmod
   x-powered-by: centminmod
   < expires: Fri, 13 Sep 2024 11:18:54 GMT
   expires: Fri, 13 Sep 2024 11:18:54 GMT
   < cache-control: public, max-age=604800
   cache-control: public, max-age=604800
   < link: <https://centminmod.com/>; rel="canonical"
   link: <https://centminmod.com/>; rel="canonical"
   < x-frame-options: SAMEORIGIN
   x-frame-options: SAMEORIGIN
   < x-xss-protection: 1; mode=block
   x-xss-protection: 1; mode=block
   < x-content-type-options: nosniff
   x-content-type-options: nosniff
   < strict-transport-security: max-age=15638400
   strict-transport-security: max-age=15638400
   < referrer-policy: strict-origin-when-cross-origin
   referrer-policy: strict-origin-when-cross-origin
   < permissions-policy: interest-cohort=(), accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()
   permissions-policy: interest-cohort=(), accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()
   < cwnd: 19
   cwnd: 19
   < crtt: 76000
   crtt: 76000
   < crqt: 0.000
   crqt: 0.000
   < last-modified: Fri, 09 Aug 2024 09:15:03 GMT
   last-modified: Fri, 09 Aug 2024 09:15:03 GMT
   < cf-cache-status: HIT
   cf-cache-status: HIT
   < age: 2426623
   age: 2426623
    < nel: {"success_fraction":0.01,"report_to":"cf-nel","max_age":604800}
   nel: {"success_fraction":0.01,"report_to":"cf-nel","max_age":604800}
   < server: cloudflare
   server: cloudflare
   < cf-ray: 8bee0f9f0d74840a-LAX
   cf-ray: 8bee0f9f0d74840a-LAX
   < alt-svc: h3=":443"; ma=86400
   alt-svc: h3=":443"; ma=86400

   < 
   * Connection #0 to host 192.168.122.60 left intact
   ```

   Inspecting log at `/var/log/caddy/forward_proxy_access_8081.log`:

   ```bash
   tail -10 /var/log/caddy/forward_proxy_access_8081.log | jq -c | tail -1 | jq -r
   {
     "level": "info",
     "ts": 1725621534.613994,
     "logger": "http.log.access.log0",
     "msg": "handled request",
     "request": {
       "remote_ip": "192.168.122.60",
       "remote_port": "18080",
       "client_ip": "192.168.122.60",
       "proto": "HTTP/1.1",
       "method": "CONNECT",
       "host": "centminmod.com:443",
       "uri": "centminmod.com:443",
       "headers": {
         "Proxy-Connection": [
           "Keep-Alive"
         ],
         "Proxy-Authorization": [
           "REDACTED"
         ],
         "User-Agent": [
           "curl/7.76.1"
         ]
       }
     },
     "bytes_read": 848,
     "user_id": "yourusername",
     "duration": 0.087575974,
     "size": 5427,
     "status": 0,
     "resp_headers": {
       "Server": [
         "Caddy"
       ]
     }
   }
   ```

2. **Browser Configuration**:
   - Set the Caddy server as your HTTP/HTTPS proxy in your browser settings.
   - Use `yourdomain.com:8444` for HTTPS proxy or `yourdomain.com:8081` for non-HTTPS proxy, and authenticate using the credentials you set up in the `basic_auth` directive.

### Optional: Load Balancing Across Multiple Caddy Instances

If you want to distribute traffic across multiple Caddy instances, you can set up a load balancer like HAProxy to distribute requests. Here’s a basic example of an HAProxy config that balances across multiple Caddy proxies:

```haproxy
frontend http-in
    bind *:8080
    mode tcp
    default_backend caddy-backend
    # Optionally set timeouts
    timeout client 300s

backend caddy-backend
    mode tcp
    balance roundrobin
    server caddy1 192.168.1.10:8081 check
    server caddy2 192.168.1.11:8081 check
    server caddy3 192.168.1.12:8081 check
    # Optionally set timeouts
    timeout server 300s
```

Or via Caddy load balancing:

```caddy
{
    log {
        output file /var/log/caddy/caddy_errors.log
        level ERROR
    }
}

:8080 {
    reverse_proxy {
        to 192.168.1.10:8081 192.168.1.11:8081 192.168.1.12:8081
        lb_policy round_robin  # Round robin load balancing policy

        # Optionally set timeouts
        transport http {
            dial_timeout 5s
            response_header_timeout 300s
            keepalive 300s
        }

        # Active health checks (optional)
        health_uri /health  # Health check endpoint
        health_interval 30s # Frequency of health checks
        health_timeout 5s   # Timeout for health checks
        health_status 200   # Expected status code for healthy backends
    }
    
    log {
        output file /var/log/caddy/forward_proxy_access_8080.log
        format json
    }
}
```

Combined with Caddy HTTP forward proxy:

```caddy
{
    log {
        output file /var/log/caddy/caddy_errors.log
        level ERROR
    }
}

# Forward Proxy Configuration on Port 8081
:8081 {
    route {
        forward_proxy {
            basic_auth yourusername yourpassword
            hide_ip
            hide_via
            probe_resistance secret_token
        }
    }
    log {
        output file /var/log/caddy/forward_proxy_access_8081.log
        format json
    }
}

# Load Balancer Configuration on Port 8080
:8080 {
    reverse_proxy {
        to 192.168.1.10:8081 192.168.1.11:8081 192.168.1.12:8081  # Backend servers
        lb_policy round_robin  # Round-robin load balancing policy

        # Optionally set timeouts
        transport http {
            dial_timeout 5s
            response_header_timeout 300s
            keepalive 300s
        }

        # Active health checks (optional)
        health_uri /health  # Health check endpoint
        health_interval 30s # Frequency of health checks
        health_timeout 5s   # Timeout for health checks
        health_status 200   # Expected status code for healthy backends
    }
    
    log {
        output file /var/log/caddy/forward_proxy_access_8080.log
        format json
    }
}
```

- **Forward Proxy on Port 8081**: serving the forward proxy as it was before.
- **Load Balancer on Port 8080**:
  - **`reverse_proxy`**: This directive is used to define the load balancing behavior.
  - **Backends**: The `to` directive specifies the backend servers (`192.168.1.10`, `192.168.1.11`, `192.168.1.12`) running on port `8081`.
  - **Load Balancing Policy**: The `lb_policy round_robin` ensures that traffic is evenly distributed across backends.
  - **Health Checks**: Optionally, health checks are enabled via `health_uri`, ensuring that only healthy backends are used.
  - **Logging**: Access logs for the load balancer are saved to `/var/log/caddy/forward_proxy_access_8080.log` in JSON format.

This configuration maintains your existing forward proxy on port `8081` while adding a new load balancer on port `8080` that distributes traffic across multiple backend servers.

### Conclusion

By following these steps, you will have built Caddy with the forward proxy plugin on AlmaLinux 8/9, configured it for HTTP forwarding, and set it up as a systemd service. If you want to scale the solution, you can introduce load balancing across multiple Caddy instances using HAProxy or another load balancer.