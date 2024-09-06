A guide on building Caddy with the `forwardproxy` plugin on [Centmin Mod LEMP stack server](https://centminmod.com) running AlmaLinux 9.

### Step 1: Install Dependencies
First, ensure you have the necessary tools for building software, as well as Go, which is required to build Caddy.

1. **Update your system**:
   ```bash
   sudo dnf update -y
   ```

2. **Install Go**:
   Download and install the latest Go version (replace with the latest version link if necessary).

   ```
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
   xcaddy build --with github.com/caddyserver/forwardproxy@latest
   ```

   This will download the Caddy source code and build it with the forward proxy plugin.

3. **Setup Caddy**:
   Once the build is complete, move the Caddy binary to `/usr/local/bin`:

   ```bash
   sudo mv caddy /usr/local/bin/caddy
   sudo chmod +x /usr/local/bin/caddy
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
   sudo nano /etc/caddy/Caddyfile
   ```

   Here is an example of a `Caddyfile` configured for forward proxying with non-HTTPS:

   ```caddy
   {
       log {
           output file /var/log/caddy/caddy_errors.log
           level ERROR
       }
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
       }
   }
   ```

   This configuration makes Caddy listen on port 81 and act as a forward proxy.

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
           dns cloudflare   # Optional: Use only if using DNS challenge, otherwise remove this line for HTTP-01 challenge
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