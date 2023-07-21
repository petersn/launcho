# Launcho - Ultra-simplified k8s replacement in 2k lines of Rust

I got frustrated with the complexity of k8s, so I'm writing the dumbest replacement I can.
All this program does is:
* Relaunch processes that die
* Perform health checks, and relaunch processes that fail
* Spool logs, for remote access (like with `kubectl get logs`)
* Allow remote reconfiguration, including upgrading processes
* Manage load balancing (including sunsetting processes that are upgrading, and not sending traffic to new processes until they pass a health check)

This is all written in ~2k lines of Rust.

## Setting up launcho

```bash
git clone https://github.com/petersn/launcho
cd launcho
cargo build --release
cp target/release/launcho /wherever/you/put/binaries
```

On the server do:
```bash
sudo apt-get install ipvsadm # Make sure you have ipvsadm installed
sudo launcho server
```
Also feel free to add `launcho server` to `init.d` or whatever to make it run on start-up.

Once a server is running you can run `launcho print-auth` on the server to get the auth info needed for connecting. It'll look something like:
```
# Paste this into ~/.launcho/launcho-client-auth.yaml on the client machine
host: change-me-to-point-to-the-server.example.com:12888
cert: |
  -----BEGIN CERTIFICATE-----
  MIIBWzCCAQKgAwIBAgIUY2V0NJXiRC+qMdydF42rmIR6TfIwCgYIKoZIzj0EAwIw
  ITEfMB0GA1UEAwwWcmNnZW4gc2VsZiBzaWduZWQgY2VydDAgFw03NTAxMDEwMDAw
  MDBaGA80MDk2MDEwMTAwMDAwMFowITEfMB0GA1UEAwwWcmNnZW4gc2VsZiBzaWdu
  ZWQgY2VydDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBNEBkWsYqN/EDudl0mE
  f2cLr1iWbGMB7YmoxmVy+VMzAZ1WvKO23kenPNKNHZC9vomNLww7HtRHDau4GmXd
  +J6jFjAUMBIGA1UdEQQLMAmCB2xhdW5jaG8wCgYIKoZIzj0EAwIDRwAwRAIgSd8V
  Q7j0xX/zGmyiaAToDXMzo/3pjmZ4WtLUg4ROfTYCIFV1Kjw1lHObS0HPVUkc8UKq
  Kul0XMy4//sfCpqT1SeD
  -----END CERTIFICATE-----
private: null
token: 4d0f71f5d2d69b25b6a1638245386ebb1b3f6f4cc109006907707fa6e30bedd8
```
You then paste this into `~/.launcho/launcho-client-auth.yaml` on the client machine, after first changing `host` to point to the server.

Finally, you can control the launcho server. You should be able to see something like:
```bash
$ launcho status
Events:
  Warning { msg: "Auth file not found at \"/root/.launcho/launcho-server-auth.yaml\" -- generating a new one" }
```

## Using launcho

The main idea is that launcho has a "target" configuration that it is attempting to reach.
This target is specified via yaml that you can version control.
To get the current target:
```
launcho target get     # or launcho t get
```
To set the current target:
```
launcho target set FILE     # or launcho t set FILE
```

The default target file will look like:
```
# No orchestration target set, this is an example file.
# Use `launcho target get` and `launcho target set` to edit this.

# Create processes like this:
processes:
  # -
  #   name: "example_proc"
  #   command: ["python", "server.py"]
  #   env:
  #     # Use ${SECRET_NAME} to access secrets defined in the server config.
  #     DATABASE_URL: "${DATABASE_URL}"
  #   # List all services this process should receive traffic from.
  #   # Each service for each process gets allocated a port, which is given
  #   # via a corresponding environment variable, in this case SERVICE_PORT_WEB.
  #   receives:
  #     - "web"
  #   # Define an endpoint to hit to check for health.
  #   health:
  #     service: "web"
  #     path: "/health"
  #   #uid: "whoever"
  #   #gid: "whoever"
  #   #cwd: "/var/wherever"

# Create services like this:
services:
  # -
  #   name: "web"
  #   on: "127.0.0.1:5000"
```

There are several concepts here:
| Name     | Meaning |
| -------- | ------- |
| `target` | The configuration of processes + services that launcho is trying to keep running |
| `process` | A single process that launcho is trying to keep running (basically a k8s pod) |
| `service` | Each "service" load balances traffic over some set of processes that receive it (basically a k8s service) |
| `secret` | Launcho maintains a key-value store mapping secrets to strings (basically a k8s secret) |
| `resource` | Launcho stores blobs of data that processes can access (used like k8s container images) |

Each service will be routed to every process that receives it.
Each process will get an environment variable with a name like `SERVICE_PORT_SERVICE_NAME` for every service it receives -- your processes should bind to `localhost:that service port` in order to receive their load-balanced share of the service requests.

You can list/upload/download/delete resources with:
```
launcho resource ls          # or launcho l ls
launcho resource up FILE     # ... and so on
launcho resource down RESOURCE_ID OUTPUT_FILE
launcho resource rm RESOURCE_ID RESOURCE_ID...
```

You can modify secrets with:
```
launcho secret ls       # or launcho s ls
launcho secret get SECRET_NAME SECRET_NAME... 
launcho secret set SECRET_NAME VALUE
launcho secret rm SECRET_NAME SECRET_NAME...
```
Note that modifying a secret will automatically launch new versions of any processes whose configs depend on it, and traffic will be moved over once the new versions are healthy.

## Intended workflow

A process may request some resources be placed in its working directory, and you can run a command before the process is started.
This is the intended mechanism for making what are basically "container images".
For example, using the following server:
```
const http = require('http');
const url = require('url');

const server = http.createServer((req, res) => {
  const path = url.parse(req.url).pathname;
  if (path === '/health') {
    res.statusCode = 200;
    res.end('OK');
  } else if (path === '/') {
    res.statusCode = 200;
    res.end('Hello, world!');
  } else {
    res.statusCode = 404;
    res.end('Not Found');
  }
});

const port = process.env.SERVICE_PORT_TRAFFIC;
server.listen(port, () => console.log(`Server running on port ${port}`));
```

we could set the following target (using `launcho target set target.yaml`):

```
processes:
  -
    name: "main_server"
    resources:
    -
      id: "${BUNDLE_RESOURCE_ID}"
      file: "bundle.tar.bz2"
    before: |
      tar -xf bundle.tar.bz2
      mv bundle/* .
    command: ["node", "server.js"]
    receives:
      - "traffic"
    health:
      service: "traffic"
      path: "/health"

services:
  -
    name: "traffic"
    on: "127.0.0.1:5000"
```

Then to deploy a new version you need merely do:
```
# Assuming bundle/server.js contains the above server...
tar -cvvhjf bundle.tar.bz2 bundle/
launcho resource up bundle.tar.bz2 | tee NEW_RESOURCE_ID
launcho secret set BUNDLE_RESOURCE_ID $(cat NEW_RESOURCE_ID)
```
This would cause a new version of the server to launch.
All traffic to port 5000 will then be rerouted from the old version to the new version once the new version passes a health check, and then the old version will be killed.

You can check up on the server with `launcho status`, and get its logs via `launcho logs PROCESS_RANDOM_NAME`.

The assumption is that generally you'll point some sort of TLS-handling reverse proxy at your services (for example, maybe you point nginx at 127.0.0.1:5000, and leave nginx outside of the purview of launcho, but that's not mandatory, of course).

