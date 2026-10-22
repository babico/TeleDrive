"""Single-process Web UI + path-style S3, routed by socket-local TCP port."""
import argparse
import socket
import uvicorn
from web.app import app as web_app
from web.s3 import app as s3_app

class UnifiedApplication:
    def __init__(self, web_port=8080, s3_port=9000):
        if not all(1 <= value <= 65535 for value in (web_port,s3_port)) or web_port == s3_port:
            raise ValueError("Distinct valid Web and S3 ports required")
        self.web_port, self.s3_port = web_port, s3_port

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            await web_app(scope, receive, send)
            return
        if scope["type"] not in ("http","websocket"):
            raise RuntimeError("Unsupported ASGI scope")
        server = scope.get("server")
        if not server or len(server) < 2:
            raise RuntimeError("Missing local listener identity")
        if server[1] == self.web_port:
            await web_app(scope, receive, send)
        elif server[1] == self.s3_port:
            await s3_app(scope, receive, send)
        elif scope["type"] == "http":
            from starlette.responses import PlainTextResponse
            await PlainTextResponse("Unknown TeleDrive listener",status_code=421)(scope,receive,send)
        else:
            await send({"type":"websocket.close","code":1008})

app = UnifiedApplication()

def _bind(host, port):
    sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        sock.bind((host,port))
        sock.listen(2048)
        sock.set_inheritable(False)
        return sock
    except BaseException:
        sock.close()
        raise

def main():
    import web.app as webapp

    parser=argparse.ArgumentParser()
    parser.add_argument("--host",default=None)
    parser.add_argument("--web-port",type=int,default=None)
    parser.add_argument("--s3-port",type=int,default=None)
    args=parser.parse_args()
    host = args.host or webapp.settings_bind_address()
    web_port = args.web_port or webapp.settings_web_port()
    s3_port = args.s3_port or webapp.settings_s3_port()
    service=UnifiedApplication(web_port,s3_port)
    listeners=[]
    # Materialize the TLS settings BEFORE building the server configs:
    # uvicorn.Config captures ssl_certfile at construction time, but the
    # webapp globals are only populated by _reload_service_settings()
    # (previously first-run during lifespan — too late, TLS was silently
    # dropped).
    webapp._reload_service_settings()

    # Two servers: WebUI and S3 get INDEPENDENT TLS settings. The web UI
    # commonly stays plain HTTP behind a reverse proxy (storage.trusted_
    # proxy) while the S3 listener serves direct TLS, or vice versa.
    import asyncio
    web_socket = _bind(host, service.web_port)
    s3_socket = _bind(host, service.s3_port)
    web_server = uvicorn.Server(uvicorn.Config(
        service, host=host, port=service.web_port,
        workers=1, lifespan="on", server_header=False,
        ssl_certfile=webapp.SSL_CERTFILE or None,
        ssl_keyfile=webapp.SSL_KEYFILE or None,
    ))
    s3_server = uvicorn.Server(uvicorn.Config(
        service, host=host, port=service.s3_port,
        workers=1, lifespan="off", server_header=False,
        ssl_certfile=webapp.S3_SSL_CERTFILE or None,
        ssl_keyfile=webapp.S3_SSL_KEYFILE or None,
    ))
    # One server owns the signal handlers; the second must not install
    # its own in the same event loop.
    s3_server.install_signal_handlers = lambda: None

    async def _serve():
        await asyncio.gather(
            web_server.serve(sockets=[web_socket]),
            s3_server.serve(sockets=[s3_socket]),
        )
    try:
        asyncio.run(_serve())
    finally:
        web_socket.close()
        s3_socket.close()

if __name__=="__main__":
    main()
