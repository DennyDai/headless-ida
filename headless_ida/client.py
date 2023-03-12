import rpyc
import socket
import os
import subprocess


class HeadlessIda():
    def __init__(self, idat_path, binary_path):
        server_path = os.path.join(os.path.realpath(
            os.path.dirname(__file__)), "server.py")
        port = 8000
        with socket.socket() as s:
            s.bind(('', 0))
            port = s.getsockname()[1]
        p = subprocess.Popen(
            f'{idat_path} -A -S"{server_path} {port}" -P+ {binary_path}', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while True:
            if p.poll() is not None:
                raise Exception(f"IDA failed to start: return code {p.poll()}\n{p.stderr.read().decode()}")
            try:
                self.conn = rpyc.connect("localhost", port)
            except:
                continue
            break

    def import_module(self, mod):
        return self.conn.root.import_module(mod)

    def __del__(self):
        if hasattr(self, "conn"):
            self.conn.close()
