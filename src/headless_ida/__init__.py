from importlib import metadata

from .cli import headlessida_cli, headlessida_server_cli
from .client import HeadlessIda, HeadlessIdaRemote
from .server import HeadlessIdaServer

__version__ = metadata.version("headless-ida")
