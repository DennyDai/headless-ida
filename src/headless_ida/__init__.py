from importlib import metadata

from .client import HeadlessIda, HeadlessIdaRemote
from .server import HeadlessIdaServer

from .cli import headlessida_cli, headlessida_server_cli

__version__ = metadata.version("headless-ida")
