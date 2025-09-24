import os
from django.conf import settings as _settings


# Unix socket of clamd. If not provided we will guess.
CLAMAV_UNIX_SOCKET = getattr(_settings, 'CLAMAV_UNIX_SOCKET', None)

if CLAMAV_UNIX_SOCKET is None:
    known_list = [
        '/var/run/clamd.scan/clamd.sock',  # Fedora, CentOS
        '/var/run/clamav/clamd.ctl',  # Ubuntu, Debian based
        '/var/lib/clamav/clamd.sock'  # Arch
    ]
    for path in known_list:
        if os.path.exists(path):
            CLAMAV_UNIX_SOCKET = path
            break

# If you want to use TCP socket set this to True
CLAMAV_USE_TCP = getattr(_settings, 'CLAMAV_USE_TCP', False)

# Default clamd TCP socket port
CLAMAV_TCP_PORT = getattr(_settings, 'CLAMAV_TCP_PORT', 3310)
# Default clamd TCP socket address
CLAMAV_TCP_ADDR = getattr(_settings, 'CLAMAV_TCP_ADDR', '127.0.0.1')

# Enable clamd scanner. By default True. Set to False only for development.
CLAMAV_ENABLED = getattr(_settings, 'CLAMAV_ENABLED', True)

# Maximum file size to scan
CLAMAV_MAX_FILE_SIZE = getattr(_settings, 'CLAMAV_MAX_FILE_SIZE', 2147483648)
