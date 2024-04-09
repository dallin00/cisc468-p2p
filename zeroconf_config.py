import time
from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser, ServiceStateChange
import socket

def create_zeroconf_service():
    """
    Creates a zeroconf service to be detected on the local network.

    Returns:
      - ServiceInfo that allows for local discovery
      - error if any occurred during execution
    """
    # Ping google to get local ip address
    connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connection.connect(("8.8.8.8", 80))
    local_ip = connection.getsockname()[0]
    connection.close()

    r = Zeroconf()
    addresses = [local_ip]
    info = ServiceInfo(
        "_tls._tcp.local.",
        "TLS._tls._tcp.local.",
        addresses=addresses,
        port=8081,
    )
    r.register_service(info)
    return r


def on_service_state_change(zeroconf, service_type, name, state_change):
    if state_change is ServiceStateChange.Added:
        info = zeroconf.get_service_info(service_type, name)
        if info:
            addresses = ["%s:%d" % (addr, int(info.port)) for addr in info.parsed_scoped_addresses()]
            print("  Addresses: %s" % ", ".join(addresses))


def list_zeroconf_services():
    """
    Finds local devices accepting TLS connections & displays them.
    """
    print("\nLocal Devices:")
    zeroconf = Zeroconf()
    browser = ServiceBrowser(zeroconf, "_tls._tcp.local.", handlers=[on_service_state_change])

    try:
        time.sleep(2)
    except KeyboardInterrupt:
        pass
    finally:
        zeroconf.close()