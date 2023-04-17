from cx_Freeze import setup, Executable

# Executable File + Icon
executables = [Executable('CableOrca.py', icon='CableOrcaIco.ico')]

# Configuration
setup(
    name='CableOrca',
    version='1.0',
    description='CableOrca High Level Packet Sniffer',
    executables=executables,
    options={
        'build_exe': {
            'packages': ['scapy', 'ipwhois', 'mac_vendor_lookup', 'matplotlib', 'requests', 'scapy.layers.bluetooth', 'scapy.layers.l2', 'speedtest_cli']
        }
    }
)
