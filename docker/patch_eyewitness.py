"""Pin the browser to the local scope proxy; refuse standalone EyeWitness execution."""
from pathlib import Path

path = Path('/opt/eyewitness/Python/modules/selenium_module.py')
source = path.read_text()
needle = 'options = ChromeOptions()'
assert source.count(needle) == 1, 'Unexpected EyeWitness browser adapter; review required'
source = source.replace(needle, '''options = ChromeOptions()
        options.ignore_local_proxy_environment_variables()
        proxy = os.environ.get('HB_CAPTURE_PROXY')
        if not proxy:
            raise RuntimeError('A HackingBara scope proxy is required')
        options.add_argument('--proxy-server=' + proxy)
        options.add_argument('--proxy-bypass-list=<-loopback>')
        options.add_argument('--disable-quic')
        options.add_argument('--force-webrtc-ip-handling-policy=disable_non_proxied_udp')
        options.add_argument('--disable-background-networking')
        options.add_argument('--disable-extensions')''')
path.write_text(source)
