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

# Modern applications render asynchronously after the initial page navigation.
# EyeWitness's implicitly_wait() does not wait unless an element is searched.
source = path.read_text()
needle = '        driver.get(http_object.remote_system)'
assert source.count(needle) == 1, 'Unexpected EyeWitness navigation adapter; review required'
source = source.replace(needle, '''        from selenium.webdriver.support.ui import WebDriverWait
        import time
        try:
            driver.get(http_object.remote_system)
        except TimeoutException:
            # Keep the already rendered document when a slow asset delays load.
            driver.execute_script('window.stop()')
        time.sleep(2)
        try:
            WebDriverWait(driver, 15).until(lambda browser: browser.execute_script(
                "return document.body && document.body.innerText.trim() && "
                "!/^loading[\\\\s.\\u2026]*$/i.test(document.body.innerText.trim())"
            ))
        except TimeoutException:
            pass  # Persist the visible page, including stalled applications.''')
# Headers are collected separately by HackingBara through its pinned connection.
# Avoid EyeWitness's additional HTTP client bypassing that connection adapter.
needle = '''    headers, header_error = collect_http_headers(
        url=http_object.remote_system,
        timeout=getattr(cli_parsed, 'timeout', 7),
        user_agent=ua or getattr(cli_parsed, 'user_agent', None),
        proxy=proxy_config
    )'''
assert source.count(needle) == 1, 'Unexpected EyeWitness header adapter; review required'
source = source.replace(needle, '    headers, header_error = {}, None')
path.write_text(source)
