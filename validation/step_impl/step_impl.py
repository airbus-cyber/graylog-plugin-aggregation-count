from getgauge.python import before_suite, after_suite, step
from selenium.webdriver import Firefox
from step_impl.graylog_server import GraylogServer

@before_suite
def init():
    # Note: I am not sure this is better, or using the data_store.suite is better...
    global browser
    global server
    server = GraylogServer()
    browser = Firefox()
    
@after_suite
def close():
    browser.close()

@step("Start Graylog server")
def start_graylog_server():
    server.start()
    server.wait_until_log('Graylog server did not start correctly')
    
@step("Stop Graylog server")
def stop_graylog_server():
    server.stop()

