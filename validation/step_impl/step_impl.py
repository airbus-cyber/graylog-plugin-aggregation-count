from getgauge.python import step
from pathlib import Path
import subprocess
from threading import Thread
from queue import Queue

def put_stream_lines_in_queue(stream, queue):
    while True:
        line = stream.readline()
        if (line == ''): break
        queue.put(line)

def docker_compose(docker_compose_command):
    command = ['docker-compose'] + docker_compose_command
    subprocess.run(command, cwd='execution_environment')


@step("Start Graylog server")
def start_graylog_server():
    docker_compose(['up', '--detach'])
    # TODO clean this up and factor with the other docker_compose commands
    graylog_logs = subprocess.Popen(['docker-compose', 'logs', '--no-color', '--follow'], stdout=subprocess.PIPE, text=True, cwd='execution_environment')
    logs = Queue()
    reading_logs = Thread(target=put_stream_lines_in_queue, args=[graylog_logs.stdout, logs])
    reading_logs.start()
    while True:
        try:
            log = logs.get(1)
        except Empty:
            raise AssertionError('Graylog server did not start correctly')
            break
        print(log)
        if 'Graylog server up and running.' in log:
            break
    graylog_logs.terminate()
    reading_logs.join()

    
@step("Stop Graylog server")
def stop_graylog_server():
    docker_compose(['down'])

