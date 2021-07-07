import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import threading
import utilities
import time


MAIN_OBSERVER_OBJECT = None
INACTIVE_MONITOR_PATHS = list()
ACTIVE_MONITOR_PATHS_WATCH = list()


class Handler(FileSystemEventHandler):
    def check_log(self, paths, event):
        flag = False
        for path in paths:
            if str(event.src_path).startswith(path):
                flag = True
                break
        return flag

    def on_created(self, event):
        paths = utilities.get_event_file('createEvents')
        flag = self.check_log(paths, event)
        if flag:
            utilities.event_handler(event)

    def on_deleted(self, event):
        paths = utilities.get_event_file('deleteEvents')
        flag = self.check_log(paths, event)
        if flag:
            utilities.event_handler(event)

    def on_modified(self, event):
        paths = utilities.get_event_file('modifyEvents')
        flag = self.check_log(paths, event)
        if flag:
            utilities.event_handler(event)


def init_watchdog(complete_paths):
    global MAIN_OBSERVER_OBJECT
    global ACTIVE_MONITOR_PATHS_WATCH
    handler = Handler()
    observer = Observer()
    MAIN_OBSERVER_OBJECT = observer
    for path in complete_paths:
        watch = observer.schedule(handler, path=path, recursive=True)
        temp = dict()
        temp['path'] = path
        temp['object'] = watch
        ACTIVE_MONITOR_PATHS_WATCH.append(temp)
    try:
        observer.start()
    except FileNotFoundError:
        print("ERROR")
        sys.exit(1)
    try:
        while True:
            # Set the thread sleep time
            time.sleep(1)
    except KeyboardInterrupt:
        print("ERROR")
        observer.stop()
    observer.join()


def update_watchdog():
    global MAIN_OBSERVER_OBJECT
    global ACTIVE_MONITOR_PATHS_WATCH
    if MAIN_OBSERVER_OBJECT is not None:
        global INACTIVE_MONITOR_PATHS
        new_paths = list()
        handler = Handler()
        while(True):
            for path in INACTIVE_MONITOR_PATHS:
                if os.path.exists(path):
                    watch = MAIN_OBSERVER_OBJECT.schedule(handler, path=path, recursive=True)
                    INACTIVE_MONITOR_PATHS.remove(path)
                    temp = dict()
                    temp['path'] = path
                    temp['object'] = watch
                    ACTIVE_MONITOR_PATHS_WATCH.append(temp)
            for pathObject in ACTIVE_MONITOR_PATHS_WATCH:
                path = pathObject['path']
                if not os.path.exists(path):
                    removeWatch = MAIN_OBSERVER_OBJECT.unschedule(pathObject['object'])
                    ACTIVE_MONITOR_PATHS_WATCH.remove(pathObject)
                    INACTIVE_MONITOR_PATHS.append(path)


def main():
    settingsFile = utilities.read_yaml()
    global INACTIVE_MONITOR_PATHS
    if utilities.check_path(settingsFile):
        paths = utilities.get_paths()
        complete_paths = list(set(paths['createEvents'] + paths['modifyEvents'] + paths['deleteEvents']))
        complete_paths = [os.path.expanduser(path) for path in complete_paths]
        existent_paths = [path for path in complete_paths if os.path.exists(path)]
        INACTIVE_MONITOR_PATHS = [path for path in complete_paths if path not in existent_paths]
        mainWatchdogThread = threading.Thread(target=init_watchdog, name='main Watchdog Thread', args=(existent_paths,))
        mainWatchdogThread.start()
        time.sleep(5)
        updateWatchdogThread = threading.Thread(target=update_watchdog, name='Update Watchdog Thread')
        updateWatchdogThread.start()

    else:
        print("Settings File Does not Exist")


if __name__ == "__main__":
    main()
