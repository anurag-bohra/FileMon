# FileMon
A simple Filesystem monitor with virustotal query integration and events being sent to elastic. The code has been tested on Linux(Debian)/MACOS Catalina. The code should also work in Windows though.

A databasew is mentioned with all the file details with the has so as to avoid repeated lookup in virusTotal.

**settings.yaml**
This file should be present in the directory where the script files are present. Please input following fields in this file.
```
pathsFile: "paths.yaml"
virustotalAPI: <API_KEY>
elasticIP: "localhost"
elasticPort: "9200"
databaseFile: "files.db"
```

**paths.yaml**
This file specifies the file paths that needs to be monitored. Monitor has been added for three type of events which are Create, Modify and Delete. The paths can be specified either in absoulute format or relative. Input the paths in respective keys. We can specify either directory or a path to a file. To specify directory, end thepath with the '/' or '\\' respectively.
```
fileEvents:
  createEvents:
    - /Library/LaunchAgents/
  modifyEvents:
    - ~/Library/Preferences/com.apple.loginwindow.plist
  deleteEvents:
    - ~/Library/Preferences/ByHost/
```

Requirements:
**Python 3.7+**
Library requirements:
```
pip3 install watchdog
pip3 install elasticsearch
pip3 install requests
pip3 install pyyaml
```

Execution: Simply run ```python3 main.py``` with no arguments. it starts monitoring the paths. If the path specified does not exist, it will be added to watchdog observer once the path becomes accessible. 

**Future Work:**
1. Incase of plist files, parsing the file to read the Executable Path and auto-scanning that.
2. Add more Event handler types such as read, open
3. Include Process Monitor and environment variable scanning for various other scans such as PRELOAD, DYLIB 
4. Add Regex based filtering for paths
5. Add Filtering based on known File types such as macho, PE, ELF, etc. 
