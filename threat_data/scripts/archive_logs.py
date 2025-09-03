import os
import shutil
from datetime import date,timedelta

log_dir = "/opt/threat_data/logs"
archive_dir = "/opt/threat_data/logs/archive"

os.makedirs(log_dir,exist_ok=True)

yesterday = (date.today() - timedelta(days=1)).strftime("%Y-%m-%d")

for filename in os.listdir(log_dir):
    if filename.endswith(".json") and yesterday in filename:
        source = os.path.join(log_dir,filename)
        dest = os.path.join(archive_dir,filename)

        shutil.move(source,dest)
        print(f"Archived File : {filename}")
