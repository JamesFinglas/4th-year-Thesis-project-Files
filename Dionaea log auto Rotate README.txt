This script will enable auto rotation of the Dionaea Sensor logs.

Step 1: Enter the logrotate.d folder at the following location from the root folder:
/etc/logrotate.d

Step 2: place this file in this location and ensure it has root permissions

Step 3: If permissions must be adjust use the following command:
sudo chmod 660 root root

Step 4: once the file is in place and the sensor is installed be sure to restart the sensor with the command:
sudo supervisorctl restart dionaea

Congratulations, your sensor is now set to auto rotate logs and conserve storage space.