This script will automatically manage the compressiona nd rotation of the 
Dionaea Sensors Bistream folder to conserve storage space.

****Disclaimer: Please keep in mind this script will delete the bistreams 
    every 6 hours, therefore, if the user intends to perform any malware 
    analysis of these they mist be downloaded prior to deletion. ****

Step 1: navigate to the root folder

Step 2: place this file in this location and ensure it has root permissions

Step 3: If permissions must be adjust use the following command:
sudo chmod 660 root root

Step 4: Make the script executabel with the following command:
chmod +x bistream_rotate

Step 5: add the job to the crontab manaagement interface to create a recurring CronJob
with the following command to open the cron tab config file:
cron tab -e

Step 6: Select the first option (1) to edit the file with the nano editor

Step 7: Add the following line to the bottom of the file

0 * * * * /root/bistream_rotate

Step 8: Save the file with ctrl+x then y and enter.

Congratulations. Youve now created your Donara bistream compression/rotation CronJob.



