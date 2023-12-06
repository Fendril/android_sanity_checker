# android_sanity_checker

## What is it?
**android_sanity_checker** is a tool made to compare an ADB dump of an android smartphone against one or many other dumps.
This utility is made to compare same models smartphones and do a batch analysis from a white reference.
Every differences found between the ADB dump reference and others ADB dumps, will be reported in a .csv file and make a YARA Scan of this difference.
**android_sanity_checker** will write as many CSV reports as modules it will do into each device directory.
This choice was made to make easier the usage of these results into solutions like Splunk.
There is an embedded open source compiled YARA rules. At starting, it may ask for a folder where you may have your custom YARAs.
It will test them, purge the errored ones and compile the valid ones. Then it will add them to the default scan.

Still working on more features with IoC's and YARA scans.

## How it works?
If you are on Windows OS, you can download the latest release and execute it.
**android_sanity_checker** will prompt you to choose a Yara rules directory, if you don't have, or don't want to use it, just choose Cancel or press 'ESC'.
There is an open source Yara Rules by default that will make a first large job.
Be careful : Many Yara rules are designed to work with THOR Lite or LOKI. There are identifiers that may be undefined and these rules will be Skipped.
As well, it will continue the job to compare reference with others ADB dumps.
Then you will be prompted to choose a reference directory. Select the directory of your reference device (the White ADB Dump). **android_sanity_checker** will internally create a SQLite Database into memory to work faster than a file to file comparison.
In the end, you will be prompted to select a Directory to analyze. Select it, and the tool will recursively check into all of the directory and subdirectories to do th analysis work.

Be sure to have a folder like this
```
    |_All_my_devices
        |_Device_A
            |_backup
            |_dumpsys
            |_info
            |_live
            |_package_manager
            |_sdcard
            |_system
        |_Device_B
            |_(...)
        |_Device_C
            |_(...)
--------|
```

## Future features
Actual version is 0.1.4-alpha.
- I think about working on a slint gui to make the tool more user-friendly.
- There are many files into "system" folder that are not parsed or analyzed actually, and still working on this to make the tool more complete.

## Issues
Feel free to say which features you would like to see in futures versions, and any useful information to analyze on android devices.
If you encounter any disfunction, please report it so I can work on a fix and make this tool greater.

## Work in progress
Please consider it as an unfinished tool, it may have some bugs to fix.