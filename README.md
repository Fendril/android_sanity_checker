# android_sanity_checker

## What is it?
**android_sanity_checker** is a tool made to compare an ADB dump of an android smartphone against one or many other dumps.
This utility is made to compare same models smartphones and do a batch analysis from a white reference.
Every differences found between the ADB dump reference and others ADB dumps, will be reported in a .csv file and make a YARA Scan of this difference.
**android_sanity_checker** will write as many CSV reports as modules (plain text config files parsed) it will do into each device directory.
This choice was made to make easier the usage of these results into solutions like Splunk.
There is an embedded open source compiled YARA rules.

Still working on more features with IoC's and YARA scans.

## How it works?
### Usage
If you are on Windows OS, you can download the latest release and execute it.
**android_sanity_checker** will prompt you to choose a Yara rules directory, if you don't have, or don't want to use it, just choose Cancel or press 'ESC'.
There is an open source Yara Rules by default that will make a first large job.
__Be careful__ : Many Yara rules are designed to work with **THOR Lite or LOKI**. There are identifiers that may be undefined and these rules will be Skipped.
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
### Behind the scene
**android_sanity_checker** will parse recursively every files and folders of the selected YARA Folder.
Then it will try to add and compile every single YARA rule file. If everything is fine, it will add it to the custom YARA rules for later.
Otherwise it will report to you that something went wrong and report to you the file.
**android_sanity_checker** will continue the search anyway en in the end of this first step, will resume to you how many
YARA rules were skipped for duplication (based on rules name) and how many contained errors.

The second step is the reference creation.
**asc** is going to parse every config text file of the white ADB Dump and reference every configuration into a volatile SQLite DB.
As well for any binaries into __*/system/bin/__ but for binaries, it will calculate SHA256 sum and insert them into DB for comparison later.

Last step, is to analyze the folder recursively you gave for analysis. (again, be sure to stand the tree I made as model before)
It will do as for the reference but every time something is not like the White ADB, it will report it into a reporting file and do a YARA scan on this.
For binaries, it will compare SHA256, and in case of difference, will report it into the __reported_binaries.csv__ file after a YARA scan.

Every MIME-TYPED files that could be found with Magic Numbers, will be scanned as is and if YARA found rules matching, it will be reported to __reported_yara_matches.csv__ file.

These 2 last files are created into the directory where you executed **android_sanity_checker**.

### Use as a crate
If you need to use it as a crate, I reworked code from 0.1.5-alpha to be more modules standardized.
I will work on doc to make it easier to import and understand.
At this point, know that you'll need to call ::new(ref_path: String, analyze_path: String, custom_yara_path: String) to get an AndroidParser structure.
Then : 2 methods to use as public
- go_ref()
- go_parse()

## Future features
Actual version is 0.1.5-alpha.
- I think about working on a slint gui to make the tool more user-friendly.
- There are many files into "system" folder that are not parsed or analyzed actually, and still working on this to make the tool more complete.
- Doc.rs may come...

## Issues
Testing very aggressive Multi-threading, **android_sanity_checker** will consume **100% CPU** to work as fast as it can. (~1min / Device [2Go])

Feel free to say which features you would like to see in futures versions, and any useful information to analyze on android devices.
If you encounter any disfunction, please report it so I can work on a fix and make this tool greater.

## Work in progress
Please consider it as an unfinished tool, it may have some bugs to fix.