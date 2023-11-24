# android_sanity_checker
## What is it?
**android_sanity_checker** is a tool made to compare an ADB dump of an android smartphone against one or many other dumps.
This utility is made to compare same models smartphones and do a batch analysis.
Every differences found between the ADB dump reference and others ADB dumps, will be reported in a .csv file.
**android_sanity_checker** will write as many CSV reports as modules it will do into each device directory.
This choice was made to make easier the usage of these results into solutions like Splunk.
At starting, the tool will ask for an Yara rules directory. If you do so, every difference found, will be anayzed with these rules you pushed and be reported as well into the CSV into the 2 fields "yara_match" and "yara_rulename".

Still working on more features with IoC's and YARA scans.

## How it works?
If you are on Windows OS, you can download the latest release and execute it.
**android_sanity_checker** will prompt you to choose a Yara rules directory, if you don't have, or don't want to use it, just choose Cancel.
There is an open source Yara Rules by default that will make a first job.
Be careful : Many Yara rules are designed to work with THOR Lite or LOKI. There are identifiers that may be undefined and these rules will be Skipped.
As well, it will continue the job of compare reference with others ADB dumps.
Then you will be prompted to choose a reference directory. Select the directory of you reference device. android_sanity_checker will internally create a SQLite Database into memory to work faster than a file to file comparison.
In the end, you will be prompted to select a Directory to analyze. Select it, and the tool will recursively check into all of the directory and subdirectories to do th analysis work.

## Future features
Actual version is 0.1.4-alpha.
- I think about working on a slint gui to make the tool more user-friendly.
- There is many files into "system" folder that are not parsed or analyzed actually, and still working on this to make the tool more complete.

## Issues
Feel free to say which features you would like to see in futures versions, and any useful information to analyze on android devices.
If you encounter any disfunction, please report it so I can work on a fix and make this tool greater.

## Work in progress
Please consider it as an unfinished tool, it may have some bugs to fix.