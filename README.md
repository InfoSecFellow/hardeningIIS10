# Hardening IIS 10 v1.0
Hardening for IIS 10 is a project to automate the implementation of security controls in IIS 10.

In this project, there are 45 scripted security controls and 43 rollback scripts.
....Why are there only 43 rollback scripts and not 45?

There are two security controls that only validate the IIS configuration; if necessary, changes must be made manually.

- 2.7 - Ensure 'passwordFormat' is not set to clear (can do manual rollback based in the web.config file or using the information stored in the .json backup file).
- 2.8 - (Check) Ensure 'credentials are not stored' in configuration files (only check the configuration)

# Description of how to use the tool

>>> **Before using the tool, ensure that backups of the folders are available and, if possible, create a server snapshot (in case it is a virtual server).** <<< 

There are two main options in the tool:

**- Hardening Deployment:** deploy the security controls.
**- Hardening Rollback:** perform the rollback of the security controls.

The **Run All** option applies to both **Deployment** and **Rollback**, in the same way as the **Run Selected** option.

When executing **Run All**, the tool will automatically create backups of the following directories:

>> inetpub
>> inetsrv
>> .NET folders

However, manual backups can also be performed for additional safety.

After executing **Run All**, the IIS service will be restarted, and all websites will be impacted by this service restart.
**All backup files will be compressed into a .zip file**. It is important to **extract the .zip** file in order to perform a rollback if necessary.
The **Clear Screen** button only clears the log screen to make it easier to read during the next execution.

The **Abort** button stops the execution. However, the current script will continue running until completion, and the abort will only prevent the execution of the next scripts.

The **Check Hardening** button generates a .txt report in the **logs folder**. The filename will contain the word "compliance".


This script calculates how many controls were successfully implemented and how many were not, providing totals and a percentage related to the Hardening implementation.

It is recommended to always run the **Check Hardening** option before applying IIS 10 Hardening, as this provides a baseline metric of the configuration state before the hardening is applied.

# In case of negative impact on the application, how to perform a rollback?

1 - Extract the .zip backup file.
2 - Select the **Hardening Rollback** option and execute **Run All**.
(If you prefer to **roll back a single control**, select the desired control from the list and execute **Run Selected**.)
3 - If the application continues to experience issues even after performing the rollback through the tool, **perform a manual rollback** of the following folders:

>> inetpub
>> inetsrv
>> .NET folders

However, it is recommended to perform a prior analysis to identify which control is causing the issue and roll back only that specific control. 
In critical cases, a full rollback may be the best option.

----------------------------------------------------------

# About the features:

### Functions – GUI ###
 - Manual backup of inetsrv and inetpub
 - Manual backup of .NET folders
 - Abort button
 - HIIS_logs button
 - Script_Logs button
 - Run All with full backup + zip, and removal of .json files and folders
 - Button to run manual hardening (Run Selected)
 - Button to restart IIS services
 - Button to clear the log screen
 - Generates HIIS10 log for debugging
 - Generates execution log for each PowerShell script
 - Generates separate logs for the scripts
 - Creates backups folder
 - Creates script_logs folder
 - Creates logs folder
 - Small status viewer for deployment and rollback
 - Option for Full or Selected Deployment and Rollback

### Functions – CLI ###
 - Manual backup of inetsrv and inetpub
 - Manual backup of .NET folders
 - Abort command (q + enter)
 - Run All with full backup + zip, and removal of .json files and folders
 - Option to run manual hardening (Run Selected)
 - Command to restart IIS services
 - Command to clear the log screen
 - Generates HIIS10 log for debugging
 - Generates execution log for each PowerShell script
 - Generates separate logs for the scripts
 - Creates backups folder
 - Creates script_logs folder
 - Creates logs folder
 - Option for Full or Selected Deployment and Rollback

----------------------------------------------------------

# Pre req:
- IIS 10 installed
- PowerShell updated (recommended)
- Run as Administrator

  >> GUI tool was created to run in the Windows Server GUI.
  >> CLI tool was created to run in the Windows Server core.

# Steps to use this tool:

1 - Download all the files in your Windows Server.
2 - Don't change the folders location and don't change the folder name, the tool works 'as is'.
3 - Open the tool GUI or CLI as administrator.
4 - Run the tool and grab a coffee.
5 - Enjoy!

----------------------------------------------------------

# How to change the code and compile?

- Have sure you have the python installed in your machine and have sure you have virtual env configured in python.
- If you want to make changes and the code, feel free to do this. 

To compile the code just run this command:
  
# Compiling HardeningIIS10 in CLI version (Windows Server Core)
pyinstaller --onefile --console --clean --noupx --name CLI_HardeningIIS10 CLI_HardeningIIS10_v1.0.py

# Compiling HardeningIIS10 in GUI version (Windows Server GUI)
pyinstaller --onefile --console --clean --noupx --name GUI_HardeningIIS10 CLI_HardeningIIS10_v1.0.py


