# Cisco FMC
## FRIT - Firewall Rules Inducer Tool

Code to create Firewall Rules in Cisco FMC by parsing spreadsheet

There are two modes:
- Single rule implementing one by one, use fmc_sequential.py
- Bulk rules implementation of limit 1000 at once, use fmc.py

## To Prepare Environment
Run:
- `pip3 install -r requirements.txt`

## To Prepare Windows Executable
Run:
- `pip3 install py2exe`
- `python3 setup.py py2exe`
- `fmc.exe` file will be present inside `dist` folder
- Rename `dist` folder to `windows_release`
- Create zip file to ship `windows_release.zip`

## How to Execute
`fmc.exe --config_file <fmc_config.yml>`

## For Help
`fmc.exe --help`
