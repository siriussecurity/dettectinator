# Dettectinator
Dettectinator - The Python library to your DeTT&amp;CT YAML files.

[DeTT&CT](https://github.com/rabobank-cdc/DeTTECT) is a framework that helps blue teams in using MITRE ATT&CK to score and compare data log source quality, visibility coverage, detection coverage and threat actor behaviours. All administration is done in YAML files which can be editted via the [DeTT&CT Editor](https://rabobank-cdc.github.io/dettect-editor). But what if you want to automate the generation and modification of these YAML files? That's were Dettectinator comes in!

Dettectinator is built to be included in your SOC automation tooling. It can be included as a Python library (`pip install dettectinator`) or it can be used via the command line (`python dettectinator.py -h`).

Dettectinator also provides plugins to read detections and data sources from your SIEM or EDR and create a DeTT&CT YAML for it, so that you can use it to visualize your ATT&CK data source and detection coverage in the ATT&CK  Navigator.

Currently for detections, we have plugins for the following tools:
- Microsoft Sentinel: Analytics Rules (API)
- Microsoft Defender: Alerts (API)
- Microsoft Defender: Custom Detection Rules (API, _under construction_)
- Microsoft Defender for Identity: Detection Rules (loaded from MS Github)
- Tanium: Signals (API)
- Elastic Security: Rules (API)
- Suricata: rules (file)
- Suricata: rules summarized (file)
- Sigma: rules (folder with YAML files)
- Splunk: saved searches config (file)
- CSV: any csv with detections and ATT&CK technique ID's (file)
- Excel: any Excel file with detections and ATT&CK technique ID's (file)

For data sources, you can use the following plugins:
- Defender for Endpoints: tables available in Advanced Hunting (based on OSSEM)
- Windows Sysmon: event logging based on Sysmon (based on OSSEM and your Sysmon config file)
- Sentinel Window Security Auditing: event logging (based on OSSEM and EventID's found in your logging)
- CSV: any csv with ATT&CK data sources and products (file)
- Excel: any Excel file with ATT&CK data sources and products (file)

In the latest version we have also added support for importing attack groups data. The way that you import that data will depend on how you get your CTI data delivered. We added 2 sample plugins that you can use to create your own tailored plugins:
- Excel: import techniques for groups from Excel. In this Excel (which can be found in the examples) each group has its own tab that lists the techniques.
- PDF: import techniques and software based on regular expressions from a PDF file.

It's easy to create your own Dettectinator plugins or edit the ones we've provided to cover additional scenario's.

More information on how to use Dettectinator and how to use and create plugins can be found in the [wiki](https://github.com/siriussecurity/dettectinator/wiki).