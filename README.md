# cms-ars-3.1-high-microsoft-windows-2012r2-member-server-stig-overlay

InSpec profile overlay to validate the secure configuration of Microsoft Windows 2012R2 Member Server against [DISA's](https://iase.disa.mil/stigs/Pages/index.aspx) Microsoft Windows 2012R2 Member Server STIG Version 2 Release 14 tailored for [CMS ARS 3.1](https://www.cms.gov/Research-Statistics-Data-and-Systems/CMS-Information-Technology/InformationSecurity/Info-Security-Library-Items/ARS-31-Publication.html).

## Getting Started  
It is intended and recommended that InSpec and this profile overlay be run from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely over __winrm__.

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

## Running This Overlay
When the __"runner"__ host uses this profile overlay for the first time, follow these instructions: 

```
mkdir profiles
cd profiles
git clone https://github.cms.gov/ispg-dev/cms-ars-3.1-high-microsoft-windows-2012r2-member-server-stig-overlay.git
git clone https://github.com/mitre/microsoft-windows-2012r2-memberserver-stig-baseline.git
cd cms-ars-3.1-high-microsoft-windows-2012r2-member-server-stig-overlay
bundle install
inspec exec ../cms-ars-3.1-high-microsoft-windows-2012r2-member-server-stig-overlay -t winrm://$winhostip --user 'Administrator' --password=Pa55w0rd --reporter cli json:windows-memberserver-overlay-results.json
```

For every successive run, follow these instructions to always have the latest version:

```
cd profiles/cms-ars-3.1-high-microsoft-windows-2012r2-member-server-stig-overlay
git pull
cd ../microsoft-windows-2012r2-memberserver-stig-baseline
git pull
cd ../cms-ars-3.1-high-microsoft-windows-2012r2-member-server-stig-overlay
bundle install
inspec exec ../cms-ars-3.1-high-microsoft-windows-2012r2-member-server-stig-overlay -t winrm://$winhostip --user 'Administrator' --password=Pa55w0rd --reporter cli json:windows-memberserver-overlay-results.json
```

## Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://mitre.github.io/heimdall-lite/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __full heimdall server__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* Eugene Aronne
* Danny Haynes

## Special Thanks
* Alicia Sturtevant

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.cms.gov/ispg-dev/cms-ars-3.1-high-microsoft-windows-2012r2-member-server-stig-overlay/issues/new).

## License
This is licensed under the [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) license. 

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.

### NOTICE
DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx
