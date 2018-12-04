# cms-ars3.1-microsoft-windows_2012r2-memberserver-stig-overlay
CMS ARS 3.1 Overlay InSpec Validation Profile for the Microsoft Windows 2012r2 Member Server DISA STIG Benchmark.

This InSpec Profile is based on the Microsoft Windows 2012r2 Member Server DISA STIG.

## Description

This [InSpec](https://github.com/chef/inspec) compliance profile validates the security settings in the Microsoft Windows 2012r2 Member Server DISA STIG in an automated way. The values of the security settings conform to CMS ARS 3.1.

InSpec is an open-source run-time framework and rule language used to specify compliance, security, and policy requirements for testing any node in your infrastructure.

## Requirements

- [InSpec](http://inspec.io/) at least version 2.x

## Get started

### Installing InSpec 

### Install InSpec on Unix/Linux/Mac

#### Option 1 Install InSpec (Package installer)
First things first: We need InSpec on our workstation. For production and standalone environments, I recommend the ChefDK package, since it gives you Chef + Test-Kitchen + InSpec. You can download the package from [https://downloads.chef.io/chefdk](https://downloads.chef.io/chefdk).

#### Option 2 Install InSpec (Terminal install)
Another option is to install InSpec via a command line script:

```
$ curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -channel stable -P chefdk
```

#### After Install
Once InSpec is installed, run `inspec version` to verify that the installation was successful.


### Install InSpec on Windows

#### Option 1 (package installer)
First things first: We need InSpec on our workstation. For production and standalone environments, I recommend the ChefDK package, since it gives you Chef + Test-Kitchen + InSpec. You can download the package from [https://downloads.chef.io/chefdk](https://downloads.chef.io/chefdk).

#### Option 2 (command line)
Another option is to install InSpec via a Powershell script:

```
$ . { iwr -useb https://omnitruck.chef.io/install.ps1 } | iex; install -channel stable -project chefdk
```

#### After Install
Once InSpec is installed, run `inspec version` to verify that the installation was successful.
  
### Get the Microsoft Windows 2012r2 Member Server Baseline

You will need to download the InSpec Profile to your `runner` system. You can do this via `git` or the GitHub Web interface, etc.

  a. `git clone https://github.com/mitre/microsoft-windows-2012r2-memberserver-stig-baseline`, or 
  
  b. Save a Zip or tar.gz copy of the master branch from the `Clone or Download` button of this project

### Setting up dependencies in your Ruby and InSpec Environments

The profile uses Bundler to manage needed dependencies - so you will need to installed the needed gems via bundler before you run the profile. Change directories to your your cloned inspec profile then do a `bundle install`. 

  a. `cd rsa-archer-security-configuration-guide-baseline` 
  
  b. `bundle install`

## Credentials

The profile uses RSA Archer REST API connection parameters as `attributes` specified below

- url: Base url of the RSA Archer application, (REQUIRED) <br>
`url: 'https://urltoarcherapp.org/'`

- instancename: Name of the RSA Archer instance (REQUIRED)<br>
`instancename: archerapp`

- user_domain: RSA Archer User Domain (OPTIONAL)<br>
`user_domain: ''`

- username: REST API User with at least `Read-Only` access to `Access Control` attributes on archer (REQUIRED)<br>
`username: restapiuser`

- password: Password of the users is pulled from the ENV <br> Export the password to `ARCHER_API_PASSWORD` (REQUIRED)<br>
`password: <%=ENV['ARCHER_API_PASSWORD']%>`

- ssl_verify: Set this to `false` if Archer App uses self-signed certs<br>
`ssl_verify: true`


## Usage

InSpec makes it easy to run your tests wherever you need. More options listed here: [InSpec cli](http://inspec.io/docs/reference/cli/)

```
# Clone Inspec Profile
$ git clone https://github.com/mitre/microsoft-windows-2012r2-memberserver-stig-baseline

# Install Gems
$ bundle install

# Update the attributes specified in `inspec.yml` as required

# Set required ENV variables
$ export ARCHER_API_PASSWORD=s3cr3tpassw0rd

# To run profile locally and directly from Github with cli & json output 
$ inspec exec /path/to/profile --reporter cli json:archer-results.json
```

### Run individual controls

In order to verify individual controls, just provide the control ids to InSpec:

```
$ inspec exec /path/to/profile --controls rsa-archer-1.1
```

## Contributors + Kudos

- Rony Xavier [rx294](https://github.com/rx294)
- Eugene Aronne [ejaronne](https://github.com/ejaronne)
- Aaron Lippold [aaronlippold](https://github.com/aaronlippold)

### Authors

- Author: Alicia Sturtevant

### License
This project is licensed under the terms of the Apache license 2.0 (apache-2.0)

### NOTICE
© 2018 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE
This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA 22102-7539, (703) 983-6000.

### NOTICE
DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx
