# encoding: utf-8

include_controls 'microsoft-windows-2012r2-memberserver-stig-baseline' do

  control 'V-1089' do
    desc 'check', 'If the following registry value does not exist or is not 
         configured as specified, this is a finding:
    
        Registry Hive: HKEY_LOCAL_MACHINE 
        Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

        Value Name: LegalNoticeText

        Value Type: REG_SZ
        Value: See message text below


        * This warning banner provides privacy and security notices consistent with 
        applicable federal laws, directives, and other federal guidance for accessing 
        this Government system, which includes (1) this computer network, (2) 
        all computers connected to this network, and (3) all devices and storage media 
        attached to this network or to a computer on this network.
        * This system is provided for Government authorized use only.
        * Unauthorized or improper use of this system is prohibited and may result in 
        disciplinary action and/or civil and criminal penalties.
        * Personal use of social media and networking sites on this system is limited 
        as to not interfere with official work duties and is subject to monitoring.
        * By using this system, you understand and consent to the following:

        - The Government may monitor, record, and audit your system usage, including 
        usage of personal devices and email systems for official duties or to conduct 
        HHS business. Therefore, you have no reasonable expectation of privacy regarding 
        any communication or data transiting or stored on this system. At any time, and 
        for any lawful Government purpose, the government may monitor, intercept, and 
        search and seize any communication or data transiting or stored on this system.
        - Any communication or data transiting or stored on this system may be 
        disclosed or used for any lawful Government purpose'
    desc 'fix', 'Configure the policy value for Computer Configuration >> 
         Windows Settings >> Security Settings >> Local Policies >> Security Options >> 
         "Interactive Logon: Message text for users attempting to log on" to the following:

         * This warning banner provides privacy and security notices consistent with 
         applicable federal laws, directives, and other federal guidance for accessing 
         this Government system, which includes (1) this computer network, (2) all 
         computers connected to this network, and (3) all devices and storage media 
         attached to this network or to a computer on this network.

         Configure the policy value for Computer Configuration >> 
         Windows Settings >> Security Settings >> Local Policies >> Security Options >> 
         "Interactive Logon: Message text for users attempting to log on" to the following:

         * This warning banner provides privacy and security notices consistent with 
         applicable federal laws, directives, and other federal guidance for accessing 
         this Government system, which includes (1) this computer network, (2) all 
         computers connected to this network, and (3) all devices and storage media 
         attached to this network or to a computer on this network.
         * This system is provided for Government authorized use only.
         * Unauthorized or improper use of this system is prohibited and may result in 
         disciplinary action and/or civil and criminal penalties.
         * Personal use of social media and networking sites on this system is limited 
         as to not interfere with official work duties and is subject to monitoring.
         * By using this system, you understand and consent to the following:
         - The Government may monitor, record, and audit your system usage, including
         usage of personal devices and email systems for official duties or to conduct 
         HHS business. Therefore, you have no reasonable expectation of privacy 
         regarding any communication or data transiting or stored on this system. 
         At any time, and for any lawful Government purpose, the government may monitor, 
         intercept, and search and seize any communication or data transiting or 
         stored on this system.
         - Any communication or data transiting or stored on this system may be 
         disclosed or used for any lawful Government purpose'
  end

  control 'V-1098' do
    title 'The reset period for the account lockout counter must be configured 
          to 120 minutes or greater on Windows 2012.'
    desc 'check', 'Verify the effective setting in Local Group Policy Editor.
         Run "gpedit.msc".

         Navigate to Local Computer Policy >> Computer Configuration >> 
         Windows Settings >> Security Settings >> Account Policies >> 
         Account Lockout Policy.

         If the "Reset account lockout counter after" value is less than "120" 
         minutes, this is a finding.'
    desc 'fix', 'Configure the policy value for Computer Configuration >> 
         Windows Settings >> Security Settings >> Account Policies >> 
         Account Lockout Policy >> "Reset account lockout counter after" to at 
         least "120" minutes.'

    describe security_policy do
      its('ResetLockoutCount') { should be >= 120 }
    end
  end
  
  control 'V-1099' do
    title "Windows 2012 account lockout duration must be configured to 0 
          minutes."
    desc 'check', 'Verify the effective setting in Local Group Policy Editor.
         Run "gpedit.msc".

         Navigate to Local Computer Policy >> Computer Configuration >> 
         Windows Settings >> Security Settings >> Account Policies >> 
         Account Lockout Policy.

         If the "Account lockout duration" is not "0", this is a finding.

         Configuring this to "0", requiring an administrator to unlock the account, 
         is not a finding.'
    desc 'fix', 'Configure the policy value for Computer Configuration >> Windows 
         Settings >> Security Settings >> Account Policies >> 
         Account Lockout Policy >> "Account lockout duration" to "0".

         A value of "0" requires an administrator to unlock the account.'
  
    describe security_policy do
      its('LockoutDuration') { should cmp == 0 }
    end
  end

  control 'V-1107' do
    title 'The password history must be configured to 12 passwords remembered.'
    desc 'A system is more vulnerable to unauthorized access when system users 
         recycle the same password several times without being required to 
         change to a unique password on a regularly scheduled basis. This 
         enables users to effectively negate the purpose of mandating periodic 
         password changes.  The default value is 12 for Windows domain systems.  
         CMS has decided this is the appropriate value for all Windows systems.'
    desc 'check', 'Verify the effective setting in Local Group Policy Editor.
         Run "gpedit.msc".

         Navigate to Local Computer Policy >> Computer Configuration >> Windows 
         Settings >> Security Settings >> Account Policies >> Password Policy.

         If the value for "Enforce password history" is less than "12" passwords 
         remembered, this is a finding.'
    desc 'fix', 'Configure the policy value for Computer Configuration >> 
         Windows Settings >> Security Settings >> Account Policies >> 
         Password Policy >> "Enforce password history" to "12" passwords remembered.'
    describe security_policy do
      its('PasswordHistorySize') { should be >= 12 }
    end
  end

  control 'V-1112' do
    desc 'check', 'Run "PowerShell".

         Member servers and standalone systems:
         Copy or enter the lines below to the PowerShell window and enter. (Entering twice 
         may be required. Do not include the quotes at the beginning and end of the query.)

         "([ADSI](\'WinNT://{0}\' -f $env:COMPUTERNAME)).Children | 
         Where { $_.SchemaClassName -eq \'user\' } | ForEach {
                 $user = ([ADSI]$_.Path)
                 $lastLogin = $user.Properties.LastLogin.Value
                 $enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
                 if ($lastLogin -eq $null) {
                   $lastLogin = \'Never\'
                 }
                 Write-Host $user.Name $lastLogin $enabled 
               }"

         This will return a list of local accounts with the account name, last logon, 
         and if the account is enabled (True/False).

         For example: User1 10/31/2015 5:49:56 AM True

         Domain Controllers:
         Enter the following command in PowerShell.
         
         "Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 30.00:00:00"

         This will return accounts that have not been logged on to for 30 days, along 
         with various attributes such as the Enabled status and LastLogonDate.

         Review the list of accounts returned by the above queries to determine the 
         finding validity for each account reported.

         Exclude the following accounts:
         
         Built-in administrator account (Renamed, SID ending in 500)
         Built-in guest account (Renamed, Disabled, SID ending in 501)
         Application accounts

         If any enabled accounts have not been logged on to within the past 30 days, 
         this is a finding.

         Inactive accounts that have been reviewed and deemed to be required must 
         be documented with the ISSO.'

    desc 'fix', 'Regularly review accounts to determine if they are still active. 
    Disable or delete any active accounts that have not been used in the last 30 days.'

    users = command("Get-CimInstance -Class Win32_Useraccount -Filter 'LocalAccount=True and Disabled=False' | FT Name | Findstr /V 'Name --'").stdout.strip.split(' ')

    get_sids = []
    get_names = []
    names = []
    inactive_accounts = []

    if !users.empty?
      users.each do |user|
        get_sids = command("wmic useraccount where \"Name='#{user}'\" get name',' sid| Findstr /v SID").stdout.strip
        get_last = get_sids[get_sids.length-3, 3]

        loc_space = get_sids.index(' ')
        names = get_sids[0, loc_space]
        if get_last != '500' && get_last != '501'
          get_names.push(names)
        end
      end
    end
  
    if !get_names.empty?
      get_names.each do |user|
        get_last_logon = command("Net User #{user} | Findstr /i 'Last Logon' | Findstr /v 'Password script hours'").stdout.strip
        last_logon = get_last_logon[29..33]
        if last_logon != 'Never'
          month = get_last_logon[28..29]
          day = get_last_logon[31..32]
          year = get_last_logon[34..37]

          if get_last_logon[32] == '/'
            month = get_last_logon[28..29]
            day = get_last_logon[31]
            year = get_last_logon[33..37]
          end
          date = day + '/' + month + '/' + year

          date_last_logged_on = DateTime.now.mjd - DateTime.parse(date).mjd
          if date_last_logged_on > 30
            inactive_accounts.push(user)
          end

          describe "#{user}'s last logon" do
            describe date_last_logged_on do
              it { should cmp <= 30 }
            end
          end if !inactive_accounts.empty?
        end

        if !inactive_accounts.empty?
          if last_logon == 'Never'
            date_last_logged_on = 'Never'
            describe "#{user}'s last logon" do
              describe date_last_logged_on do
                it { should_not == 'Never' }
              end
            end
          end
        end
      end
    end

    if inactive_accounts.empty?
      impact 0.0
      describe 'The system does not have any inactive accounts, control is NA' do
        skip 'The system does not have any inactive accounts, controls is NA'
      end
    end
  end

  control 'V-1151' do
    impact "none"
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the 
          related security control is not included in CMS ARS 3.1'
  end

  control 'V-1174' do
    desc 'check', 'If the following registry value does not exist or is not 
         configured as specified, this is a finding:

         Registry Hive:  HKEY_LOCAL_MACHINE
         Registry Path:  \SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\

         Value Name:  autodisconnect

         Value Type:  REG_DWORD
         Value:  0x0000001e (30) (or less)'
    desc 'fix', 'Configure the policy value for Computer Configuration >> 
         Windows Settings >> Security Settings >> Local Policies >> Security Options >> 
         "Microsoft Network Server: Amount of idle time required before suspending 
         session" to "30" minutes or less.'
  end
  
  control 'V-3373' do
    desc 'Computer account passwords are changed automatically on a regular basis.  
         This setting controls the maximum password age that a machine account 
         may have. This setting must be set to no more than 60 days, ensuring the 
         machine changes its password monthly.'
    desc 'check', 'If the following registry value does not exist or is not 
         configured as specified, this is a finding:

         Registry Hive: HKEY_LOCAL_MACHINE 
         Registry Path: \System\CurrentControlSet\Services\Netlogon\Parameters\

         Value Name: MaximumPasswordAge

         Value Type: REG_DWORD
         Value: 60 (or less, but not 0)'
    desc 'fix', 'Configure the policy value for Computer Configuration -> 
         Windows Settings -> Security Settings -> Local Policies -> 
         Security Options -> "Domain member: Maximum machine account password 
         age" to "60" or less (excluding "0" which is unacceptable).'

    describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
      it { should have_property 'MaximumPasswordAge' }
      its('MaximumPasswordAge') { should cmp <= 60 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
      it { should have_property 'MaximumPasswordAge' }
      its('MaximumPasswordAge') { should cmp > 0 }
    end
  end

  control 'V-3376' do
    impact "none"
     desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the 
           related security control is not included in CMS ARS 3.1'
  end
  
  control 'V-3453' do
    impact "none"
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the 
          related security control is not included in CMS ARS 3.1'
  end

  control 'V-3472' do
    title 'The time service must synchronize with an appropriate CMS-approved 
          time source.'
    desc 'check', 'Open "Windows PowerShell" or an elevated "Command Prompt" 
         (run as administrator).

         Enter "W32tm /query /configuration".

         Domain-joined systems are automatically configured with a "Type" of 
         "NT5DS" to synchronize with domain controllers and would not be a 
         finding.

         If systems are configured with a "Type" of "NTP", including standalone 
         systems and the forest root domain controller with the PDC Emulator 
         role, and do not have a CMS-approved time server defined for 
         "NTPServer", this is a finding.

         If an alternate time synchronization tool is used and is not enabled 
         or not configured to synchronize with a CMS-approved time source, 
         this is a finding.

         CMS-approved time servers include:
         - NIST Internet Time Servers (http://tf.nist.gov/tf-cgi/servers.cgi)
         - U.S. Naval Observatory Stratum-1 NTP Servers (http://tycho.usno.navy.mil/ntp.html); and
         - CMS designated internal NTP time servers providing an NTP Stratum-2 
           service to the above servers

         Time synchronization will occur through a hierarchy of time servers down 
         to the local level. Clients and lower-level servers will synchronize with 
         an authorized time server in the hierarchy.'
    desc 'fix', 'If the system needs to be configured to an NTP server, configure 
         the system to point to an authorized time server by setting the policy 
         value for Computer Configuration >> Administrative Templates >> System 
         >> Windows Time Service >> Time Providers >> "Configure Windows NTP 
         Client" to "Enabled", and configure the "NtpServer" field to point to 
         an authorized time server.   

         CMS-approved time servers include:
         - NIST Internet Time Servers (http://tf.nist.gov/tf-cgi/servers.cgi)
         - U.S. Naval Observatory Stratum-1 NTP Servers (http://tycho.usno.navy.mil/ntp.html); and
         - CMS designated internal NTP time servers providing an NTP Stratum-2 
           service to the above servers

           Time synchronization will occur through a hierarchy of time servers 
           down to the local level. 
           Clients and lower-level servers will synchronize with an authorized 
           time server in the hierarchy.'
  end

  control 'V-3480' do
    impact "none"
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the 
          related security control is not included in CMS ARS 3.1'
  end
  
  control 'V-3481' do
    impact "none"
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the 
          related security control is not included in CMS ARS 3.1'
  end
  
  control 'V-4108' do
    desc 'check', 'If the system is configured to write to an audit server, 
         or is configured to automatically archive full logs, this is NA.

         If the following registry value does not exist or is not configured 
         as specified, this is a finding:

         Registry Hive: HKEY_LOCAL_MACHINE 
         Registry Path: \System\CurrentControlSet\Services\Eventlog\Security\

         Value Name: WarningLevel

         Value Type: REG_DWORD
         Value: 80 (or less)'
    desc 'fix', 'Configure the policy value for Computer Configuration -> 
                Windows Settings -> Security Settings -> Local Policies -> 
                Security Options -> "MSS: (WarningLevel) Percentage threshold 
                for the security event log at which the system will generate 
                a warning" to "80" or less.

                (See "Updating the Windows Security Options File" in the STIG 
                Overview document if MSS settings are not visible in the 
                system\'s policy tools.)'
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security') do
      it { should have_property 'WarningLevel' }
      its('WarningLevel') { should cmp <= 80 }
    end
  end

  control 'V-4442' do
    desc 'check', 'If the following registry value does not exist or is not 
         configured as specified, this is a finding:

         Registry Hive: HKEY_LOCAL_MACHINE 
         Registry Path: \Software\Microsoft\Windows NT\CurrentVersion\Winlogon\

         Value Name: ScreenSaverGracePeriod

         Value Type: REG_SZ
         Value: 0'
    desc 'fix', 'Configure the policy value for Computer Configuration -> Windows 
         Settings -> Security Settings -> Local Policies -> Security Options -> 
         "MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver 
         grace period expires must be "0".

         (See "Updating the Windows Security Options File" in the STIG Overview 
         document if MSS settings are not visible in the system\'s policy tools.)'
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
      it { should have_property 'ScreenSaverGracePeriod' }
      its('ScreenSaverGracePeriod') { should eq 0 }
    end
  end
  
  control 'V-6836' do
    title 'Passwords must, at a minimum, be 15 characters.'
    desc 'check', 'Verify the effective setting in Local Group Policy Editor.
         Run "gpedit.msc".

         Navigate to Local Computer Policy -> Computer Configuration -> 
         Windows Settings -> Security Settings -> Account Policies -> 
         Password Policy.

         If the value for the "Minimum password length," is less than "15" 
         characters, this is a finding.'
    desc 'fix', 'Configure the policy value for Computer Configuration -> 
         Windows Settings -> Security Settings -> Account Policies -> 
         Password Policy -> "Minimum password length" to "15" characters.'
    describe security_policy do
      its('MinimumPasswordLength') { should be >= 15 }
    end
  end

  control 'V-14225' do
    title 'Windows 2012/2012 R2 password for the built-in Administrator 
          account must be changed at least every 60 days and 
          when a member of the administrative team leaves the organization.'
    desc 'The longer a password is in use, the greater the opportunity for 
         someone to gain unauthorized knowledge of the password. The 
         password for the built-in Administrator account must be changed at 
         least every 60 days and when any member of the 
         administrative team leaves the organization.

         Organizations that use an automated tool, such Microsoft\'s Local 
         Administrator Password Solution (LAPS), on domain-joined systems 
         can configure this to occur more frequently. LAPS will change the 
         password every "30" days by default.'
    desc 'check', 'Review the password last set date for the built-in 
         Administrator account.

         Domain controllers:
         
         Open "Windows PowerShell".

         Enter "Get-ADUser -Filter * -Properties SID, PasswordLastSet | 
         Where SID -Like "*-500" | FL Name, SID, PasswordLastSet".

         If the "PasswordLastSet" date is greater than 60 days 
         old, this is a finding.

         Member servers and standalone systems:

         Open "Windows PowerShell" or "Command Prompt".

         Enter \'Net User [account name] | Find /i "Password Last Set"\', 
         where [account name] is the name of the built-in administrator account.

         (The name of the built-in Administrator account must be changed to 
         something other than "Administrator" per STIG requirements.)

         If the "PasswordLastSet" date is greater than 60 days 
         old, this is a finding.'
    desc 'fix', 'Change the built-in Administrator account password at least 
         every 60 days and whenever an administrator leaves the 
         organization. More frequent changes are recommended.

         Automated tools, such as Microsoft\'s LAPS, may be used on domain-
         joined member servers to accomplish this.'
  end

  control 'V-14228' do
    impact "none"
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the                                                             
           related security control is not included in CMS ARS 3.1'
  end

  control 'V-14229' do
    impact "none"
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the                                                             
          related security control is not included in CMS ARS 3.1'
  end

  control 'V-14234' do
    impact "none"
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the                                                             
          related security control is not included in CMS ARS 3.1'
  end

  control 'V-14236' do
    impact "none"
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the                                                             
          related security control is not included in CMS ARS 3.1'
  end

  control 'V-14240' do
    impact "none"
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the                                                             
          related security control is not included in CMS ARS 3.1'
  end

  control 'V-14247' do
    impact "none"
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the                                                             
          related security control is not included in CMS ARS 3.1'
  end

  control 'V-14253' do
    impact "none"
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the                                                             
          related security control is not included in CMS ARS 3.1'
  end

  control 'V-14261' do
    impact "none"
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the                                                             
          related security control is not included in CMS ARS 3.1'
  end

  control 'V-15685' do
    impact "none"
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the                                                             
          related security control is not included in CMS ARS 3.1'
  end

  control 'V-15686' do
    impact "none"
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the                                                             
          related security control is not included in CMS ARS 3.1'
  end

  control 'V-15703' do
    impact "none"
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the                                                             
          related security control is not included in CMS ARS 3.1'
  end

  control 'V-15705' do
    impact "none"
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the                                                             
          related security control is not included in CMS ARS 3.1'
  end

  control 'V-15706' do
    impact "none"
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the                                                             
          related security control is not included in CMS ARS 3.1'
  end

  control 'V-21963' do
    impact "none"
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the                                                             
          related security control is not included in CMS ARS 3.1'
  end

  control 'V-21965' do
    impact "none"
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the                                                             
          related security control is not included in CMS ARS 3.1'
  end

  control 'V-26359' do
    impact "none"
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the                                                             
          related security control is not included in CMS ARS 3.1'
  end

  control 'V-32272' do
    title 'The CMS Root CA certificates must be installed in the Trusted Root Store.'
    desc 'To ensure secure CMS websites and CMS-signed code are properly validated, 
         the system must trust the CMS Root Certificate Authorities (CAs). The CMS 
         root certificates will ensure that the trust chain is established for server 
         certificates issued from the CMS CAs.'
    desc 'check', 'Verify the DoD Root CA certificates are installed as Trusted Root 
         Certification Authorities.'
    desc 'fix', 'Install the CMS Root CA certificates.'
    describe "For this CMS ARS 3.1 overlay, this control must be reviewed manually" do 
      skip "For this CMS ARS 3.1 overlay, this control must be reviewed manually"
    end
  end

  control 'V-32272' do
    title 'The CMS Interoperability Root CA cross-certificates must be installed into 
          the Untrusted Certificates Store on unclassified systems.'
    desc 'To ensure users do not experience denial of service when performing 
         certificate-based authentication to CMS websites due to the system chaining 
         to a root other than CMS Root CAs, the CMS Interoperability Root CA cross-
         certificates must be installed in the Untrusted Certificate Store. This 
         requirement only applies to unclassified systems.'
    desc 'check', 'Verify the CMS Interoperability cross-certificates are installed on unclassified 
         systems as Untrusted Certificates.'
    desc 'fix', 'Install the CMS Interoperability Root CA cross-certificates on 
         unclassified systems.'
    describe "For this CMS ARS 3.1 overlay, this control must be reviewed manually" do 
      skip "For this CMS ARS 3.1 overlay, this control must be reviewed manually"
    end
  end

  control 'V-34974' do
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related 
          security control is not included in CMS ARS 3.1'
  end

  control 'V-36662' do
    title 'Windows 2012/2012 R2 manually managed application account passwords must 
          be changed at least every 60 days and when a system administrator 
          with knowledge of the password leaves the organization.'
    desc 'check', 'Determine if manually managed application/service accounts exist. 
         If none exist, this is NA.

         If passwords for manually managed application/service accounts are not 
         changed at least every 60 days and when an administrator with 
         knowledge of the password leaves the organization, this is a finding.

         Identify manually managed application/service accounts.
         
         To determine the date a password was last changed:

         Domain controllers:

         Open "Windows PowerShell".

         Enter "Get-ADUser -Identity [application account name] -Properties PasswordLastSet | 
         FL Name, PasswordLastSet", where [application account name] is the name of the 
         manually managed application/service account.

         If the "PasswordLastSet" date is more than 60 days old, this is a 
         finding.

         Member servers and standalone systems:

         Open "Windows PowerShell" or "Command Prompt".

         Enter \'Net User [application account name] | Find /i "Password Last Set"\', where 
         [application account name] is the name of the manually managed application/service 
         account.

         If the "Password Last Set" date is more than 60 days old, this is 
         a finding.'
    desc 'fix', 'Change passwords for manually managed application/service accounts at 
         least every 60 days and when an administrator with knowledge of the 
         password leaves the organization.

         It is recommended that system-managed service accounts be used where possible.'

    users = command("net user | Findstr /V 'command -- accounts'").stdout.strip.split(' ')
    
    users.each do |user|
      
      get_password_last_set = command("Net User #{user}  | Findstr /i 'Password Last Set' | 
      Findstr /v 'expires changeable required may logon'").stdout.strip
      
      month = get_password_last_set[27..29]
      day = get_password_last_set[31..32]
      year = get_password_last_set[34..38]
      
      date = day + '/' + month + '/' + year
      
      date_password_last_set = DateTime.now.mjd - DateTime.parse(date).mjd
      describe "#{user}'s data password last set" do
        describe date_password_last_set do
          it { should cmp <= 60 }
        end
      end
    end
    if users.empty?
      impact 0.0
      describe 'There are no system users' do
        skip 'This control is not applicable'
      end
    end
  end

  control 'V-36672' do
    impact "none"
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the 
          related security control is not included in CMS ARS 3.1'
  end

  control 'V-36677' do
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the 
          related security control is not included in CMS ARS 3.1'
  end

  control 'V-36677' do
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the                                                             
           related security control is not included in CMS ARS 3.1'
  end

  control 'V-36698' do
    desc 'Allowing biometrics may bypass required authentication methods.  
          Biometrics may only be used as an additional authentication factor 
          where an enhanced strength of identity credential is necessary or 
          desirable.  Additional factors must be met per CMS policy.'
  end

  control 'V-36713' do
    tag "cci": ['CCI-000068', 'CCI-002890']
    tag "nist": ['AC-17(2)', 'MA-4 (6)', 'Rev_4']
  end

  control 'V-36719' do
    tag "cci": ['CCI-000068', 'CCI-002890']
    tag "nist": ['AC-17(2)', 'MA-4 (6)', 'Rev_4']
  end

  control 'V-36720' do
    impact "none"
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since 
          the related security control is not included in CMS ARS 3.1'
  end

  control 'V-36733' do
    desc 'check', 'Determine whether user-level information is backed up 
         in accordance with local recovery time and recovery point objectives.  
         If user-level information is not backed up in accordance with local 
         recovery time and recovery point objectives, this is a finding.

         Std.1 - Perform full backups weekly to separate media. Perform 
         incremental or differential backups daily to separate media.  Backups 
         to include user-level and system-level information (including system 
         state information).  Three (3) generations of backups (full plus all 
         related incremental or differential backups) are stored off-site.  
         Off-site and on-site backups must be logged with name, date, time, 
         and action.Std.2 - Backups must be compliant with CMS requirements 
         for protecting data at rest. (see SC-28)'
  end

  control 'V-36734' do
    title 'The operating system must employ automated mechanisms to determine 
          the state of system components with regard to flaw remediation no less 
          often than once every seventy-two (72) hours.'
    desc 'Without the use of automated mechanisms to scan for security flaws on 
         a continuous and/or periodic basis, the operating system or other system 
         components may remain vulnerable to the exploits presented by undetected 
         software flaws.'
    desc 'check', 'Verify the operating system employs automated mechanisms to 
         determine the state of system components with regard to flaw remediation 
         no less often than once every seventy-two (72) hours. If it does not, 
         this is a finding.'
    desc 'fix', 'Configure the operating system to employ automated mechanisms to 
         determine the state of system components with regard to flaw remediation 
         no less often than once every seventy-two (72) hours. '
  end

  control 'V-40173' do
    desc 'check', 'Determine whether system-related documentation is backed up in 
         accordance with local recovery time and recovery point objectives.  If 
         system-related documentation is not backed up in accordance with local 
         recovery time and recovery point objectives, this is a finding.

         Std.1 - Perform full backups weekly to separate media. Perform incremental 
         or differential backups daily to separate media.  Backups to include user-
         level and system-level information (including system state information).  
         Three (3) generations of backups (full plus all related incremental or 
         differential backups) are stored off-site.  Off-site and on-site backups 
         must be logged with name, date, time, and action.Std.2 - Backups must be 
         compliant with CMS requirements for protecting data at rest. (see SC-28)'
  end

  control 'V-40179' do
    impact 'none'
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related 
          security control is not included in CMS ARS 3.1'
  end

  control 'V-40237' do
    impact 'none'
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related 
          security control is not included in CMS ARS 3.1'
  end

  control 'V-57653' do
    title 'Windows 2012 / 2012 R2 must automatically remove or disable temporary 
          user accounts after 30 days.'
    desc 'If temporary user accounts remain active when no longer needed or for an 
         excessive period, these accounts may be used to gain unauthorized access. 
         To mitigate this risk, automated termination of all temporary accounts 
         must be set upon account creation.

         Temporary accounts are established as part of normal account activation 
         procedures when there is a need for short-term accounts without the demand 
         for immediacy in account activation.

         If temporary accounts are used, the operating system must be configured to 
         automatically terminate these types of accounts after a CMS-defined time 
         period of 30 days.

         To address access requirements, many operating systems may be integrated 
         with enterprise-level authentication/access mechanisms that meet or exceed 
         access control policy requirements.'
    desc 'check', 'Determine if temporary user accounts are used and identify any 
         that exist.
 
         If none exist, this is NA.

         Review temporary user accounts for expiration dates.

         Open "PowerShell".

         Domain Controllers:

         Enter "Search-ADAccount -AccountExpiring -TimeSpan 30:00:00:00 | FT Name, 
         AccountExpirationDate"

         This will return any accounts configured to expire within the next 30 days.

         If any accounts identified as temporary are not listed, this is a finding.

         For any temporary accounts returned by the previous query:
         Enter "Get-ADUser -Identity [Name] -Property WhenCreated" to determine when 
         the account was created.

         If the "WhenCreated" date and "AccountExpirationDate" from the previous 
         query are greater than 30 days apart, this is a finding.

         Member servers and standalone systems:

         Enter "Net User [username]", where [username] is the name of the temporary 
         user account.

         If "Account expires" has not been defined within 30 days for any temporary 
         user account, this is a finding.

         If the "Password last set" date and "Account expires" date are greater than 
         30 days apart, this is a finding. (Net User does not provide an account 
         creation date.)'
    desc 'fix', 'Configure temporary user accounts to automatically expire within 
         30 days.

         Domain account can be configured with an account expiration date, under 
         "Account" properties.

         Local accounts can be configured to expire with the command "Net user 
         [username] /expires:[mm/dd/yyyy]", where username is the name of the 
         temporary user account.

         Delete any temporary user accounts that are no longer necessary.'

    if !attribute('temp_account').empty?
      attribute('temp_account').each do |user|

        
        get_account_expires = command("Net User #{user} | Findstr /i 'expires' | 
                                       Findstr /v 'password'").stdout.strip
        
        month_account_expires = get_account_expires[28..30]
        day_account_expires = get_account_expires[32..33]
        year_account_expires = get_account_expires[35..39]
        
        if get_account_expires[30] == '/'
          month_account_expires = get_account_expires[28..29]
          if get_account_expires[32] == '/'
            day_account_expires = get_account_expires[31]
          end
          if get_account_expires[32] != '/'
            day_account_expires = get_account_expires[31..32]
          end
          if get_account_expires[33] == '/'
            year_account_expires = get_account_expires[34..37]
          end
          if get_account_expires[33] != '/'
            year_account_expires = get_account_expires[33..37]
          end
          
        end
        
        date_expires = day_account_expires + '/' +
                       month_account_expires + '/' + year_account_expires
        
        get_password_last_set = command("Net User #{user}  | 
                                         Findstr /i 'Password Last Set' | 
                                         Findstr /v 'expires changeable required may logon'").stdout.strip
        
        month = get_password_last_set[27..29]
        day = get_password_last_set[31..32]
        year = get_password_last_set[34..38]
        
        if get_password_last_set[32] == '/'
          month = get_password_last_set[27..29]
          day = get_password_last_set[31]
          year = get_password_last_set[33..37]
        end
        date = day + '/' + month + '/' + year
        
        date_expires_minus_password_last_set = DateTime.parse(date_expires).mjd -
                                               DateTime.parse(date).mjd
        
        account_expires = get_account_expires[27..33]
        
        if account_expires == 'Never'
          describe "#{user}'s account expires" do
            describe account_expires do
              it { should_not == 'Never' }
            end
          end
        end
        next unless account_expires != 'Never'
        describe "#{user}'s account expires" do
          describe date_expires_minus_password_last_set do
            it { should cmp <= 30 }
          end
        end
      end
      
    else
      impact 0.0
      describe 'No temporary accounts on this system, control not applicable' do
        skip 'No temporary accounts on this system, control not applicable'
      end
    end
  end

  control 'V-57655' do
    title 'Windows 2012 / 2012 R2 must automatically remove or disable emergency 
          accounts after the crisis is resolved or within 24 hours.'
    desc 'check', 'Determine if emergency administrator accounts are used and 
         identify any that exist. If none exist, this is NA.

         If emergency administrator accounts cannot be configured with an expiration 
         date due to an ongoing crisis, the accounts must be disabled or removed when 
         the crisis is resolved.

         If emergency administrator accounts have not been configured with an 
         expiration date or have not been disabled or removed following the resolution 
         of a crisis, this is a finding.

         Domain Controllers:

         Enter "Search-ADAccount -AccountExpiring -TimeSpan 1:00:00:00 | FT Name, 
         AccountExpirationDate"

         This will return any accounts configured to expire within the next day.  
         (The "TimeSpan" value to can be changed to find accounts configured to expire 
         at various times such as 30 for the next month.)

         If any accounts identified as emergency administrator accounts are not listed, 
         this is a finding.

         For any emergency administrator accounts returned by the previous query:
         Enter "Get-ADUser -Identity [Name] -Property WhenCreated" to determine when    
         the account was created.

         If the "WhenCreated" date and "AccountExpirationDate" from the previous query 
         are greater than 1 day apart, this is a finding.

         Member servers and standalone systems:

         Enter "Net User [username]", where [username] is the name of the emergency 
         administrator accounts.

         If "Account expires" has not been defined within 24 hours for any emergency 
         administrator accounts, this is a finding.

         If the "Password last set" date and "Account expires" date are greater than 
         24 hours apart, this is a finding. (Net User does not provide an account 
         creation date.)'

    desc 'fix', 'Remove emergency administrator accounts after a crisis has been 
         resolved or configure the accounts to automatically expire within 24 hours.

         Domain accounts can be configured with an account expiration date, under 
         "Account" properties.

         Local accounts can be configured to expire with the command "Net user 
         [username] /expires:[mm/dd/yyyy]", where username is the name of the 
         emergency administrator account.'
    
    
    if !attribute('emergency_account').empty?

      attribute('emergency_account').each do |user|
        
      get_account_expires = command("Net User #{user} | Findstr /i 'expires' | Findstr /v 'password'").stdout.strip
      
      month_account_expires = get_account_expires[28..30]
      day_account_expires = get_account_expires[32..33]
      year_account_expires = get_account_expires[35..39]
      
      if get_account_expires[30] == '/'
        month_account_expires = get_account_expires[28..29]
        if get_account_expires[32] == '/'
          day_account_expires = get_account_expires[31]
        end
        if get_account_expires[32] != '/'
          day_account_expires = get_account_expires[31..32]
        end
        if get_account_expires[33] == '/'
          year_account_expires = get_account_expires[34..37]
        end
        if get_account_expires[33] != '/'
          year_account_expires = get_account_expires[33..37]
        end
      end
      
      date_expires = day_account_expires + '/' + month_account_expires + '/' + year_account_expires
      
      get_password_last_set = command("Net User #{user}  | Findstr /i 'Password Last Set' | Findstr /v 'expires changeable required may logon'").stdout.strip
      
      month = get_password_last_set[27..29]
      day = get_password_last_set[31..32]
      year = get_password_last_set[34..38]
      
      if get_password_last_set[32] == '/'
        month = get_password_last_set[27..29]
        day = get_password_last_set[31]
        year = get_password_last_set[33..37]
      end
      date = day + '/' + month + '/' + year
      
      date_expires_minus_password_last_set = DateTime.parse(date_expires).mjd - DateTime.parse(date).mjd
      
      account_expires = get_account_expires[27..33]
      
      if account_expires == 'Never'
        describe "#{user}'s account expires" do
          describe account_expires do
            it { should_not == 'Never' }
          end
        end
      end
      next unless account_expires != 'Never'
      describe "#{user}'s account expires" do
        describe date_expires_minus_password_last_set do
          it { should cmp <= 1 }
        end
      end
      end
      
    else
      impact 0.0
      describe 'No emergency accounts exist' do
        skip 'check not applicable'
      end
    end
  end

  control 'V-57719' do
    impact 'none'
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related 
          security control is not included in CMS ARS 3.1'
  end
end
