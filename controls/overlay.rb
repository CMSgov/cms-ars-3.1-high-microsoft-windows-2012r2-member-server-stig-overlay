# encoding: utf-8

include_controls 'archer-baseline' do

  control 'V-1089' do
    desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:
    
Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: LegalNoticeText

Value Type: REG_SZ
Value: See message text below

* This warning banner provides privacy and security notices consistent with applicable federal laws, directives, and other federal guidance for accessing this Government system, which includes (1) this computer network, (2) all computers connected to this network, and (3) all devices and storage media attached to this network or to a computer on this network.
* This system is provided for Government authorized use only.
* Unauthorized or improper use of this system is prohibited and may result in disciplinary action and/or civil and criminal penalties.
* Personal use of social media and networking sites on this system is limited as to not interfere with official work duties and is subject to monitoring.
* By using this system, you understand and consent to the following:

- The Government may monitor, record, and audit your system usage, including usage of personal devices and email systems for official duties or to conduct HHS business. Therefore, you have no reasonable expectation of privacy regarding any communication or data transiting or stored on this system. At any time, and for any lawful Government purpose, the government may monitor, intercept, and search and seize any communication or data transiting or stored on this system.
- Any communication or data transiting or stored on this system may be disclosed or used for any lawful Government purpose'
    desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Interactive Logon: Message text for users attempting to log on" to the following:

* This warning banner provides privacy and security notices consistent with applicable federal laws, directives, and other federal guidance for accessing this Government system, which includes (1) this computer network, (2) all computers connected to this network, and (3) all devices and storage media attached to this network or to a computer on this network.
* This system is provided for Government authorized use only.
* Unauthorized or improper use of this system is prohibited and may result in disciplinary action and/or civil and criminal penalties.
* Personal use of social media and networking sites on this system is limited as to not interfere with official work duties and is subject to monitoring.
* By using this system, you understand and consent to the following:

- The Government may monitor, record, and audit your system usage, including usage of personal devices and email systems for official duties or to conduct HHS business. Therefore, you have no reasonable expectation of privacy regarding any communication or data transiting or stored on this system. At any time, and for any lawful Government purpose, the government may monitor, intercept, and search and seize any communication or data transiting or stored on this system.
- Any communication or data transiting or stored on this system may be disclosed or used for any lawful Government purpose'

    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
      it { should have_property 'LegalNoticeText' }
      its('LegalNoticeText') {
        should eq ["You are accessing a U.S. Government (USG) Information System (IS) that is
    provided for USG-authorized use only.
               
    By using this IS (which includes any device attached to this IS), you consent
    to the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for
    purposes including, but not limited to, penetration testing, COMSEC monitoring,
    network operations and defense, personnel misconduct (PM), law enforcement
    (LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are subject
    to routine monitoring, interception, and search, and may be disclosed or used
    for any USG-authorized purpose.

    -This IS includes security measures (e.g., authentication and access controls)
    to protect USG interests--not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to PM, LE
    or CI investigative searching or monitoring of the content of privileged
    communications, or work product, related to personal representation or services
    by attorneys, psychotherapists, or clergy, and their assistants.  Such
    communications and work product are private and confidential.  See User
    Agreement for details."]
    }
  end
    
    describe 'The required legal notice' do
      subject { registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').LegalNoticeText }
      it {
        should eq ["You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

    By using this IS (which includes any device attached to this IS), you consent
    to the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for
    purposes including, but not limited to, penetration testing, COMSEC monitoring,
    network operations and defense, personnel misconduct (PM), law enforcement
    (LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are subject
    to routine monitoring, interception, and search, and may be disclosed or used
    for any USG-authorized purpose.
 -This IS includes security measures (e.g., authentication and access controls)
    to protect USG interests--not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to PM, LE
    or CI investigative searching or monitoring of the content of privileged
    communications, or work product, related to personal representation or services
    by attorneys, psychotherapists, or clergy, and their assistants.  Such
    communications and work product are private and confidential.  See User
    Agreement for details."]
    }
    end
  end

  control 'V-1099' do
    title "Windows 2012 account lockout duration must be configured to 0 minutes."
    desc 'check', 'Verify the effective setting in Local Group Policy Editor.                                 
         Run \"gpedit.msc\".                                                                                 

         Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings                   
         >> Security Settings >> Account Policies >> Account Lockout Policy.                               
         
         If the \"Account lockout duration\" is not \"0\" this is a finding. 
                                                                                                              
         Configuring this to \"0\", requiring an administrator to unlock the account, is                   
         more restrictive and is not a finding.'
    
    desc 'fix', 'Configure the policy value for Computer Configuration >> Windows                            
         Settings >> Security Settings >> Account Policies >> Account Lockout Policy >>                       
         \"Account lockout duration\" to \"0\" minutes. This requires an administrator
         to unlock the account.'
  
    describe security_policy do
      its('LockoutDuration') { should cmp == 0 }
    end
  end

  control 'V-1107' do
    title 'The password history must be configured to 12 passwords remembered.'
    desc 'A system is more vulnerable to unauthorized access when system users recycle 
         the same password several times without being required to change to a unique 
         password on a regularly scheduled basis. This enables users to effectively 
         negate the purpose of mandating periodic password changes.  The default value 
         is 12 for Windows domain systems.  CMS has decided this is the appropriate 
         value for all Windows systems.'
    desc 'check', 'Verify the effective setting in Local Group Policy Editor.
         
         Run "gpedit.msc".

         Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> 
         Security Settings >> Account Policies >> Password Policy.

         If the value for "Enforce password history" is less than "12" passwords remembered, 
         this is a finding.'
    desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> 
         Security Settings >> Account Policies >> Password Policy >> "Enforce password history" 
         to "12" passwords remembered.'
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

    users = command("net user | Findstr /V 'command -- accounts'").stdout.strip.split(' ')

    get_sids = []
    get_names = []
    names = []
    inactive_accounts = []
    
    users.each do |user|
      get_sids = command("wmic useraccount where \"Name='#{user}'\" get name',' sid',' Disabled | 
      Findstr /v SID").stdout.strip
      get_last = get_sids[get_sids.length-3, 3]
      get_disabled = get_sids[0, 4]
      loc_colon = get_sids.index(' ')
      names = get_sids[0, loc_colon]
      if get_last != '500' && get_last != '501' && get_disabled != 'TRUE'
        get_names.push(names)
      end
    end
    
    if get_names != []
      get_names.each do |user|
        
        get_last_logon = command("Net User #{user} | Findstr /i 'Last Logon' | 
                         Findstr /v 'Password script hours'").stdout.strip
        
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
          end if inactive_accountsac != []
        end
        
      if inactive_accountsac != []
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
    
    describe 'The system does not have any inactive accounts, control is NA' do
      skip 'The system does not have any inactive accounts, controls is NA'
    end if inactive_accounts == []
    
    if inactive_accounts == []
      impact 0.0
    end
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
