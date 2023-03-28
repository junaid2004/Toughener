<#
.SYNOPSIS
    DSC script to harden Windows Server 2019 VM baseline policies for CSBP.
.DESCRIPTION
                  ValueData = '90'
.NOTE
    Copyright (c) ZCSPM. All rights reserved.
    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    # PREREQUISITE
    * Windows PowerShell version 5 and above
        1. To check PowerShell version type "$PSVersionTable.PSVersion" in PowerShell and you will find PowerShell version,
        2. To Install powershell follow link https://docs.microsoft.com/en-us/powershell/scripting/install/installing-windows-powershell?view=powershell-6
    * DSC modules should be installed
        1. AuditPolicyDsc
        2. SecurityPolicyDsc
        3. NetworkingDsc
        4. PSDesiredStateConfiguration

        To check Azure AD version type "Get-InstalledModule -Name <ModuleName>" in PowerShell window
        You can Install the required modules by executing below command.
            Install-Module -Name <ModuleName> -MinimumVersion <Version>
.EXAMPLE

    .\CIS_Benchmark_WindowsServer2019_v100.ps1 [Script will generate MOF files in directory]
    Start-DscConfiguration -Path .\CIS_Benchmark_WindowsServer2019_v100  -Force -Verbose -Wait
#>

# Configuration Definition
Configuration CIS_Benchmark_WindowsServer2019_v100 {
    param (
        [string[]]$ComputerName = 'localhost'
    )

    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'AuditPolicyDsc'
    Import-DscResource -ModuleName 'SecurityPolicyDsc'
    Import-DscResource -ModuleName 'NetworkingDsc'

	#Import-Module AuditPolicyDsc

    Node $ComputerName {
        AccountPolicy AccountPolicies
        {
            Name                                        = 'PasswordPolicies'

            # CceId: CCE-36286-3
            # DataSource: Security Policy
            # Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
Store_passwords_using_reversible_encryption = 'Disabled'

            # CceId: CCE-37063-5
            # DataSource: Security Policy
            # Ensure 'Password must meet complexity requirements' is set to 'Enabled'
Password_must_meet_complexity_requirements  = 'Enabled'

            # CceId: CCE-37432-2
            # DataSource: Security Policy
            # Ensure 'Accounts: Guest account status' is set to 'Disabled'
            #Accounts_Guest_account_status = 'Disabled'


            # CceId: CCE-36534-6
            # DataSource: Security Policy
            # Ensure 'Minimum password length' is set to '8 or more character'
Minimum_Password_Length = '14'

            # CceId: CCE-37073-4
            # DataSource: Security Policy
            # Ensure 'Minimum password age' is set to '1 or more day'
Minimum_Password_Age = '1'

            # CceId: CCE-37166-6
            # DataSource: Security Policy
            #  Ensure 'Enforce password history' is set to '24 or more password(s)'
Enforce_password_history = '24'

            # CceId: CCE-37167-4
            # DataSource: Security Policy
            # Ensure 'Maximum password age' is set to '90 or fewer days, but not 0'
Maximum_Password_Age = '90'
        }


SecurityOption AccountSecurityOptions {
                Name                                   = 'AccountSecurityOptions'

                # CceId: CCE-36056-0
                # DataSource: Registry Policy
                # Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
Interactive_logon_Do_not_display_last_user_name = 'Enabled'

                # CceId: CCE-37637-6
                # DataSource: Registry Policy
                # Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
Interactive_logon_Do_not_require_CTRL_ALT_DEL = 'Disabled'

                # CceId: CCE-36325-9
                # DataSource: Registry Policy
                # Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'

                # CceId: CCE-36269-9
                # DataSource: Registry Policy
                # Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'

                # CceId: CCE-37863-8
                # DataSource: Registry Policy
                # Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'
Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'

                # CceId: CCE-37615-2
                # DataSource: Registry Policy
                # Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'

                # CceId: CCE-36788-8
                # DataSource: Registry Policy
                # Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on = 'Disabled'

                # CceId: CCE-36858-9
                # DataSource: Registry Policy
                # Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
Network_security_LDAP_client_signing_requirements = 'Negotiate signing'

                # CceId:
                # DataSource: Registry Policy
                # Ensure 'System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies' is set to 'Enabled'
System_settings_Use_Certificate_Rules_on_Windows_Executables_for_Software_Restriction_Policies = 'Enabled'

                # CceId: CCE-37623-6
                # DataSource: Registry Policy
                # Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'
Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - local users authenticate as themselves'

                # CceId: CCE-35907-5
                # DataSource: Registry Policy
                # Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
Audit_Shut_down_system_immediately_if_unable_to_log_security_audits = 'Disabled'

                # CceId: CCE-37972-7
                # DataSource: Registry Policy
                # Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
Microsoft_network_server_Disconnect_clients_when_logon_hours_expire = 'Enabled'

                # CceId: CCE-35988-5
                # DataSource: Registry Policy
                # Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
Microsoft_network_server_Digitally_sign_communications_if_client_agrees  = 'Enabled'

                # CceId: CCE-37864-6
                # DataSource: Registry Policy
                # Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'

                # CceId: CCE-37701-0
                # DataSource: Registry Policy
                # Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
Devices_Allowed_to_format_and_eject_removable_media = 'Administrators'

                # CceId: CCE-37942-0
                # DataSource: Registry Policy
                # Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
Devices_Prevent_users_from_installing_printer_drivers = 'Enabled'

		
            	# CceId: CCE-36347-3
            	# DataSource: Registry Policy
            	# Configure 'Network access: Remotely accessible registry paths and sub-paths'
            	# BUG - https://github.com/PowerShell/SecurityPolicyDsc/issues/83
            	Network_access_Remotely_accessible_registry_paths_and_subpaths = 'System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog,System\CurrentControlSet\Services\CertSvc,System\CurrentControlSet\Services\Wins'

            	# CceId: CCE-37194-8
            	# DataSource: Registry Policy
            	# Configure 'Network access: Remotely accessible registry paths'
            	# BUG - https://github.com/PowerShell/SecurityPolicyDsc/issues/83
            	Network_access_Remotely_accessible_registry_paths = 'System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion'


		# CceId: CCE-36148-5
                # DataSource: Registry Policy
                # Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'

                # CceId: CCE-38046-9
                # DataSource: Registry Policy
                # Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute, but not 0'
Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15'

                # CceId:
                # DataSource: Registry Policy
                # Ensure 'Devices: Allow undock without having to log on' is set to 'Enabled'
Devices_Allow_undock_without_having_to_log_on = 'Disabled'

Interactive_logon_Message_text_for_users_attempting_to_log_on = 'IT IS AN OFFENSE TO CONTINUE WITHOUT PROPER AUTHORIZATION.'

Interactive_logon_Message_title_for_users_attempting_to_log_on = 'Warning!!!'

Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '1'

Interactive_logon_Prompt_user_to_change_password_before_expiration = '14'

Accounts_Administrator_account_status = 'Enabled'

Accounts_Rename_administrator_account = 'Dulantha'

Accounts_Rename_guest_account = 'GuestNo'

Audit_Audit_the_access_of_global_system_objects = 'Disabled'

Audit_Audit_the_use_of_Backup_and_Restore_privilege = 'Disabled'

DCOM_Machine_Access_Restrictions_in_Security_Descriptor_Definition_Language_SDDL_syntax = ''

DCOM_Machine_Launch_Restrictions_in_Security_Descriptor_Definition_Language_SDDL_syntax = ''

Devices_Restrict_CD_ROM_access_to_locally_logged_on_user_only = 'Disabled'

Devices_Restrict_floppy_access_to_locally_logged_on_user_only = 'Disabled'

Domain_controller_Allow_server_operators_to_schedule_tasks = 'Disabled'

                #Domain_controller_LDAP_server_signing_requirements = ''

Domain_controller_Refuse_machine_account_password_changes = 'Disabled'

Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'

Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'

Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'

Domain_member_Disable_machine_account_password_changes = 'Disabled'

Domain_member_Maximum_machine_account_password_age = '30'

Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'

                #Interactive_logon_Display_user_information_when_the_session_is_locked = ''

Interactive_logon_Require_Domain_Controller_authentication_to_unlock_workstation = 'Enabled'

Interactive_logon_Require_smart_card = 'Disabled'

Interactive_logon_Smart_card_removal_behavior = 'Lock Workstation'

Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'

Network_access_Do_not_allow_storage_of_passwords_and_credentials_for_network_authentication = 'Enabled'

Network_access_Named_Pipes_that_can_be_accessed_anonymously = ''

Network_security_Force_logoff_when_logon_hours_expire = 'Enabled'

Recovery_console_Allow_automatic_administrative_logon = 'Disabled'

                #System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = ''

System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Disabled'

System_objects_Require_case_insensitivity_for_non_Windows_subsystems = 'Enabled'

System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'

                #System_settings_Optional_subsystems = ''

}

		# CceId: CCE-36173-3
                # DataSource: Registry Policy
                # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
                Registry 'LmCompatibilityLevel' {
                    Ensure    = 'Present'
                    Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
                    ValueName = 'LmCompatibilityLevel'
                    ValueType = 'DWord'
                    ValueData = '4'
                }

                # CceId: CCE-37835-6
                # DataSource: Registry Policy
                # Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
                Registry 'NTLMMinServerSec' {
                    Ensure    = 'Present'
                    Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
                    ValueName = 'NTLMMinServerSec'
                    ValueType = 'DWord'
                    ValueData = '537395248'
                }

                # CceId: CCE-37553-5
                # DataSource: Registry Policy
                # Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
                Registry 'NTLMMinClientSec' {
                    Ensure    = 'Present'
                    Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
                    ValueName = 'NTLMMinClientSec'
                    ValueType = 'DWord'
                    ValueData = '537395248'
                }

                # CceId:
                # DataSource: Registry Policy
                # Ensure 'Shutdown: Clear virtual memory pagefile' is set to 'Disabled'
                Registry 'ClearPageFileAtShutdown' {
                    Ensure    = 'Present'
                    Key       = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management'
                    ValueName = 'ClearPageFileAtShutdown'
                    ValueType = 'DWord'
                    ValueData = '0'
                }

                # CceId:
                # DataSource: Registry Policy
                # Ensure 'Recovery console: Allow floppy copy and access to all drives and all folders' is set to 'Disabled'
                Registry 'AllowAllPaths' {
                    Ensure    = 'Present'
                    Key       = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand'
                    ValueName = 'AllowAllPaths'
                    ValueType = 'DWord'
                    ValueData = '0'
                }

                # CceId: CCE-37695-4
                # DataSource: Registry Policy
                # Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'
                Registry 'MaxSizeSecurityLog' {
                    Ensure    = 'Present'
                    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
                    ValueName = 'MaxSize'
                    ValueType = 'DWord'
                    ValueData = '122880'
                }

                # CceId: CCE-36326-7
                # DataSource: Registry Policy
                # Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'
                Registry 'NoLMHash' {
                    Ensure    = 'Present'
                    Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
                    ValueName = 'NoLMHash'
                    ValueType = 'DWord'
                    ValueData = '1'
                }

                # CceId:
                # DataSource: Registry Policy
                # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled' (MS only)
                Registry 'RestrictAnonymousSAM' {
                    Ensure    = 'Present'
                    Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
                    ValueName = 'RestrictAnonymousSAM'
                    ValueType = 'DWord'
                    ValueData = '1'
                }

                # CceId: CCE-36077-6
                # DataSource: Registry Policy
                # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' (MS only)
                Registry 'RestrictAnonymous' {
                    Ensure    = 'Present'
                    Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
                    ValueName = 'RestrictAnonymous'
                    ValueType = 'DWord'
                    ValueData = '1'
                }

                # CceId: CCE-36627-8
                # DataSource: Registry Policy
                # Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'
                Registry 'MinEncryptionLevel' {
                    Ensure    = 'Present'
                    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                    ValueName = 'MinEncryptionLevel'
                    ValueType = 'DWord'
                    ValueData = '3'
                }

                # CceId: CCE-37948-7
                # DataSource: Registry Policy
                # Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
                Registry 'MaxSizeApplication' {
                    Ensure    = 'Present'
                    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
                    ValueName = 'MaxSize'
                    ValueType = 'DWord'
                    ValueData = '40960'
                }

		Registry 'RestrictGuestAccessSystem' {
                  Ensure    = 'Present'
                  Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\System'
                  ValueName = 'RestrictGuestAccess'
                  ValueType = 'DWord'
                  ValueData = '1'
              }

              Registry 'RestrictGuestAccessSecurity' {
                  Ensure    = 'Present'
                  Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security'
                  ValueName = 'RestrictGuestAccess'
                  ValueType = 'DWord'
                  ValueData = '1'
              }

              Registry 'RestrictGuestAccessApplication' {
                  Ensure    = 'Present'
                  Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application'
                  ValueName = 'RestrictGuestAccess'
                  ValueType = 'DWord'
                  ValueData = '1'
              }

		# CceId: CCE-36021-4
                # DataSource: Registry Policy
                # Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'
                Registry 'RestrictNullSessAccess' {
                    Ensure    = 'Present'
                    Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
                    ValueName = 'RestrictNullSessAccess'
                    ValueType = 'DWord'
                    ValueData = '1'
                }

                # CceId: CCE-36092-5
                # DataSource: Registry Policy
                # Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
                Registry 'MaxSizeSystemLog' {
                    Ensure    = 'Present'
                    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
                    ValueName = 'MaxSize'
                    ValueType = 'DWord'
                    ValueData = '40960'
                }

		
		Registry 'AutoAdminLogon' {
                  Ensure    = 'Present'
                  Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
                  ValueName = 'AutoAdminLogon'
                  ValueType = 'DWord'
                  ValueData = '0'
              }



              Registry 'AutoReboot' {
                  Ensure    = 'Present'
                  Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl'
                  ValueName = 'AutoReboot'
                  ValueType = 'DWord'
                  ValueData = '0'
              }

              Registry 'AutoShareWks' {
                  Ensure    = 'Present'
                  Key       = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters'
                  ValueName = 'AutoShareWks'
                  ValueType = 'DWord'
                  ValueData = '1'
              }


            #Set time limit for disconnected sessions
            Registry 'MaxDisconnectionTime' {
                    Ensure    = 'Present'
                    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                    ValueName = 'MaxDisconnectionTime'
                    ValueType = 'DWord'
                    ValueData = '900000'
                }

            
            #Set time limit for active but idle Remote Desktop Services sessions
            Registry 'MaxIdleTime' {
                    Ensure    = 'Present'
                    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                    ValueName = 'MaxIdleTime'
                    ValueType = 'DWord'
                    ValueData = '900000'
                }


            #Do not allow clipboard redirection
            Registry 'fDisableClip' {
                    Ensure    = 'Present'
                    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                    ValueName = 'fDisableClip'
                    ValueType = 'DWord'
                    ValueData = '1'
                }


            #Allow AUdio Recording Resdirection
            Registry 'fDisableAudioCapture' {
                    Ensure    = 'Present'
                    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                    ValueName = 'fDisableAudioCapture'
                    ValueType = 'DWord'
                    ValueData = '1'
                }


            #Do not allow COM port redirection
            Registry 'fDisableCcm' {
                    Ensure    = 'Present'
                    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                    ValueName = 'fDisableCcm'
                    ValueType = 'DWord'
                    ValueData = '1'
                }


            #Do not allow client printer redirection
            Registry 'fDisableCpm' {
                    Ensure    = 'Present'
                    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                    ValueName = 'fDisableCpm'
                    ValueType = 'DWord'
                    ValueData = '1'
                }


            #Do not allow LPT port redirection
            Registry 'fDisableLPT' {
                    Ensure    = 'Present'
                    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                    ValueName = 'fDisableLPT'
                    ValueType = 'DWord'
                    ValueData = '1'
                }


            #Do no allow Drive redirection
            Registry 'fDisableCdm' {
                    Ensure    = 'Present'
                    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                    ValueName = 'fDisableCdm'
                    ValueType = 'DWord'
                    ValueData = '1'
                }
		

}
}
CIS_Benchmark_WindowsServer2019_v100

