#Setting the Audit Policy
auditpol /set /category:"Account Logon"  /failure:enable /success:enable
auditpol /set /category:"Account Management"  /failure:enable /success:enable
auditpol /set /category:"DS Access"  /failure:enable /success:enable
auditpol /set /category:"Logon/Logoff"  /failure:enable /success:enable
auditpol /set /category:"Object Access"  /failure:enable /success:disable
auditpol /set /category:"Policy Change"  /failure:enable /success:enable
auditpol /set /category:"Privilege Use"  /failure:enable /success:disable
auditpol /set /category:"Detailed Tracking"  /failure:enable /success:enable
auditpol /set /category:"System"  /failure:enable /success:enable


 
