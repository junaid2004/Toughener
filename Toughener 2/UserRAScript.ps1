#IMPORT PS EXCEL MODULE 
#import-module psexcel

#FILE TO BE COMPARED VARIABLES

#Getting User rights from the local secuirty policy and saving is in the file Userlogonrights.csv
#.\Get-UserRights.ps1 -FileOutputPath $pwd\ -FileOutputType CSV


$file1 = import-csv -path $pwd\UserLogonRights.csv     #may need to put the path into a string and different variable
$file2 = import-csv -path $pwd\UserRightAssignment.csv

$IncludedPriv = @()

#Iterating through lines in first csv file
foreach ($line in $file1) {

	#Extracting the Privilege and Principal
	$PrivilegeTemp = $line.Privilege
	$PrincipalTemp = $line.Principal
	

	foreach ($line2 in $file2) {

	
		$PrivilegeTemp2 = $line2.Privilege
		$PrincipalTemp2 = $line2.Principal	
 
		if ($PrivilegeTemp -contains $PrivilegeTemp2) {
			
			$IncludedPriv += "$($line2.Privilege)"

			if ($PrincipalTemp -contains $PrincipalTemp2) {
			
				#gc $pwd\needtoadd.csv | ? {$_ -notlike "*$($line2.Principal)*" } | sc needtoadd.csv

				$line3 = gc $pwd\UserLogonRights.csv | ? {$_ -notlike "*$($line2.Privilege)*$($line2.Principal)*" }
				
				$line3 | sc $pwd\UserLogonRights.csv

				$line4 = gc $pwd\UserRightAssignment.csv | ? {$_ -notlike "*$($line2.Privilege)*$($line2.Principal)*" }
				
				$line4 | sc $pwd\UserRightAssignment.csv 
			}
				
		} 
	}
}

#Removing lines with untold privileges 

$file1 = import-csv -path $pwd\UserLogonRights.csv     #may need to put the path into a string and different variable
$file2 = import-csv -path $pwd\UserRightAssignment.csv

$IncludedPriv = $IncludedPriv | select -uniq

foreach ($line in $file1) {
	
	$cond = $false

	foreach ($Priv in $IncludedPriv){
		
		if ($line.Privilege -contains $Priv) { 
	
			$cond = $true
			
			}


	}


	if ($cond -eq $false) {

			#Write-Host "$($line.PrivilegeName)"

			$line5 = gc $pwd\UserLogonRights.csv | ? {$_ -notlike "*$($line.Privilege)*" }
				
			$line5 | sc $pwd\UserLogonRights.csv	
			
	}

}




#Performing the Actual User Rights Assingment

$file1 = import-csv -path $pwd\UserLogonRights.csv     #These are the things that need to be removed accordingly to privilege
$file2 = import-csv -path $pwd\UserRightAssignment.csv   #These are the things that needs to be added

foreach ($line in $file2) {

	if ($line.Principal -eq "" ) { }

	else {
	.\Set-UserRights.ps1 -AddRight -Username $line.Principal -UserRight $line.Privilege
	}
}

foreach ($line in $file1) {

	.\Set-UserRights.ps1 -RemoveRight -Username $line.Principal -UserRight $line.Privilege
}
