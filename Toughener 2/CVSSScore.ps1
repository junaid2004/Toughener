$file1 = import-csv -path $pwd\PolicyCSV\AccountLockoutPolicy.csv
$file2 = import-csv -path $pwd\AccountLockoutPolicy.csv

$file3 = import-csv -path $pwd\PolicyCSV\SecurityOption.csv
$file4 = import-csv -path $pwd\SecurityOption.csv

$file5 = import-csv -path $pwd\PolicyCSV\PasswordPolicy.csv
$file6 = import-csv -path $pwd\PasswordPolicy.csv

$file7 = import-csv -path $pwd\PolicyCSV\AuditPolicy.csv
$file8 = import-csv -path $pwd\AuditPolicy.csv


$file9 = import-csv -path $pwd\PolicyCSV\URAPolicy.csv
$file10 = import-csv -path $pwd\URAPolicy.csv



$TotalScore = 0

$files = @(($file1, $file2), ($file3, $file4), ($file5, $file6), ($file7, $file8), ($file9, $file10))


foreach ($file in $files){

($file1, $file2) = $file

foreach ($line in $file1) {

	$PolicyTemp = $line.Policy
	$SettingTemp = $line.'Security Setting'

	#write-host "$($PolicyTemp)"
	#write-host "$($SettingTemp)"


	foreach ($line2 in $file2){

		$CPolicyTemp = $line2.Policy
		$CSettingTemp = $line2.'Security Setting'
		$CScore = $line2.Score

		if ($PolicyTemp -contains $CPolicyTemp) {

			if ($SettingTemp -contains $CSettingTemp) {

				$TotalScore += $line2.Score

			}

		}

	}
	
}

}

write-host "$($TotalScore)"
