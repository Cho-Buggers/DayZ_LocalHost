#params

param (
	[string] $paramFile,          # the ini file with all your DayZ startup parameters (default is DZ_server_params.ini in same directory of this script)
	[switch] $showLog,            # keep console window open to monitor the server logs?
	[switch] $deferClient,        # wait for the server to be ready for clients before starting the client?
	[switch] $ignoreClient,       # start server only (no client)?
	[switch] $removeLogFiles,     # remove old logfiles?
	[int]    $logIntervall = 800  # speed to check for changes in the logfile
)

#/params


#functions

function Set-WindowState {
	<#
	.LINK
	https://gist.github.com/Nora-Ballard/11240204
	modified by Cho Buggers to set window style of multiple windows of same process
	this function is used to minimize all unnecessary steam windows before startin the game (they just annoy me)
	#>

	[CmdletBinding(DefaultParameterSetName = 'InputObject')]
	param(
		[Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
		[Object[]] $InputObject,

		[Parameter(Position = 1)]
		[ValidateSet('FORCEMINIMIZE', 'HIDE', 'MAXIMIZE', 'MINIMIZE', 'RESTORE',
					 'SHOW', 'SHOWDEFAULT', 'SHOWMAXIMIZED', 'SHOWMINIMIZED',
					 'SHOWMINNOACTIVE', 'SHOWNA', 'SHOWNOACTIVATE', 'SHOWNORMAL')]
		[string] $State = 'SHOW',
		[switch] $SuppressErrors = $false,
		[switch] $SetForegroundWindow = $false
	)

	Begin {
		$WindowStates = @{
			'FORCEMINIMIZE'     = 11
			'HIDE'              = 0
			'MAXIMIZE'          = 3
			'MINIMIZE'          = 6
			'RESTORE'           = 9
			'SHOW'              = 5
			'SHOWDEFAULT'       = 10
			'SHOWMAXIMIZED'     = 3
			'SHOWMINIMIZED'     = 2
			'SHOWMINNOACTIVE'   = 7
			'SHOWNA'            = 8
			'SHOWNOACTIVATE'    = 4
			'SHOWNORMAL'        = 1
		}

		$Win32ShowWindowAsync = Add-Type -MemberDefinition @'
[DllImport("user32.dll")]
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
[DllImport("user32.dll", SetLastError = true)]
public static extern bool SetForegroundWindow(IntPtr hWnd);
'@ -Name "Win32ShowWindowAsync" -Namespace Win32Functions -PassThru

		if (!$global:MainWindowHandles) {
			$global:MainWindowHandles = @{ }
		}
	}
	
	Process {
		foreach ($process in $InputObject) {
			$handle  = $process.MainWindowHandle
			$handles = @()
			
			if ($handle -eq 0) {
				if (-not $SuppressErrors) {
					Write-Error "Main Window handle is '0'"
				}
				continue
			}
			
			# mod by Cho Buggers
			while($handle -ne 0)
			{
				$handles += $handle
				$handles += (($handle | Get-ChildWindow) | Where-Object {$_.MainWindowHandle -eq $handle} ).ChildId
				foreach($h in $handles)
				{
					$Win32ShowWindowAsync::ShowWindowAsync($handle, $WindowStates[$State]) | Out-Null
					if ($SetForegroundWindow) {
						$Win32ShowWindowAsync::SetForegroundWindow($handle) | Out-Null
					}
				}
				$handle = (Get-Process -id $process.Id).MainWindowHandle
			}
		}
	}
}

function Get-ChildWindow{
	<#
	link: https://stackoverflow.com/questions/25369285/how-can-i-get-all-window-handles-by-a-process-in-powershell#25484076
	this function is used in conjunction with Set-WindowState
	#>

	[CmdletBinding()]
	param (
		[Parameter(ValueFromPipeline = $true, ValueFromPipelinebyPropertyName = $true)]
		[ValidateNotNullorEmpty()]
		[System.IntPtr]$MainWindowHandle
	)
	
	BEGIN{
		function Get-WindowName($hwnd) {
			$len = [apifuncs]::GetWindowTextLength($hwnd)
			if($len -gt 0){
				$sb = New-Object text.stringbuilder -ArgumentList ($len + 1)
				$rtnlen = [apifuncs]::GetWindowText($hwnd,$sb,$sb.Capacity)
				$sb.tostring()
			}
		}
	
		if (("APIFuncs" -as [type]) -eq $null){
			Add-Type  @"
			using System;
			using System.Runtime.InteropServices;
			using System.Collections.Generic;
			using System.Text;
			public class APIFuncs
			  {
				[DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
				public static extern int GetWindowText(IntPtr hwnd,StringBuilder lpString, int cch);
	
				[DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
				public static extern IntPtr GetForegroundWindow();
	
				[DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
				public static extern Int32 GetWindowThreadProcessId(IntPtr hWnd,out Int32 lpdwProcessId);
	
				[DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
				public static extern Int32 GetWindowTextLength(IntPtr hWnd);
	
				[DllImport("user32")]
				[return: MarshalAs(UnmanagedType.Bool)]
				public static extern bool EnumChildWindows(IntPtr window, EnumWindowProc callback, IntPtr i);
				public static List<IntPtr> GetChildWindows(IntPtr parent)
				{
				   List<IntPtr> result = new List<IntPtr>();
				   GCHandle listHandle = GCHandle.Alloc(result);
				   try
				   {
					   EnumWindowProc childProc = new EnumWindowProc(EnumWindow);
					   EnumChildWindows(parent, childProc,GCHandle.ToIntPtr(listHandle));
				   }
				   finally
				   {
					   if (listHandle.IsAllocated)
						   listHandle.Free();
				   }
				   return result;
			   }
				private static bool EnumWindow(IntPtr handle, IntPtr pointer)
			   {
				   GCHandle gch = GCHandle.FromIntPtr(pointer);
				   List<IntPtr> list = gch.Target as List<IntPtr>;
				   if (list == null)
				   {
					   throw new InvalidCastException("GCHandle Target could not be cast as List<IntPtr>");
				   }
				   list.Add(handle);
				   //  You can modify this to check to see if you want to cancel the operation, then return a null here
				   return true;
			   }
				public delegate bool EnumWindowProc(IntPtr hWnd, IntPtr parameter);
			   }
"@
			}
	}
	
	PROCESS{
		foreach ($child in ([apifuncs]::GetChildWindows($MainWindowHandle))){
			Write-Output (,([PSCustomObject] @{
				MainWindowHandle = $MainWindowHandle
				ChildId = $child
				ChildTitle = (Get-WindowName($child))
			}))
		}
	}
}


Function Get-PSScriptPath 
{
	# this was initially used to get the current path of the compiled exe (using PS2EXE compiler)
	# but thanks to some assholes that used powershell and PS2EXE to create malware
	# all powershell scripts using PS2EXE compiler are now recognized as malware by Windows Defender...
	# ( ︶︿︶)_╭∩╮
	
	<#
	
	.SYNOPSIS
	Returns the current filepath of the .ps1 or compiled .exe with Win-PS2EXE.
	
	.DESCRIPTION
	This will return the path of the file. This will work when the .ps1 file is
	converted with Win-PS2EXE
	
	.NOTES
	Author: Ste
	Date Created: 2021.05.03
	Tested with PowerShell 5.1 and 7.1.
	Posted here: https://stackoverflow.com/q/60121313/8262102
	
	.PARAMETER None
	NA
	
	.INPUTS
	None. You cannot pipe objects to Get-PSScriptPath.
	
	.OUTPUTS
	Returns the current filepath of the .ps1 or compiled .exe with Win-PS2EXE.
	
	.EXAMPLE (When run from a .ps1 file)
	PS> Get-PSScriptPath
	PS> C:\Users\Desktop\temp.ps1
	
	.EXAMPLE (When run from a compiled .exe file with Win-PS2EXE.
	PS> Get-PSScriptPath
	PS> C:\Users\Desktop\temp.exe
	
	#>

	if ([System.IO.Path]::GetExtension($PSCommandPath) -eq '.ps1') {
		$psScriptPath = $PSCommandPath
	} else {
		# This enables the script to be compiled and get the directory of it.
		$psScriptPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
	}
	return (Get-Item $psScriptPath -ErrorAction SilentlyContinue).Directory.FullName
}


function GetDzLogFile
{
	param (
		[int]    $procId,
		[string] $logPath,
		[string] $logType = "script",
		[switch] $showLog
	)
	
	$error = $false
	
	if( !$procId )
	{
		if( $showLog ) 
		{
			Write-Error "ERROR: Function GetDzLogFile - argument '-procId' must not be empty!" -ForegroundColor Red
		}
		$error = $true
	}
	
	$process = (Get-Process -id $procId -ErrorAction SilentlyContinue)
	if(!$process) 
	{
		if( $showLog ) 
		{
			Write-Error "ERROR: Function GetDzLogFile - argument '-procId' must be a valid process id! No instance of process with ID $($procId) found!" -ForegroundColor Red
		}
		$error = $true
	}
	
	if( !$logPath )
	{
		if( $showLog ) 
		{
			Write-Error "ERROR: Function GetDzLogFile - argument '-logPath' must not be empty!" -ForegroundColor Red
		}
		$error = $true
	}
	
	$logPathExists = !!(Get-Item $logPath)
	
	if( !$logPathExists )
	{
		if( $showLog ) 
		{
			Write-Error "ERROR: Function GetDzLogFile - argument '-logPath' must be a valid path! Path $($logPath) not found!" -ForegroundColor Red
		}
		$error = $true
	}
	
	if( $error ) 
	{
		exit
	}
	
	$startTime = Get-Date $process.StartTime
	
	#ToDo: obsolete?
	if( !$startTime ) 
	{
		$startTime = Get-Date 0
	}
	
	if( $showLog ) 
	{
		Write-Host "[$(Get-Date)] Checking for latest $($logType) log file " -NoNewline -ForegroundColor DarkGray
	}
	
	$logFilePattern = switch ( $logType )
	{
		'script' { 'script_????-??-??_??-??-??.log' }
		'report' { 'DayZDiag_x64_????-??-??_??-??-??.RPT' }
		# ToDo: Admin/crash logs
	}
	
	while($startTime -gt $modifiedDate -and (Get-Process -id $procId -ErrorAction SilentlyContinue) ) 
	{
		if( $showLog ) 
		{
			Write-Host '.' -NoNewline -ForegroundColor DarkGray
		}
		Start-Sleep -Milliseconds 1000
		$logFile = Get-ChildItem "$($logPath)\$($logFilePattern)" | Where-Object { $_.LastWriteTime.Date -lt $startTime } | sort LastWriteTime | select -last 1
		if( $logFile ) 
		{
			$modifiedDate = $logFile.LastWriteTime
		}
	}
	
	if( $showLog ) 
	{
		Write-Host ""
		Write-Host "[$(Get-Date)] $($logType) logfile found at $($logFile.FullName)" -ForegroundColor DarkGray
	}
	
	$logFile
}


function RemoveDzLogFiles
{
	param (
		[String[]] $path,
		[String[]] $fileTypes = @(".log",".RPT",".mdmp",".ADM"),
		[switch]   $showLog
	)
	
	if( $showLog ) 
	{
		Write-Host "[$(Get-Date)] Removing log files " -NoNewline -ForegroundColor DarkGray
	}
	
	foreach( $item in $path )
	{
		if( $showLog ) 
		{
			Write-Host '.' -NoNewline -ForegroundColor DarkGray
		}
		Get-ChildItem $item -File `
		| Where-Object { ! $_.PSIsContainer -and $_.extension -in $fileTypes } `
		| Remove-Item -ErrorAction Ignore
	}
	if( $showLog ) 
	{
		Write-Host ""
	}
}


#stop process by id
function StopProcess
{
	param (
		[int]    $id,
		[String] $label,
		[switch] $showLog
	)
	
	$error = $false
	
	if( !$id )
	{
		if( $showLog ) 
		{
			Write-Error "ERROR: Function StopProcess - argument '-id' must not be empty!" -ForegroundColor Red
		}
		$error = $true
	}
	
	if( $error ) 
	{
		exit
	}
	
	if( $showLog ) 
	{
		if( !$label )
		{
			$label = (Get-Process -Id $id -ErrorAction SilentlyContinue).ProcessName
			if( !$label )
			{
				$label = "Process with Id $($id)"
			}
		}
		Write-Host "[$(Get-Date)] Stopping $($label) " -NoNewline -ForegroundColor DarkGray
	}
	
	Stop-Process -Id $id -Force -ErrorAction SilentlyContinue
	
	while ( (Get-Process -Id $id -ErrorAction SilentlyContinue).Count )
	{
		if( $showLog ) 
		{
			Write-Host '.' -NoNewline -ForegroundColor DarkGray
		}
		Start-Sleep -Milliseconds 1000
	}
	
	if( $showLog ) 
	{
		Write-Host ""
		Write-Host "[$(Get-Date)] $($label) stopped" -ForegroundColor DarkGray
	}
}


function StartProcess
{
	param (
		[String]   $path,
		[String[]] $argList,
		[String]   $label,
		[switch]   $showLog,
		[switch]   $unique,
		[ValidateSet('NORMAL', 'HIDDEN', 'MINIMIZE', 'MAXIMIZE')]
		[string] $windowStyle = 'NORMAL'
	)

	$windowStates = @{
		'NORMAL'   = 0
		'HIDDEN'   = 1
		'MINIMIZE' = 2
		'MAXIMIZE' = 3
	}
	
	$error = $false
	
	if( !$path )
	{
		if( $showLog ) 
		{
			Write-Error "ERROR: Function StartProcess - argument '-path' must not be empty!" -ForegroundColor Red
		}
		$error = $true
	}
	
	$name = (Get-Item $path).BaseName
	
	if( !$name )
	{
		if( $showLog ) 
		{
			Write-Error "ERROR: Function StartProcess - argument '-path' must be a valid file!" -ForegroundColor Red
		}
		$error = $true
	}
	
	if( $error ) 
	{
		exit
	}
	
	$args = @{}
	if ($argList) 
	{ 
		$args["ArgumentList"] = $argList 
	}
	
	if( !$label )
	{
		$label = $name
	}
	
	if( $unique )
	{
		$procId = (Get-Process -name $name -ErrorAction SilentlyContinue | Where-Object {$_.Path -eq $path}).Id | Sort-Object | Select -first 1 -unique
	}
	
	if( !$procId )
	{
		if( $showLog ) 
		{
			Write-Host "[$(Get-Date)] Starting $($label) ..." -ForegroundColor DarkGray
		}
		$procId = (Start-Process -windowStyle $windowStates[$windowStyle] -FilePath $path @args -passthru -ErrorAction SilentlyContinue).Id
	}
	
	if( !$procId )
	{
		Write-Error "ERROR: Function StartProcess - failed to start $($label)" -ForegroundColor Red
	}
	
	if( $showLog ) 
	{
		Write-Host "[$(Get-Date)] $($label) started" -ForegroundColor DarkGray
	}
	$procId
}


function Choice
{
	param (
		[string]   $title,
		[string]   $question,
		[String[]] $choices = @('&Yes', '&No')
	)
	
	$error = $false
	
	if (!$question) 
	{
		Write-Error "ERROR: Function Choice - argument '-question' must not be empty!" -ForegroundColor Red
		$error = $true
	}
	
	if ($choices.Count -lt 2) 
	{
		Write-Error "ERROR: Function Choice - argument '-choices' requires at least 2 items!" -ForegroundColor Red
		$error = $true
	}
	
	if($error) 
	{
		exit
	}
	
	$Host.UI.PromptForChoice($title, $question, $choices, 1)
}


function RestartProcess
{
	param (
		[int]      $id,
		[String]   $path,
		[String]   $logPath,
		[String[]] $argList,
		[String]   $label,
		[switch]   $showLog,
		[switch]   $unique,
		[switch]   $removeLogFiles
	)
	
	$error = $false
	
	if( !$path )
	{
		if( $showLog ) 
		{
			Write-Error "ERROR: Function RestartProcess - argument '-path' must not be empty!" -ForegroundColor Red
		}
		$error = $true
	}
	
	$name = (Get-Item $path).BaseName
	
	if( !$name )
	{
		if( $showLog ) 
		{
			Write-Error "ERROR: Function RestartProcess - argument '-path' must be a valid file!" -ForegroundColor Red
		}
		$error = $true
	}
	
	if( $error ) 
	{
		exit
	}
	
	if( $id -and (Get-Process -id $id -ErrorAction SilentlyContinue))
	{
		StopProcess -id $id -label $label -showLog:$showLog
	}
	
	if( $logPath -and $removeLogFiles )
	{
		RemoveDzLogFiles -path $logPath -showLog:$showLog
	}
	
	$procId = StartProcess -label $label -path $path -argList $argList -showLog:$showLog -unique:$unique
	$procId
}

#/functions


#code

# param stuff

if(!$paramFile)
{
	$paramFile = "$(Get-PSScriptPath)\DZ_server_params.ini"
}

$profiles     = "$($ENV:UserProfile)\Documents\DayZServer"
$dzPath       = (Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\bohemia interactive\dayz").main
Set-Location $dzPath


$_true = @(
	[string] "true"
	[string] "1"
	[bool]   $true
	[int]    1
)

$_false = @(
	[string] "false"
	[string] "0"
	[bool]   $false
	[int]    0
)


#start...
:main while( $true ) 
{
	$_ignoreClient = $ignoreClient
	#always re-read the params when (re)starting
	$params = @{
		"name"              = [string]   $env:UserName
		"mod"               = [String[]] @()
		"servermod"         = [String[]] @()
		"mission"           = [string]   "$(Get-PSScriptPath)\vanilla.chernarusplus"
		"config"            = [string]   "$(Get-PSScriptPath)\DZ_server.cfg"
		"cpucount"          = [int]      4
		"limitfps"          = [int]      300
		"world"             = [string]   "empty"
		"filepatching"      = [bool]     $true
		"dologs"            = [bool]     $true
		"adminlog"          = [bool]     $true
		"netlog"            = [bool]     $true
		"freezecheck"       = [bool]     $true
		"scrallowfilewrite" = [bool]     $true
		"nosplash"          = [bool]     $true
		"nopause"           = [bool]     $true
		"nobenchmark"       = [bool]     $true
		"scriptdebug"       = [bool]     $true
		"battleye"          = [bool]     $false
	}
	
	if( $paramFile -and (Test-Path $paramFile -PathType Leaf) ) 
	{
		Get-Content $paramFile | ForEach-Object {
			$_ = $_.Trim()
			if( $_ -match "^;" ) {
				# comments
			}
			elseif( $_ -match "^\[(\w+)\]$" ) {
				# sections
				$key = $matches[1].ToLower()
				if( $params.ContainsKey($key) -and $params[$key].GetType().Name -eq "String[]" ) {
					$section = $key
				}
			}
			elseif( $_ -match "^([^;\s\t =]+)[\s\t ]*=[\s\t ]*(.*)$" ) {
				# key = value
				$key = $matches[1].ToLower()
				if( $params.ContainsKey($key) -and $params[$key].GetType().Name -eq "Boolean" ) {
					if( $_false.Contains(($matches.2).ToLower()) )
					{
						$params.Remove($key)
					}
					elseif( $_true.Contains(($matches.2).ToLower()) )
					{
						$params[$key] = $true
					}
				}
				else {
					$params[$key] = $matches.2
				}
			}
			elseif( $_ -match "^([^;=]+)$" ) {
				# value only
				$key = $matches[1].ToLower()
				if(!$section) {
					$params[$key] = $true
				}
				else {
					$params[$section] += $matches.1 
				}
			}
		}
	}
	
	$paramsStr = @()
	foreach( $name in $params.keys )
	{
		if( !$params[$name].Count ) {
			continue
		}
		if( $params[$name].GetType().Name -eq "Object[]" ) {
			$paramsStr += "`"-$($name)=$($params[$name] -join ';')`""
		}
		else {
			$paramsStr += "`"-$($name)=$($params[$name])`""
		}
	}
	
	$paramsStr    = $paramsStr -join ' '
	$paramsServer = "-server `"-profiles=$($profiles)`" $($paramsStr)"
	$paramsClient = "`"-connect=127.0.0.1:2302`" $($paramsStr)"
	
	if($showLog)
	{
		cls
		Write-Host ''
		Write-Host ''
		Write-Host "    DayZ - Logfile Monitor"
		Write-Host ''
		Write-Host "------------------------------" -ForegroundColor DarkGray
		Write-Host ''
		
		Write-Host "[$(Get-Date)] Checking for Steam ..." -ForegroundColor DarkGray
	}
	
	
	#start steam
	$steamPath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam").InstallPath
	while(!$steamProcId)
	{
		$steamProcId = StartProcess -label "Steam" -path "$($steamPath)\steam.exe" -unique -showLog:$showLog -windowStyle hidden
		if( $showLog -and !(Get-NetUDPEndpoint -OwningProcess $steamProcId -ErrorAction SilentlyContinue) )
		{
			Write-Host "[$(Get-Date)] Waiting for Steam to be ready " -NoNewline -ForegroundColor DarkGray
			
			While((Get-Process -id $steamProcId -ErrorAction SilentlyContinue) `
				-and ( `
						 (Get-Process -id $steamProcId).MainWindowHandle -eq 0 `
					-or !(Get-NetUDPEndpoint -OwningProcess $steamProcId -ErrorAction SilentlyContinue) `
					-or  (Get-Process -name "steam*").Count -lt 9 `
				)`
			)
			{
				if($showLog)
				{
					Write-Host "." -NoNewline -ForegroundColor DarkGray
				}
				Start-Sleep -Milliseconds 1000
			}
			
			# ToDo: how to check how much windows will be opened by steam? (to hide them they annoy me)
			# This will only work if the steamwebhelper is about to open an additional window
			# if not, we're waiting forever
			#$steamWebHelper = Get-Process -id (Get-WmiObject Win32_Process | select commandline,handle,ProcessName | Where-Object {$_.commandline -like "*-clientui=*" -and $_.ProcessName -like "steamwebhelper.exe"}).handle
			#While($steamWebHelper.MainWindowHandle -eq 0)
			#{
			#	if($showLog)
			#	{
			#		Write-Host "." -NoNewline -ForegroundColor DarkGray
			#	}
			#	Start-Sleep -Milliseconds 1000
			#	$steamWebHelper.Refresh()
			#}
			
			if($showLog)
			{
				Write-Host ""
			}
		}
		
		if(Get-Process -id $steamProcId -ErrorAction SilentlyContinue)
		{
			if($showLog)
			{
				Write-Host "[$(Get-Date)] Steam is ready to rumble" -ForegroundColor DarkGray
			}
			break
		}
		
		if( $showLog )
		{
			if( (Choice -title "[$(Get-Date)] An error occured. Cannot start Steam." -question "Do you want to try again?") ) 
			{
				exit
			}
			continue
		}
		else
		{
			exit
		}
	}
	
	
	#start server
	if( $showLog )
	{
		Write-Host "[$(Get-Date)] Checking for DayZ Server ..." -ForegroundColor DarkGray
	}
	
	$dzServerProcId = (Get-WmiObject Win32_Process | select commandline,handle,ProcessName | Where-Object {$_.commandline -like "*-server *" -and $_.ProcessName -like "DayZDiag_x64.exe"}).Handle
	$dzClientProcId = (Get-WmiObject Win32_Process | select commandline,handle,ProcessName | Where-Object {$_.commandline -like "*-connect=127.0.0.1:2302*" -and $_.ProcessName -like "DayZDiag_x64.exe"}).Handle
	
	if( !$dzServerProcId )
	{
		while(!$dzServerProcId)
		{
			$dzServerProcId = RestartProcess -label "DayZ Server" -logPath $profiles -path "$($dzPath)\DayZDiag_x64.exe" -argList $paramsServer -showLog:$showLog -removeLogFiles:$removeLogFiles
			
			if( $dzServerProcId )
			{
				break
			}
			
			if( $showLog ) 
			{
				if( (Choice -title "[$(Get-Date)] An error occured. Cannot start DayZ Server." -question "Do you want to try again?") )
				{
					exit
				}
				continue
			}
			else
			{
				exit
			}
		}
	}
	elseif($showLog)
	{
		Write-Host "[$(Get-Date)] DayZ Server is already running" -ForegroundColor DarkGray
	}
	
	if( $params['dologs'] )
	{
		#get server log
		$logFile = GetDzLogFile -logPath $profiles -procId $dzServerProcId -showLog:$showLog
		if(!$logFile)
		{
			if( $showLog )
			{
				if((Choice -title "[$(Get-Date)] Unable to find script log file. Maybe DayZ Server is terminated." -question "Do you want to restart DayZ Server?")) 
				{
					StopProcess -id $dzServerProcId -label "DayZ Server" -showLog:$showLog
					exit
				}
				StopProcess -id $dzServerProcId -label "DayZ Server" -showLog:$showLog
				continue main
			}
			else
			{
				StopProcess -id $dzServerProcId -label "DayZ Server" -showLog:$showLog
				exit
			}
		}
		
		#check if server is about to go down or any issues occured regarding the logs
		$logData = Get-Content $logFile.FullName
		if(($logData | select-string -pattern "~DayZGame()").Count)
		{
			if($showLog)
			{
				Write-Host "[$(Get-Date)] DayZ Server is about to go down; waiting for server to be terminated ..." -NoNewline -ForegroundColor DarkGray
			}
			
			while((Get-Process -id $dzServerProcId -ErrorAction SilentlyContinue))
			{
				if($showLog)
				{
					Write-Host "." -NoNewline -ForegroundColor DarkGray
				}
				Start-Sleep -Milliseconds 1000
			}
			
			if($showLog)
			{
				Write-Host ""
				Write-Host "[$(Get-Date)] DayZ Server terminated" -ForegroundColor DarkGray
			}
			
			continue main
		}
		elseif(($logData | select-string -pattern "SCRIPT    \(E\): Can't compile").Count)
		{
			if($showLog)
			{
				$logData
				if( (Choice -title "[$(Get-Date)] An error occured. Check your log files for more info." -question "Do you want to try to restart DayZ Server?") ) 
				{
					StopProcess -id $dzServerProcId -label "DayZ Server" -showLog:$showLog
					exit
				}
				StopProcess -id $dzServerProcId -label "DayZ Server" -showLog:$showLog
				continue main
			}
			else {
				StopProcess -id $dzServerProcId -label "DayZ Server" -showLog:$showLog
				exit
			}
		}
	}
	
	# wait for server to be ready
	if( !$ignoreClient -and $deferClient )
	{
		$deferClient = !(Get-NetUDPEndpoint -LocalPort 2302 -OwningProcess $dzServerProcId -ErrorAction SilentlyContinue)
		if($deferClient)
		{
			if( $showLog )
			{
				Write-Host "[$(Get-Date)] Waiting for DayZ Server to be ready for clients " -NoNewline -ForegroundColor DarkGray
			}
			
			if( $params['dologs'] )
			{
				while( !($logData | select-string -pattern "SCRIPT    \(E\): Can't compile").Count -and (Get-Process -id $dzServerProcId -ErrorAction SilentlyContinue) -and !(Get-NetUDPEndpoint -LocalPort 2302 -OwningProcess $dzServerProcId -ErrorAction SilentlyContinue) )
				{
					$logData = Get-Content $logFile.FullName
					if($showLog)
					{
						Write-Host "." -NoNewline -ForegroundColor DarkGray
					}
					Start-Sleep -Milliseconds 1000
				}
				Write-Host ""
				if(($logData | select-string -pattern "SCRIPT    \(E\): Can't compile").Count)
				{
					if($showLog)
					{
						$logData
						if( (Choice -title "[$(Get-Date)] An error occured. Check your log files for more info." -question "Do you want to try to restart DayZ Server?") ) 
						{
							StopProcess -id $dzServerProcId -label "DayZ Server" -showLog:$showLog
							exit
						}
						StopProcess -id $dzServerProcId -label "DayZ Server" -showLog:$showLog
						continue main
					}
					else {
						StopProcess -id $dzServerProcId -label "DayZ Server" -showLog:$showLog
						exit
					}
				}
			}
			if(!(Get-Process -id $dzServerProcId -ErrorAction SilentlyContinue))
			{
				if($showLog)
				{
					if( (Choice -title "[$(Get-Date)] An error occured. DayZ server was terminated." -question "Do you want to try to restart DayZ Server?") ) 
					{
						exit
					}
					continue main
				}
				else {
					exit
				}
			}
		}
		if( $showLog )
		{
			Write-Host "[$(Get-Date)] DayZ Server is ready for connection" -ForegroundColor DarkGray
			Write-Host "[$(Get-Date)] Checking for DayZ Client " -ForegroundColor DarkGray
		}
	}
	
	#start client
	if( !$ignoreClient -and !$dzClientProcId )
	{
		while(!$dzClientProcId)
		{
			$dzClientProcId = RestartProcess -label "DayZ Client" -logPath "$($ENV:UserProfile)\AppData\local\DayZ" -path "$($dzPath)\DayZDiag_x64.exe" -argList $paramsClient -showLog:$showLog -removeLogFiles:$removeLogFiles
			if($dzClientProcId)
			{
				break
			}
			
			if( $showLog ) 
			{
				if( (Choice -title "[$(Get-Date)] An error occured. Cannot start DayZ Client." -question "Do you want to try again?") )
				{
					exit
				}
				continue
			}
			else {
				exit
			}
		}
	}
	elseif( !$ignoreClient -and $showLog ) {
		Write-Host "[$(Get-Date)] DayZ Client is already up and running; user interaction required; connect to server manually" -ForegroundColor DarkGray
	}
	
	if( !$ignoreClient -and $params['dologs'] )
	{
		#get client logs
		$clientLogFile = GetDzLogFile -logPath "$($ENV:UserProfile)\AppData\local\DayZ" -procId $dzClientProcId -showLog:$showLog
		if( !$clientLogFile )
		{
			if( $showLog )
			{
				if((Choice -title "[$(Get-Date)] Unable to find clients script log file. Maybe DayZ Client was terminated." -question "Do you want to restart DayZ Client?")) 
				{
					StopProcess -id $dzClientProcId -label "DayZ Client" -showLog:$showLog
					exit
				}
				StopProcess -id $dzClientProcId -label "DayZ Client" -showLog:$showLog
				continue main
			}
			else {
				StopProcess -id $dzClientProcId -label "DayZ Client" -showLog:$showLog
				exit
			}
		}
		
		#check if client is about to go down or any issues occured regarding the logs
		$logData = (Get-Content $clientLogFile.FullName)
		if(($logData | select-string -pattern "~DayZGame()").Count)
		{
			if($showLog)
			{
				Write-Host "[$(Get-Date)] DayZ Client is about to go down; waiting for client to be terminated ..." -NoNewline -ForegroundColor DarkGray
			}
			
			while((Get-Process -id $dzClientProcId -ErrorAction SilentlyContinue))
			{
				if($showLog)
				{
					Write-Host "." -NoNewline -ForegroundColor DarkGray
				}
				Start-Sleep -Milliseconds 1000
			}
			
			if($showLog)
			{
				Write-Host ""
				Write-Host "[$(Get-Date)] DayZ Client was terminated" -ForegroundColor DarkGray
			}
			
			continue main
		}
		elseif(($logData | select-string -pattern "SCRIPT    \(E\): Can't compile").Count)
		{
			if($showLog)
			{
				Get-Content $clientLogFile.FullName
				if( (Choice -title "[$(Get-Date)] An error occured. Check your client log files for more info." -question "Do you want to try to restart DayZ Client?") ) 
				{
					StopProcess -id $dzClientProcId -label "DayZ Client" -showLog:$showLog
					exit
				}
				StopProcess -id $dzClientProcId -label "DayZ Client" -showLog:$showLog
				continue main
			}
			else {
				StopProcess -id $dzClientProcId -label "DayZ Client" -showLog:$showLog
				exit
			}
		}
	}
	
	
	# This will only close the main steam window on start or all steam windows if steam was already running and all windows where ready
	# ToDo: how to make sure all windows are closed regardless of start/running?
	# A: currently we just put these lines down here to be executed as late as possible ...
	Get-Process -name "steam*" | Set-WindowState -State HIDE -SuppressErrors
	
	
	# start monitoring logfile
	if( $showLog -and $params['dologs'] )
	{
		Write-Host "[$(Get-Date)] Start monitoring DayZ Server log file" -ForegroundColor DarkGray
		Write-Host ''
		
		$logData = (Get-Content $logFile.FullName)
		$lines   = $logData.Count
		$logData
		
		while($true) 
		{
			If (!(Get-Process -id $dzServerProcId -ErrorAction SilentlyContinue)) 
			{
				if( (Choice -title "[$(Get-Date)] DayZ Server was terminated. Monitoring stopped." -question "Do you want to restart DayZ Server?") ) 
				{
					exit
				}
				continue main
			}
			
			$logFile = (get-item $logFile.FullName)
			
			if( (Get-Date).AddSeconds(($logIntervall/1000) * -2) -gt $logFile.LastWriteTime )
			{
				Start-Sleep -Milliseconds $logIntervall
				continue
			}
			
			$logData   = (Get-Content $logFile.FullName)
			$_lines    = $logData.Count
			$lastLines = ( $logData | select -last ($_lines - $lines) )
			$lines     = $_lines
			
			if( $lastLines )
			{
				$lastLines
				if(($lastLines | select-string -pattern "~DayZGame()").Count -or ($lastLines | select-string -pattern "SCRIPT    \(E\): Can't compile").Count)
				{
					if( (Choice -title "[$(Get-Date)] An error occured or server shut down. Monitoring stopped." -question "Do you want to restart DayZ Server?") ) 
					{
						StopProcess -id $dzServerProcId -label "DayZ Server" -showLog:$showLog
						exit
					}
					StopProcess -id $dzServerProcId -label "DayZ Server" -showLog:$showLog
					continue main
				}
			}
			
			if( !$_ignoreClient -and !(Get-Process -id $dzClientProcId -ErrorAction SilentlyContinue) )
			{
				$choice = (Choice -title "[$(Get-Date)] DayZ Client was terminated." -question "Do you want to restart DayZ Client?" -choices @('&Yes', '&No' , '&Ignore'))
				if( $choice -eq 0 ) {
					$dzClientProcId = RestartProcess -label "DayZ Client" -logPath "$($ENV:UserProfile)\AppData\local\DayZ" -path "$($dzPath)\DayZDiag_x64.exe" -argList $paramsClient -showLog:$showLog -removeLogFiles:$removeLogFiles
				}
				elseif( $choice -eq 2 ) {
					$_ignoreClient = $true
				}
			}
			
			Start-Sleep -Milliseconds $logIntervall
		}
	}
	else
	{
		if($showLog)
		{
			Write-Host "[$(Get-Date)] "-dologs" is disabled by DayZ startup params; nothing to do here." -ForegroundColor DarkGray
		}
		exit
	}
}