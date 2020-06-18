#This script is used to cleanup the vRLI NFS Archive, you can specify the numebr of days for the NFS archive to maintain logs.
#v1.0 vMan.ch, 21.08.2019 - Initial Version
<#

    .SYNOPSIS

    vRLI just dumps files to archive and doesnt clean them up after X period, this script does the cleanup

    Script requires posh-ssh module --> Find-Module Posh-SSH | Install-Module

    Run the command below to store root user and pass in secure credential XML for each vRLI environment

        $cred = Get-Credential
        $cred | Export-Clixml -Path "C:\Scripts\vRLIArchiveManager\config\vRLI.xml"

#>
[CmdletBinding()]
param
(
    [String]$vRLI,
    [String]$vRLICreds,
    [int]$ArchiveDays,
    [String]$Email
)


#Logging Function
Function Log([String]$message, [String]$LogType, [String]$LogFile){
    $date = Get-Date -UFormat '%m-%d-%Y %H:%M:%S'
    $message = $date + "`t" + $LogType + "`t" + $message
    $message >> $LogFile
}

#Log rotation function
function Reset-Log 
{ 
    #function checks to see if file in question is larger than the parameter specified if it is it will roll a log and delete the oldest log if there are more than x logs. 
    param([string]$fileName, [int64]$filesize = 1mb , [int] $logcount = 5) 
     
    $logRollStatus = $true 
    if(test-path $filename) 
    { 
        $file = Get-ChildItem $filename 
        if((($file).length) -ige $filesize) #this starts the log roll 
        { 
            $fileDir = $file.Directory 
            $fn = $file.name #this gets the name of the file we started with 
            $files = Get-ChildItem $filedir | ?{$_.name -like "$fn*"} | Sort-Object lastwritetime 
            $filefullname = $file.fullname #this gets the fullname of the file we started with 
            #$logcount +=1 #add one to the count as the base file is one more than the count 
            for ($i = ($files.count); $i -gt 0; $i--) 
            {  
                #[int]$fileNumber = ($f).name.Trim($file.name) #gets the current number of the file we are on 
                $files = Get-ChildItem $filedir | ?{$_.name -like "$fn*"} | Sort-Object lastwritetime 
                $operatingFile = $files | ?{($_.name).trim($fn) -eq $i} 
                if ($operatingfile) 
                 {$operatingFilenumber = ($files | ?{($_.name).trim($fn) -eq $i}).name.trim($fn)} 
                else 
                {$operatingFilenumber = $null} 
 
                if(($operatingFilenumber -eq $null) -and ($i -ne 1) -and ($i -lt $logcount)) 
                { 
                    $operatingFilenumber = $i 
                    $newfilename = "$filefullname.$operatingFilenumber" 
                    $operatingFile = $files | ?{($_.name).trim($fn) -eq ($i-1)} 
                    write-host "moving to $newfilename" 
                    move-item ($operatingFile.FullName) -Destination $newfilename -Force 
                } 
                elseif($i -ge $logcount) 
                { 
                    if($operatingFilenumber -eq $null) 
                    {  
                        $operatingFilenumber = $i - 1 
                        $operatingFile = $files | ?{($_.name).trim($fn) -eq $operatingFilenumber} 
                        
                    } 
                    write-host "deleting " ($operatingFile.FullName) 
                    remove-item ($operatingFile.FullName) -Force 
                } 
                elseif($i -eq 1) 
                { 
                    $operatingFilenumber = 1 
                    $newfilename = "$filefullname.$operatingFilenumber" 
                    write-host "moving to $newfilename" 
                    move-item $filefullname -Destination $newfilename -Force 
                } 
                else 
                { 
                    $operatingFilenumber = $i +1  
                    $newfilename = "$filefullname.$operatingFilenumber" 
                    $operatingFile = $files | ?{($_.name).trim($fn) -eq ($i-1)} 
                    write-host "moving to $newfilename" 
                    move-item ($operatingFile.FullName) -Destination $newfilename -Force    
                } 
                     
            } 
 
                     
          } 
         else 
         { $logRollStatus = $false} 
    } 
    else 
    { 
        $logrollStatus = $false 
    } 
    $LogRollStatus 
} 


#Send Email Function
Function SS64Mail($SMTPServer, $SMTPPort, $SMTPuser, $SMTPPass, $strSubject, $strBody, $strSenderemail, $strRecipientemail, $AttachFile)
   {
   [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { return $true }
      $MailMessage = New-Object System.Net.Mail.MailMessage
      $SMTPClient = New-Object System.Net.Mail.smtpClient ($SMTPServer, $SMTPPort)
	  $SMTPClient.EnableSsl = $true
	  $SMTPClient.Credentials = New-Object System.Net.NetworkCredential($SMTPuser, $SMTPPass)
      $Recipient = New-Object System.Net.Mail.MailAddress($strRecipientemail, "Recipient")
      $Sender = New-Object System.Net.Mail.MailAddress($strSenderemail, "vRLI NFS Archive Restorer")
     
      $MailMessage.Sender = $Sender
      $MailMessage.From = $Sender
      $MailMessage.Subject = $strSubject
      $MailMessage.To.add($Recipient)
      $MailMessage.Body = $strBody
      if ($AttachFile -ne $null) {$MailMessage.attachments.add($AttachFile) }
      $SMTPClient.Send($MailMessage)
   }

#Get Stored Credentials

$ScriptPath = (Get-Item -Path ".\" -Verbose).FullName

#vars
$RunDateTime = (Get-date)
$RunDateTime = $RunDateTime.tostring("yyyyMMddHHmmss")
$CleanupDateTime = (Get-date).AddDays(-$ArchiveDays)

#clean up Log File
$LogFilePath = $ScriptPath + '\log\Logfile.log'
Reset-Log -fileName $LogFilePath -filesize 10mb -logcount 5

#SMTP Mail stuffs
$mailserver = 'smtp.vman.ch'
$mailport = 25
$mailSender = 'HawGawd@vman.ch'


#Get Stored Credentials

if($vRLICreds -gt ""){

    $vRLICred = Import-Clixml -Path "$ScriptPath\config\$vRLICreds.xml"

    }
    else
    {
    echo "vRLI Credentails not supplied, stop hammer time!"
    Exit
    }

if($Email -imatch '^.*@vman\.ch$'){

    Log -Message "$email matches the allowed domain" -LogType "JOB-$RunDateTime" -LogFile $LogFileLoc
    Echo "$email matches the allowed domain"

    $cred = Import-Clixml -Path "$ScriptPath\config\smtp.xml"

    $SMTPUser = $cred.GetNetworkCredential().Username
    $SMTPPassword = $cred.GetNetworkCredential().Password
    }
    else
    {
    Log -Message "$email is not in the vMan.ch domain, will not send mail but report generation will continue" -LogType "JOB-$RunDateTime" -LogFile $LogFileLoc
    Echo "$email is not in the vMan.ch domain, will not send mail but report generation will continue"
	$Email = ''
    }


#Script begins here

Log -Message "Starting Epic vRLI Powershell NFS Archive cleanup script" -LogType "INFO-$RunDateTime" -LogFile $LogFilePath

#Convert to Universal Time and doing date stuff.

[string]$StartYear = ($CleanupDateTime.ToUniversalTime()).tostring("yyyy")
[string]$StartMonth = ($CleanupDateTime.ToUniversalTime()).tostring("MM")
[string]$StartDay = ($CleanupDateTime.ToUniversalTime()).tostring("dd")

#Initiate connection to vRLI 

Log -Message "Initiate connection to $vRLI" -LogType "INFO-$RunDateTime" -LogFile $LogFilePath

$vRLISession = New-SSHSession -ComputerName $vRLI -Credential $vRLICred -AcceptKey -Force -KeepAliveInterval 60

If ($vRLISession.Connected -eq 'True'){

    #Get the NFS Mount

    $NFSMount = Invoke-SSHCommand -SessionId $vRLISession.SessionId -Command "mount | grep nfs"

    If ($NFSMount.Output -gt ''){

        $NFSPath = $NFSMount.Output | Select-String -Pattern '(:?\/storage\/core\/loginsight\/nfsmount\/\b[0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12}\b)(?:\stype nfs\s)'  | % {"$($_.matches.groups[1])"}

        If ($NFSPath.count -eq 0){

        $NFSPath = $NFSMount.Output | Select-String -Pattern '(:?\/storage\/core\/loginsight\/nfsmount\/\w*)(?:\stype nfs\s)'  | % {"$($_.matches.groups[1])"}

        }

        Elseif ($NFSPath.count -gt 0){
            $NFSPath = $NFSPath[0]
        }

        Write-host -ForegroundColor Green 'NFS mount found, meh continue the script'
        Log -Message "NFS mount $NFSPath found, meh continue the script" -LogType "INFO-$RunDateTime" -LogFile $LogFilePath
    } 
    else {

        Write-host -ForegroundColor Yellow 'Hotdawg NO NFS MOUNT FOUND, lets search the config and create a temp mount'
        Log -Message "Hawtdiggidy NO NFS MOUNT FOUND, lets search the config and create a temp mount" -LogType "INFO-$RunDateTime" -LogFile $LogFilePath

        $SearchforCurrentvRLIConfigXMLCommand = 'ls -at /storage/core/loginsight/config/loginsight-config.xml#* | head -1'
                            
        $NFSArchiveConfigPath = Invoke-SSHCommand -SessionId $vRLISession.SessionId -Command $SearchforCurrentvRLIConfigXMLCommand

        If ($NFSArchiveConfigPath.ExitStatus -eq 0 -and $NFSArchiveConfigPath.Output -gt ''){

            $NFSArchiveConfigXMLGrep = 'grep -oP ''nfs:?[\s\S]*?[^\\"]*'' ' + $NFSArchiveConfigPath.Output 
    
            $NFSArchiveConfigXMLPath = Invoke-SSHCommand -SessionId $vRLISession.SessionId -Command $NFSArchiveConfigXMLGrep

             If ($NFSArchiveConfigXMLPath.ExitStatus -eq 0 -and $NFSArchiveConfigXMLPath.Output -cmatch 'nfs*'){

                $NFSArchiveConfigXMLPath = $NFSArchiveConfigXMLPath.Output -replace 'nfs://',''

                $NFSServer = $NFSArchiveConfigXMLPath | select-string '(:?[^\/]*)' | % {"$($_.matches.groups[0])"}

                $NFSServerMountable = $NFSServer + ':'

                $NFSArchiveConfigXMLPath = $NFSArchiveConfigXMLPath -replace $NFSServer,$NFSServerMountable

                Write-host -ForegroundColor Green 'Found a valid config with an NFS Archive path, mounting $NFSArchiveConfigXMLPathit manually'
                Log -Message "Found a valid config with an NFS Archive path, mounting $NFSArchiveConfigXMLPath manually" -LogType "INFO-$RunDateTime" -LogFile $LogFilePath

                $mkdirOutput = Invoke-SSHCommand -SessionId $vRLISession.SessionId -Command 'mkdir /storage/core/loginsight/nfsmount/tmprestoremnt'

                If ($mkdirOutput.ExitStatus -eq 0){

                Write-host -ForegroundColor Green 'Created /storage/core/loginsight/nfsmount/tmprestoremnt, now mounting the NFS path to it'
                Log -Message "Created /storage/core/loginsight/nfsmount/tmprestoremnt, now mounting $NFSArchiveConfigXMLPath to it" -LogType "INFO-$RunDateTime" -LogFile $LogFilePath

                $MountCommand = "mount -t nfs $NFSArchiveConfigXMLPath /storage/core/loginsight/nfsmount/tmprestoremnt"

                $Mountoutput  = Invoke-SSHCommand -SessionId $vRLISession.SessionId -Command $MountCommand

                $NFSPath = '/storage/core/loginsight/nfsmount/tmprestoremnt'

                    If ($Mountoutput.ExitStatus -gt 0){

                    Write-host -ForegroundColor Red 'ERROR: Epic fail on mounting the NFS share, tired... giving up.'
                    Log -Message "Epic fail on mounting the NFS share, tired... giving up." -LogType "ERROR-$RunDateTime" -LogFile $LogFilePath

                    Remove-SSHSession -SessionId $vRLISession.SessionId
                    Remove-SSHSession -SessionId $vRLIRemoteSession.SessionId
                    EXIT
                    }

                }
             }
        }
    }

    [array]$NFSArchiveDayContents = @()
    
    $getYears = "ls " + $NFSPath
    $gotYears = (Invoke-SSHCommand -SessionId $vRLISession.SessionId -Command $getYears -TimeOut 300).Output | where-object { $_ -like "*20*" }

    foreach ($year in $gotYears) {
        $getMonths = "ls " + $NFSPath + "/" + $year
        $gotMonths = (Invoke-SSHCommand -SessionId $vRLISession.SessionId -Command $getMonths -TimeOut 300).Output
        foreach ($month in $gotMonths) {
            $getDays = "ls " + $NFSPath + "/" + $year + "/" + $month + "/"
            $gotDays = (Invoke-SSHCommand -SessionId $vRLISession.SessionId -Command $getDays -TimeOut 300).Output
            foreach ($day in $gotDays) {
                $CommandCheckNFSPathStartDay = "find " + $NFSPath + "/" + $year + "/" + $month + "/" + $day + ' -type f \( -name "*.blob" \)'
                try {
                    $currentDate = [DateTime]::ParseExact($year+$month+$day, "yyyyMMdd", $null)
                }
                catch {
                    $currentDate = Get-Date
                    write-warning "$NFSPath/$year/$month/$day does not exist. Moving on."
                    Log -Message "$NFSPath/$year/$month/$day does not exist. Moving on." -LogType "INFO-$RunDateTime" -LogFile $LogFilePath
                }
                if ($currentDate -lt $CleanupDateTime) { 
                    try {
                        write-host "Checking path:" $CommandCheckNFSPathStartDay
                        Log -Message "Checking path: $CommandCheckNFSPathStartDay" -LogType "INFO-$RunDateTime" -LogFile $LogFilePath
                        $tempVar = (Invoke-SSHCommand -SessionId $vRLISession.SessionId -Command $CommandCheckNFSPathStartDay -timeout 300).Output
                    }
                    catch [System.Management.Automation.MethodInvocationException] { # catch exception and move on if command runs over 300 seconds.
                        write-warning "Command timed out. Moving on."
                        Log -Message "Command timed out. Moving on." -LogType "INFO-$RunDateTime" -LogFile $LogFilePath
                        $vRLISession = New-SSHSession -ComputerName $vRLI -Credential $vRLICred -AcceptKey -Force -KeepAliveInterval 60
                    
                    }
                    if ($tempVar[0] -like '*.blob*' -and $day -lt $StartDay) {
                        $NFSArchiveDayContents += "rm -rf " + $NFSPath + "/" + $year + "/" + $month + "/" + $day
                    }
                }

            }
        }
    }
    If ($NFSArchiveDayContents.length -gt 0){
            
        Write-host -ForegroundColor Green "Boom! blobs on the NFS share, go go go let's start deleting old blobs"
        Log -Message "Boom! found blobs on the NFS share, go go go let's start deleting old blobs" -LogType "INFO-$RunDateTime" -LogFile $LogFilePath

        foreach ($command in $NFSArchiveDayContents) {
            Write-host -ForegroundColor Green "Running '$command'"
            Log -Message "Running '$command'" -LogType "INFO-$RunDateTime" -LogFile $LogFilePath

            $CommandDeleteblobsOutput =  (Invoke-SSHCommand -SessionId $vRLISession.SessionId -Command $command).Output
        }

        Write-host -ForegroundColor Green "Boom done! script completed, disconnecting."
        Log -Message "Boom done! Output: $CommandDeleteblobsOutput script completed, disconnecting." -LogType "INFO-$RunDateTime" -LogFile $LogFilePath

        Remove-SSHSession -SessionId $vRLISession.SessionId

    } else {
        write-host -ForegroundColor Red "The command to check the blobs in the NFS share timed out or returned null where not expected."
        Log -Message "The command to check the blobs in the NFS share timed out or returned null where not expected." -LogType "INFO-$RunDateTime" -LogFile $LogFilePath
        SS64Mail $mailserver $mailport $SMTPUser $SMTPPassword "The command to check the blobs in the NFS share timed out or returned null where not expected." $mailSender $email
        Remove-SSHSession -SessionId $vRLISession.SessionId
        Exit
    }
}
else {

Write-host -ForegroundColor DarkYellow "Couldnt SSH to $vRLI, aborting script"
Log -Message "Couldnt SSH to $vRLI, aborting script" -LogType "INFO-$RunDateTime" -LogFile $LogFilePath
SS64Mail $mailserver $mailport $SMTPUser $SMTPPassword "vRLI Automated NFS Archive Restore Failed on $vRLI" "Couldn't SSH to $vRLI, aborting script" $mailSender $email
}
