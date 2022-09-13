############################################################################################################################
#                                                                                                                          #
# Last Modified: 9/13/2022                                                                                                 #
#                                                                                                                          #
# This script is used to create a list of machines to remotely access via RDP in RDCMan Management Tool. It prompt you     #
# to enter a domain and the credentials for that domain that will be added to your file                                    #
#                                                                                                                          #
# REQUIREMENTS:                                                                                                            #
#     1.) Ability to perform LDAP queries against Active Directory for the domains                                         #
#     2.) RDCMan.exe file must exist on your local machine                                                                 #
#                                                                                                                          #
# REFERENCES:                                                                                                              #
#  https://docs.microsoft.com/en-us/sysinternals/downloads/rdcman                                                          #
#                                                                                                                          #
# Author: Robert Osborne                                                                                                   #
# Company: OsbornePro LLC.                                                                                                 #
# Contact: rosborne@osbornepro.com                                                                                         #
#                                                                                                                          #
############################################################################################################################

Write-Output "[*] Creating required functions"
Write-Output "[i] Run this script using the user account that will be opening the file to ensure the credentials will convert when you open the file"
 
Function Add-RDCManServerToGroup {
    [CmdletBinding()]
        param(
            [Parameter(
                Position=0,
                Mandatory=$False,
                HelpMessage="The name of the group that the server will be added to `nEXAMPLE: A360")]  # End Parameter
            [System.Object[]]$Group,
 
            [Parameter(
                Position=1,
                Mandatory=$True,
                HelpMessage="Define the name of the server `nEXAMPLE: desktop01.domain.com")]  # End Parameter
            [String]$ServerName
        )  # End param
   
    $ServerElement = $ServerTemplateElement.Clone()
    $ServerElement.Properties.Name = $ServerName
   
    [Void]$Group.AppendChild($ServerElement)
 
}  # End Function Add-ServerToGroup
 
Function Get-RDCManGroup {
    [CmdletBinding()]
        param(
            [Parameter(
                Position=0,
                Mandatory=$True)]  # End Parameter
            [System.Xml.XmlElement]$Element,
 
            [Parameter(
                Position=1,
                Mandatory=$True,
                HelpMessage="Enter the group name `nEXAMPLE: Company Servers")]  # End Parameter
            [String]$GroupName,
 
            [Parameter(
                Position=2,
                Mandatory=$True,
                HelpMessage="Enter the username to authetnciate with `nEXAMPLE: username@domain.com")]  # End Parameter
            [String]$UserName,
 
            [Parameter(
                Position=3,
                Mandatory=$True,
                HelpMessage="Enter your usernames password as a secure string in Base64 format `nHINT: Use 'ConvertTo-SecureString' or 'Read-Host -AsSecureString' to set this value")]  # End Parameter
            [String]$Base64,
 
            [Parameter(
                Position=4,
                Mandatory=$True,
                HelpMessage="Set the domain of the machine being added `nEXAMPLE: domain.com")]  # End Parameter
            [String]$Domain
        )  # End param
 
   $Group = $Template.RDCMan.File.Group | Where-Object { $_.Properties.Name -eq $GroupName} | Select-Object -First 1
 
    If ($Null -eq $Group) {
 
        $Group = $GroupTemplateElement.Clone()
        $Group.Properties.Name = $GroupName

        $Group.LogonCredentials.UserName = $UserName
        $Group.LogonCredentials.Password = $Base64
        $Group.LogonCredentials.Domain = $Domain
 
        $Group.RemoveChild($Group.Server)
        $Element.AppendChild($Group) | Out-Null
   
    }  # End If
  
   Return $Group
 
}  # End Function Get-RDCManGroup
 
Function Get-RDCManSecurePassword {
    [CmdletBinding()]
        param(
            [Parameter(
                Position=0,
                Mandatory=$True,
                HelpMessage="Enter the path to your RDCMan .rdg file `nEXAMPLE: C:\Temp\rdcman.rdg"
            )]  # End Parameter
            [String]$RDCManFile, # = "C:\Users\rosborne\Downloads\RDCMan\RDCMan.exe",
 
            [Parameter(
                    Position=1,
                    Mandatory=$True
            )]  # End Parameter
            [SecureString]$Password
        )  # End param
 
    If (!(Test-path "$($env:TEMP)\RDCMan.dll")) {
 
        If ($RDCManFile.Length -lt 2) {
 
            $RDCManFile = Get-ChildItem -Path "C:\" -Recurse -Filter "RDCMan.exe" -ErrorAction SilentlyContinue -Force | Select-Object -First 1 -ExpandProperty FullName
 
        }  # End If
 
        Copy-Item -Path "$RDCManFile" -Destination "$($env:TEMP)\RDCMan.dll" -Force -Confirm:$False
 
   }  # End If
 
   Import-Module -Name "$($env:TEMP)\RDCMan.dll"
 
   $EncryptionSettings = New-Object -TypeName RdcMan.EncryptionSettings
   [RdcMan.Encryption]::EncryptString([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)), $EncryptionSettings)
 
}  # End Function Get-RDCManSecurePassword
 
Function Set-RDCManFile {
   [CmdletBinding()]
    Param(
        [Parameter(
            Position=0,   
            Mandatory=$True,
            HelpMessage="Enter the object containing your computer name info")]
        [PSObject[]]$ComputerObject,
 
        [Parameter(
            Position=1,
            Mandatory=$False
        )]  # End Parameter
        [String]$OutFile,
 
        [Parameter(
            Position=2,   
            Mandatory=$False)]
        [ValidateScript({Test-Path -Path $_})]
        [String]$RDCManExecutable,
 
        [Parameter(
            Position=3,   
            Mandatory=$False)]
        [ValidateScript({Test-Path -Path $_})]
        [String]$XmlTemplate = "$env:TEMP\RDCManTemplate.rdg",
 
        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [Switch][Bool]$Open
    )  # End param
 
BEGIN {
    
    $GroupElement = @()
    Write-Verbose "Getting the location of the RDCMan.exe executable"
    If ($RDCManExecutable.Length -lt 2) {
 
        $RDCManExecutable = Get-ChildItem -Path "C:\" -Recurse -Filter "RDCMan.exe" -ErrorAction SilentlyContinue -Force | Select-Object -First 1 -ExpandProperty FullName
 
    }  # End If
 
    [Xml]$Template = '<?xml version="1.0" encoding="utf-8"?>
<RDCMan programVersion="2.7" schemaVersion="3">
    <file>
        <credentialsProfiles />
        <properties>
            <expanded>True</expanded>
            <name>Template</name>
        </properties>
        <remoteDesktop inherit="None">
            <sameSizeAsClientArea>True</sameSizeAsClientArea>
            <fullScreen>False</fullScreen>
            <colorDepth>24</colorDepth>
        </remoteDesktop>
        <group>
            <properties>
            <expanded>True</expanded>
            <name>Template</name>
            </properties>
            <logonCredentials inherit="None">
            <profileName scope="Local">Custom</profileName>
            <userName>UserName</userName>
            <password />
            <domain>DomainHereIfRelevant</domain>
            </logonCredentials>
            <server>
            <properties>
                <name>Template</name>
            </properties>
            </server>
        </group>
    </file>
    <connected />
    <favorites />
    <recentlyUsed />
</RDCMan>'
 
    $FileElement = $Template.RDCMan.File
    $GroupTemplateElement = $FileElement.Group
    $ServerTemplateElement = $GroupTemplateElement.Server
    $FileElement.Properties.Name = 'Servers' # Root element name
 
} PROCESS {
 
    ForEach ($CO in $ComputerObject) {
 
        If ($Null -ne $CO.Name -and $Null -ne $CO.Group) {
       
            $GroupElement = Get-RDCManGroup -Element $FileElement -GroupName $CO.Group -Username $CO.UserName -Base64 (Get-RDCManSecurePassword -RDCManFile $RDCManExecutable -Password (ConvertTo-SecureString -AsPlainText -String $CO.Password -Force)) -Domain $CO.Domain
            $CO | Where-Object -FilterScript { $_.Group -Match $CO.Group} | Foreach-Object { Add-RDCManServerToGroup -Group $GroupElement -ServerName "$($_.Name)" }
      
        }  # End If
 
    }  # End ForEach
  
} END {
 
    [Void]$FileElement.RemoveChild($GroupTemplateElement)
 
    $TempFile = New-TemporaryFile
    $Template.Save($TempFile)
 
    Move-Item -Path $TempFile -Destination $OutFile -Force -Confirm:$False
 
    If ($Open.IsPresent) {
 
        & $RDCManExecutable $OutFile
 
    }  # End If
  
 
}  # End END
 
}  # End Function Set-RDCManFile
 
$HT = @{}
$Devices = @()
$DefineDomains = (Read-Host -Prompt "Enter the parent domains you want to build an RDCMan file for. EXAMPLE: corp.local, nest.bluebirdbio.com, think.2seventybio.com, kiniksa.com").Split(",").Replace(" ","")
ForEach ($DomainDefined in $DefineDomains) {

    $HN = $DomainDefined.Split(".")[1]
    $HT.$HN = @()
    $HT.$HN += $DomainDefined
    $HT.$HN += Get-Credential -Message "Enter your admin credentials for the $($DomainDefined)"

}  # End ForEach

ForEach ($Item in $HT.Keys) {

    $Domain = $HT.$Item.Item(0)
    $Cred = $HT.$Item.Item(1)

    Try {
    
        If ($Cred) {

            $DirectoryContext = New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext -ArgumentList ('Domain', $Domain, $($Cred.UserName), $($Cred.GetNetworkCredential().Password))
        
        } Else {

            $DirectoryContext = New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext -ArgumentList ('Domain', $Domain)

        }  # End If Else

    } Catch {

        [Management.Automation.ErrorRecord]$Exception = $_
        $ErrorInfo = [PSCustomObject]@{
            Exception = $Exception.Exception.Message
            Reason    = $Exception.CategoryInfo.Reason
            Target    = $Exception.CategoryInfo.TargetName
            Script    = $Exception.InvocationInfo.ScriptName
            Line      = $Exception.InvocationInfo.ScriptLineNumber
            Column    = $Exception.InvocationInfo.OffsetInLine
        }  # End ErrorRecord

        Write-Error -Message ($ErrorInfo.Exception) -ErrorAction Stop

    }  # End Try Catch

    Write-Output "[*] Obtaining list of enabled servers from $($Domain)'s Active Directory"
    $LdapAllServerFilter = '(&(objectCategory=computer)(operatingSystem=*server*))'
    $DomainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DirectoryContext)
    $PrimaryDC = ($DomainObj.PdcRoleOwner).Name
    $SearchString = "LDAP://$($PrimaryDC):389/rootDSE"
    $Searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
    $Searcher.SearchRoot = New-Object -TypeName System.DirectoryServices.DirectoryEntry
    $Searcher.Filter = $LdapAllServerFilter
    $Searcher.SearchScope = "Subtree"
    
    $Results = $Searcher.FindAll()
    ForEach ($Result in $Results) {

        $Servers += $Result.GetDirectoryEntry() | Select-Object -Property name,dnsHostName,operatingSystem

    }  # End ForEach

    ForEach ($Server in $Servers) {

        If ($Server.dnsHostName.Length -gt 2 -and $Server.dnsHostName -ne "localhost") {

            Try {
        
                $Group = $Server.dnsHostName.Split(".")[-2]
                $Domain = "$($Group).$($Server.dnsHostName.Split(".")[-1])"
            
            } Catch {
    
                $Group = "NonDomainJoined"
                $Domain = "WORKSTATION"

            }  # End Try Catch
        
            $Devices += New-Object -TypeName PSCustomObject -Property @{
                Name=$($Server.dnsHostName);
                Group=$($Group);
                OS=$($Server.operatingSystem);
                Domain=$($Domain);
                Username=$Cred.UserName;
                Password=$Cred.GetNetworkCredential().Password;
            }  # End Property

        }  # End If

    }  # End ForEach

}  # End ForEach

Write-Output "[*] Saving your .rdg file to $env:USERPROFILE\Desktop\RemoteAccess.rdg"
$OutFile = "$env:USERPROFILE\Desktop\RemoteAccess.rdg" #Read-Host -Prompt "Where do you want to save your new .rdg file? EXAMPLE: C:\Temp\example.rdg"
Set-RDCManFile -ComputerObject $Devices -OutFile $OutFile
