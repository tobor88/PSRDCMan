<#
.SYNOPSIS
This cmdlet is used inside the Set-RDCManFile cmdlet to add Servers to a Group in the RDCMan profile


.DESCRIPTION
Adds Servers to a custom group in the RDCMan .rdg file


.PARAMETER Group
Defines the name of the group that the server will be added to

.PARAMETER ServerName
Defines the name of the server that will be added to a group


.EXAMPLE
Add-RDCManServerToGroup -Group General -ServerName server.domain.com
# This example adds server.domain.com to the General group


.INPUTS
None


.OUTPUTS
None


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
https://docs.microsoft.com/en-us/sysinternals/downloads/rdcman
https://github.com/tobor88
https://github.com/OsbornePro
https://www.powershellgallery.com/profiles/tobor
https://osbornepro.com
https://writeups.osbornepro.com
https://btpssecpack.osbornepro.com
https://www.powershellgallery.com/profiles/tobor
https://www.hackthebox.eu/profile/52286
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
#>
Function Add-RDCManServerToGroup {
    [CmdletBinding()]
        param(
            [Parameter(
                Position=0,
                Mandatory=$False,
                HelpMessage="The name of the group that the server will be added to `nEXAMPLE: Servers")]  # End Parameter
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


<#
.SYNOPSIS
This cmdlet is used inside the Set-RDCManFile cmdlet to retrieve the XML group element template that is used to add servers and groups to the rdg RDCMan file


.DESCRIPTION
Builds an XML entry to use in the RDCMan configurartion file


.PARAMETER Element
Defines the Element template to use when adding the customized information

.PARAMETER GroupName
Defines the group name that will be added to the XML element

.PARAMETER UserName
Defines the username that will be added to the XML element

.PARAMETER Bas64
Defines the Base64 encrypted password value to be added to the XML element

.PARAMETER Domain
Defines the domain value that will be added to the XML element


.EXAMPLE
Get-RDCManGroup -Element $Template.RDCMan.File -GroupName Servers -Username $env:USERNAME -Base64 (Get-RDCManSecurePassword -RDCManFile $RDCManExecutable -Password (ConvertTo-SecureString -AsPlainText -String $Password -Force)) -Domain $env:USERDNSDOMAIN
# This example creates an XML element entry that can be added to the RDCMan config file


.INPUTS
None


.OUTPUTS
None


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
https://docs.microsoft.com/en-us/sysinternals/downloads/rdcman
https://github.com/tobor88
https://github.com/OsbornePro
https://www.powershellgallery.com/profiles/tobor
https://osbornepro.com
https://writeups.osbornepro.com
https://btpssecpack.osbornepro.com
https://www.powershellgallery.com/profiles/tobor
https://www.hackthebox.eu/profile/52286
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
#>
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
                HelpMessage="Enter the group name `nEXAMPLE: Servers")]  # End Parameter
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


<#
.SYNOPSIS
This cmdlet is used to convert a secure password into an encrypted format that RDCMan uses when setting the password in .rdg files


.DESCRIPTION
Convert an encrypted password into something RDCMan can interpret when loading the .rdg file


.PARAMETER RDCManFile
Define the location of the RDCMan.exe file so it can be used as a DLL converting encrypted passwords. If not defined the file will be search for automatically

.PARAMETER Password
Define the password using a secure string method such as 'Read-Host -AsSecureString' or 'ConvertTo-SecureString'


.EXAMPLE
Convert-RDCManSecurePassword -RDCManFile $env:USERPROFILE\Downloads\RDCMan.exe -Password (ConvertTo-SecureString -AsPlainText -String $Password -Force)
# This example converts the defined password into an encrypted RDCMan understandable format

.EXAMPLE
Convert-RDCManSecurePassword -Password (Read-Host -AsSecureString -Message "Enter your password")
# This example discovers the RDCMan.exe file if it exists and uses it to convert the prompted password into an encrypted RDCMan understandable format


.INPUTS
None


.OUTPUTS
None


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
https://docs.microsoft.com/en-us/sysinternals/downloads/rdcman
https://github.com/tobor88
https://github.com/OsbornePro
https://www.powershellgallery.com/profiles/tobor
https://osbornepro.com
https://writeups.osbornepro.com
https://btpssecpack.osbornepro.com
https://www.powershellgallery.com/profiles/tobor
https://www.hackthebox.eu/profile/52286
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
#>
Function Convert-RDCManSecurePassword {
    [CmdletBinding()]
        param(
            [Parameter(
                Position=0,
                Mandatory=$False,
                HelpMessage="Enter the path to the RDCMan.exe file `nEXAMPLE: $env:USERPROFILE\Downloads\RDCMan\RDCMan.exe"
            )]  # End Parameter
            [String]$RDCManFile, # = ,

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

}  # End Function Convert-RDCManSecurePassword

<#
.SYNOPSIS
This cmdlet is used to create your .rdg file with the information you provide


.DESCRIPTION
Create a .rdg file that can be opened with RDCMan


.EXAMPLE
$Cred = Get-Credential -Message "Enter your Remote Admin access credentials"
$Devices = @()
$Device = Get-ADComputer -Filter * -Server $_ -Properties DNSHostName,OperatingSystem | Where-Object -FilterScript { $_.DistinguishedName -notlike "*OU=Workstations,OU=Managed,DC=osbornepro,DC=com*" }
ForEach ($D in $Device) {
    $Group = $D.DNSHostName.Split(".")[-2]
    $Domain = "$($Group).$($D.DNSHostName.Split(".")[-1])"
    $Devices += New-Object -TypeName PSCustomObject -Property @{
            Name=$($D.DNSHostName);
            Group=$($Group);
            OS=$($D.OperatingSystem);
            Domain=$($Domain);
            Username=$Cred.UserName;
            Password=$Cred.GetNetworkCredential().Password;
    }  # End Property
}  # End ForEach
Set-RDCManFile -ComputerObject $DeviceObjects -OutFile "$env:USERPROFILE\Desktop\RemoteAccess.rdg"
# This example queries Active Directory for computers not in the Workstations OU, groups them by domain, and builds a .rdg file off of it 


.INPUTS
None


.OUTPUTS
None


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
https://docs.microsoft.com/en-us/sysinternals/downloads/rdcman
https://github.com/tobor88
https://github.com/OsbornePro
https://www.powershellgallery.com/profiles/tobor
https://osbornepro.com
https://writeups.osbornepro.com
https://btpssecpack.osbornepro.com
https://www.powershellgallery.com/profiles/tobor
https://www.hackthebox.eu/profile/52286
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
#>
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
    
    [Void]$FileElement.RemoveChild($GroupTemplateElement)
  
} END {
 
    $TempFile = New-TemporaryFile
    $Template.Save($TempFile)
 
    Move-Item -Path $TempFile -Destination $OutFile -Force -Confirm:$False
 
    If ($Open.IsPresent) {
 
        & $RDCManExecutable $OutFile
 
    }  # End If
  
 
}  # End END
 
}  # End Function Get-RDCManFile
