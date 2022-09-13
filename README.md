# PSRDCMan

[Download RDCMan (Remote Desktop Connection Manager)](https://docs.microsoft.com/en-us/sysinternals/downloads/rdcman)
<br>
Collection of PowerShell functions that can be used to automate the creation of .rdg files used with Remote Desktop Connection Manager (RDCMan) from the SysInternals Suite. This tool is very useful in scripting the creation of an RDCMan file for anyone managing large clients or clients with multiple domains.

I added the script [CreateRDCManFile.ps1](https://github.com/tobor88/PSRDCMan/blob/main/PSRDCMan.psm1) which can be used out of the box to build your RDCMan file automatically. When run as is, it prompts you for the Active Directory domains you want to build your file from. To specify more than one use commas. It runs a query looking for all servers in the domain you specify. It then asks for your credentials for each domain you specify. Your credentials are used to authenticate to the domain you specify and in the RDCMan file that gets built for you. By default your file is saved to your desktop at $env:USERPROFILE\Desktop\RemoteAccess.rdg

### List of Cmdlets

1. **Add-RDCManServerToGroup** : Used inside the Set-RDCManFile cmdlet to add Servers to a Group in the RDCMan profile
2. **Get-RDCManGroup** : Uused inside the Set-RDCManFile cmdlet to retrieve the XML group element template that is used to add servers and groups to the rdg RDCMan file
3. **Convert-RDCManSecurePassword** : Convert a secure string password into something RDCMan can interpret when loading the .rdg file
4. **Set-RDCManFile** : Create a .rdg file that can be opened with RDCMan
