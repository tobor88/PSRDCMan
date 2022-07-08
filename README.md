# PSRDCMan

Collection of PowerShell functions that can be used to automate the creation of .rdg files used with Remote Desktop Connection Manager (RDCMan) from the SysInternals Suite. This tool is very useful in scripting the creation of an RDCMan file for anyone managing large clients or clients with multiple domains.

### List of Cmdlets

1. **Add-RDCManServerToGroup** : Used inside the Set-RDCManFile cmdlet to add Servers to a Group in the RDCMan profile
2. **Get-RDCManGroup** : Uused inside the Set-RDCManFile cmdlet to retrieve the XML group element template that is used to add servers and groups to the rdg RDCMan file
3. **Convert-RDCManSecurePassword** : Convert a secure string password into something RDCMan can interpret when loading the .rdg file
4. **Set-RDCManFile** : Create a .rdg file that can be opened with RDCMan
