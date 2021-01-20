
PoC in GitHub
2021
CVE-2021-1056 (2021-01-07)
NVIDIA GPU Display Driver for Linux, all versions, contains a vulnerability in the kernel mode layer (nvidia.ko) in which it does not completely honor operating system file system permissions to provide GPU device-level isolation, which may lead to denial of service or information disclosure.
pokerfaceSad/CVE-2021-1056
CVE-2021-3019 (2021-01-04)
ffay lanproxy 0.1 allows Directory Traversal to read /../conf/config.properties to obtain credentials for a connection to the intranet.
B1anda0/CVE-2021-3019
FanqXu/CVE-2021-3019
liuxu54898/CVE-2021-3019
CVE-2021-3129 (2021-01-12)
Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.
ambionics/laravel-exploits
CVE-2021-3131 (2021-01-13)
The Web server in 1C:Enterprise 8 before 8.3.17.1851 sends base64 encoded credentials in the creds URL parameter.
jet-pentest/CVE-2021-3131
CVE-2021-3164
rmccarth/cve-2021-3164
2020
CVE-2020-0001 (2020-01-08)
In getProcessRecordLocked of ActivityManagerService.java isolated apps are not handled correctly. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android Versions: Android-8.0, Android-8.1, Android-9, and Android-10 Android ID: A-140055304
Zachinio/CVE-2020-0001
CVE-2020-0014 (2020-02-13)
It is possible for a malicious application to construct a TYPE_TOAST window manually and make that window clickable. This could lead to a local escalation of privilege with no additional execution privileges needed. User action is needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9 Android-10Android ID: A-128674520
tea9/CVE-2020-0014-Toast
CVE-2020-0022 (2020-02-13)
In reassemble_and_dispatch of packet_fragmenter.cc, there is possible out of bounds write due to an incorrect bounds calculation. This could lead to remote code execution over Bluetooth with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9 Android-10Android ID: A-143894715
marcinguy/CVE-2020-0022
leommxj/cve-2020-0022
Polo35/CVE-2020-0022
5k1l/cve-2020-0022
CVE-2020-0041 (2020-03-10)
In binder_transaction of binder.c, there is a possible out of bounds write due to an incorrect bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-145988638References: Upstream kernel
bluefrostsecurity/CVE-2020-0041
j4nn/CVE-2020-0041
minutesinch/CVE-2020-0041
minutesinch/CVE-2020-0041-Original
CVE-2020-0069 (2020-03-10)
In the ioctl handlers of the Mediatek Command Queue driver, there is a possible out of bounds write due to insufficient input sanitization and missing SELinux restrictions. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-147882143References: M-ALPS04356754
R0rt1z2/AutomatedRoot
TheRealJunior/mtk-su-reverse-cve-2020-0069
yanglingxi1993/CVE-2020-0069
quarkslab/CVE-2020-0069_poc
CVE-2020-0096 (2020-05-14)
In startActivities of ActivityStartController.java, there is a possible escalation of privilege due to a confused deputy. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9Android ID: A-145669109
wyu0hop/CVE-2020-0096
liuyun201990/StrandHogg2
tea9/CVE-2020-0096-StrandHogg2
CVE-2020-0108 (2020-08-11)
In postNotification of ServiceRecord.java, there is a possible bypass of foreground process restrictions due to an uncaught exception. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-8.1 Android-9Android ID: A-140108616
CrackerCat/ServiceCheater
CVE-2020-0113 (2020-06-10)
In sendCaptureResult of Camera3OutputUtils.cpp, there is a possible out of bounds read due to a use after free. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-9Android ID: A-150944913
XDo0/ServiceCheater
CVE-2020-0114 (2020-06-10)
In onCreateSliceProvider of KeyguardSliceProvider.java, there is a possible confused deputy due to a PendingIntent error. This could lead to local escalation of privilege that allows actions performed as the System UI, with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-147606347
tea9/CVE-2020-0114-systemui
CVE-2020-0121 (2020-06-10)
In updateUidProcState of AppOpsService.java, there is a possible permission bypass due to a logic error. This could lead to local information disclosure of location data with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-148180766
mooneee/CVE-2020-0121
CVE-2020-0551 (2020-03-12)
Load value injection in some Intel(R) Processors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access. The list of affected products is provided in intel-sa-00334: https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00334.html
bitdefender/lvi-lfb-attack-poc
CVE-2020-0557 (2020-04-15)
Insecure inherited permissions in Intel(R) PROSet/Wireless WiFi products before version 21.70 on Windows 10 may allow an authenticated user to potentially enable escalation of privilege via local access.
hessandrew/CVE-2020-0557_INTEL-SA-00338
CVE-2020-0568 (2020-04-15)
Race condition in the Intel(R) Driver and Support Assistant before version 20.1.5 may allow an authenticated user to potentially enable denial of service via local access.
hessandrew/CVE-2020-0568_INTEL-SA-00344
CVE-2020-0601 (2020-01-14)
A spoofing vulnerability exists in the way Windows CryptoAPI (Crypt32.dll) validates Elliptic Curve Cryptography (ECC) certificates.An attacker could exploit the vulnerability by using a spoofed code-signing certificate to sign a malicious executable, making it appear the file was from a trusted, legitimate source, aka 'Windows CryptoAPI Spoofing Vulnerability'.
0xxon/cve-2020-0601
0xxon/cve-2020-0601-plugin
ollypwn/CurveBall
kudelskisecurity/chainoffools
RrUZi/Awesome-CVE-2020-0601
BleepSec/CVE-2020-0601
saleemrashid/badecparams
0xxon/cve-2020-0601-utils
YoannDqr/CVE-2020-0601
thimelp/cve-2020-0601-Perl
dlee35/curveball_lua
IIICTECH/-CVE-2020-0601-ECC---EXPLOIT
Ash112121/CVE-2020-0601
gentilkiwi/curveball
Hans-MartinHannibalLauridsen/CurveBall
apodlosky/PoC_CurveBall
ioncodes/Curveball
amlweems/gringotts
aloswoya/CVE-2020-0601
talbeerysec/CurveBallDetection
david4599/CurveballCertTool
eastmountyxz/CVE-2020-0601-EXP
eastmountyxz/CVE-2018-20250-WinRAR
gremwell/cve-2020-0601_poc
bsides-rijeka/meetup-2-curveball
exploitblizzard/CVE-2020-0601-spoofkey
ShayNehmad/twoplustwo
CVE-2020-0609 (2020-01-14)
A remote code execution vulnerability exists in Windows Remote Desktop Gateway (RD Gateway) when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Windows Remote Desktop Gateway (RD Gateway) Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2020-0610.
2d4d/rdg_scanner_cve-2020-0609
ollypwn/BlueGate
MalwareTech/RDGScanner
Bechsen/CVE-2020-0609
ioncodes/BlueGate
CVE-2020-0618 (2020-02-11)
A remote code execution vulnerability exists in Microsoft SQL Server Reporting Services when it incorrectly handles page requests, aka 'Microsoft SQL Server Reporting Services Remote Code Execution Vulnerability'.
euphrat1ca/CVE-2020-0618
wortell/cve-2020-0618
CVE-2020-0624 (2020-01-14)
An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-0642.
james0x40/CVE-2020-0624
CVE-2020-0668 (2020-02-11)
An elevation of privilege vulnerability exists in the way that the Windows Kernel handles objects in memory, aka 'Windows Kernel Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-0669, CVE-2020-0670, CVE-2020-0671, CVE-2020-0672.
itm4n/SysTracingPoc
RedCursorSecurityConsulting/CVE-2020-0668
Nan3r/CVE-2020-0668
CVE-2020-0674 (2020-02-11)
A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Internet Explorer, aka 'Scripting Engine Memory Corruption Vulnerability'. This CVE ID is unique from CVE-2020-0673, CVE-2020-0710, CVE-2020-0711, CVE-2020-0712, CVE-2020-0713, CVE-2020-0767.
binaryfigments/CVE-2020-0674
maxpl0it/CVE-2020-0674-Exploit
Ken-Abruzzi/CVE-2020-0674
CVE-2020-0683 (2020-02-11)
An elevation of privilege vulnerability exists in the Windows Installer when MSI packages process symbolic links, aka 'Windows Installer Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-0686.
padovah4ck/CVE-2020-0683
CVE-2020-0688 (2020-02-11)
A remote code execution vulnerability exists in Microsoft Exchange software when the software fails to properly handle objects in memory, aka 'Microsoft Exchange Memory Corruption Vulnerability'.
random-robbie/cve-2020-0688
Jumbo-WJB/CVE-2020-0688
Ridter/cve-2020-0688
Yt1g3r/CVE-2020-0688_EXP
righter83/CVE-2020-0688
truongtn/cve-2020-0688
onSec-fr/CVE-2020-0688-Scanner
youncyb/CVE-2020-0688
zcgonvh/CVE-2020-0688
justin-p/PSForgot2kEyXCHANGE
cert-lv/CVE-2020-0688
ravinacademy/CVE-2020-0688
ktpdpro/CVE-2020-0688
w4fz5uck5/cve-2020-0688-webshell-upload-technique
murataydemir/CVE-2020-0688
zyn3rgy/ecp_slap
SLSteff/CVE-2020-0688-Scanner
MrTiz9/CVE-2020-0688
CVE-2020-0708 (2020-02-11)
A remote code execution vulnerability exists when the Windows Imaging Library improperly handles memory.To exploit this vulnerability, an attacker would first have to coerce a victim to open a specially crafted file.The security update addresses the vulnerability by correcting how the Windows Imaging Library handles memory., aka 'Windows Imaging Library Remote Code Execution Vulnerability'.
asc0t6e/CVE-2020-0708
CVE-2020-0728 (2020-02-11)
An information vulnerability exists when Windows Modules Installer Service improperly discloses file information, aka 'Windows Modules Installer Service Information Disclosure Vulnerability'.
irsl/CVE-2020-0728
CVE-2020-0753 (2020-02-11)
An elevation of privilege vulnerability exists in Windows Error Reporting (WER) when WER handles and executes files, aka 'Windows Error Reporting Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-0754.
afang5472/CVE-2020-0753-and-CVE-2020-0754
VikasVarshney/CVE-2020-0753-and-CVE-2020-0754
CVE-2020-0787 (2020-03-12)
An elevation of privilege vulnerability exists when the Windows Background Intelligent Transfer Service (BITS) improperly handles symbolic links, aka 'Windows Background Intelligent Transfer Service Elevation of Privilege Vulnerability'.
cbwang505/CVE-2020-0787-EXP-ALL-WINDOWS-VERSION
MasterSploit/CVE-2020-0787
MasterSploit/CVE-2020-0787-BitsArbitraryFileMove-master
CVE-2020-0796 (2020-03-12)
A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.
k8gege/PyLadon
Aekras1a/CVE-2020-0796-PoC
technion/DisableSMBCompression
T13nn3s/CVE-2020-0796
ollypwn/SMBGhost
joaozietolie/CVE-2020-0796-Checker
ButrintKomoni/cve-2020-0796
dickens88/cve-2020-0796-scanner
kn6869610/CVE-2020-0796
awareseven/eternalghosttest
weidutech/CVE-2020-0796-PoC
xax007/CVE-2020-0796-Scanner
Dhoomralochana/Scanners-for-CVE-2020-0796-Testing
UraSecTeam/smbee
0xtobu/CVE-2020-0796
netscylla/SMBGhost
eerykitty/CVE-2020-0796-PoC
wneessen/SMBCompScan
ioncodes/SMBGhost
laolisafe/CVE-2020-0796
gabimarti/SMBScanner
Almorabea/SMBGhost-WorkaroundApplier
IAreKyleW00t/SMBGhosts
vysecurity/CVE-2020-0796
marcinguy/CVE-2020-0796
plorinquer/cve-2020-0796
BinaryShadow94/SMBv3.1.1-scan---CVE-2020-0796
w1ld3r/SMBGhost_Scanner
wsfengfan/CVE-2020-0796
GuoKerS/aioScan_CVE-2020-0796
jiansiting/CVE-2020-0796-Scanner
maxpl0it/Unauthenticated-CVE-2020-0796-PoC
ran-sama/CVE-2020-0796
sujitawake/smbghost
julixsalas/CVE-2020-0796
insightglacier/SMBGhost_Crash_Poc
5l1v3r1/CVE-2020-0796-PoC-and-Scan
cory-zajicek/CVE-2020-0796-DoS
tripledd/cve-2020-0796-vuln
danigargu/CVE-2020-0796
ZecOps/CVE-2020-0796-LPE-POC
TinToSer/CVE-2020-0796-LPE
f1tz/CVE-2020-0796-LPE-EXP
tango-j/CVE-2020-0796
jiansiting/CVE-2020-0796
eastmountyxz/CVE-2020-0796-SMB
LabDookhtegan/CVE-2020-0796-EXP
Rvn0xsy/CVE_2020_0796_CNA
intelliroot-tech/cve-2020-0796-Scanner
ZecOps/CVE-2020-0796-RCE-POC
thelostworldFree/CVE-2020-0796
section-c/CVE-2020-0796
bacth0san96/SMBGhostScanner
DreamoneOnly/CVE-2020-0796-LPE
halsten/CVE-2020-0796
ysyyrps123/CVE-2020-0796
ysyyrps123/CVE-2020-0796-exp
exp-sky/CVE-2020-0796
Barriuso/SMBGhost_AutomateExploitation
1060275195/SMBGhost
Almorabea/SMBGhost-LPE-Metasploit-Module
ZecOps/SMBGhost-SMBleed-scanner
getdrive/smbghost
rsmudge/CVE-2020-0796-BOF
aloswoya/CVE-2020-0796-cobaltstrike-cna
codewithpradhan/SMBGhost-CVE-2020-0796-
AaronWilsonGrylls/CVE-2020-0796-POC
datntsec/CVE-2020-0796
MasterSploit/LPE---CVE-2020-0796
alexa872/CVE-2020-0796
CVE-2020-0797 (2020-03-12)
An elevation of privilege vulnerability exists when the Windows Work Folder Service improperly handles file operations, aka 'Windows Work Folder Service Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-0777, CVE-2020-0800, CVE-2020-0864, CVE-2020-0865, CVE-2020-0866, CVE-2020-0897.
bonesg/CVE-2020-0797
CVE-2020-0801 (2020-03-12)
A memory corruption vulnerability exists when Windows Media Foundation improperly handles objects in memory, aka 'Media Foundation Memory Corruption Vulnerability'. This CVE ID is unique from CVE-2020-0807, CVE-2020-0809, CVE-2020-0869.
5l1v3r1/CVE-2020-0801
CVE-2020-0890 (2020-09-11)
A denial of service vulnerability exists when Microsoft Hyper-V on a host server fails to properly validate specific malicious data from a user on a guest operating system.To exploit the vulnerability, an attacker who already has a privileged account on a guest operating system, running as a virtual machine, could run a specially crafted application.The security update addresses the vulnerability by resolving the conditions where Hyper-V would fail to handle these requests., aka 'Windows Hyper-V Denial of Service Vulnerability'. This CVE ID is unique from CVE-2020-0904.
gerhart01/hyperv_local_dos_poc
CVE-2020-0910 (2020-04-15)
A remote code execution vulnerability exists when Windows Hyper-V on a host server fails to properly validate input from an authenticated user on a guest operating system, aka 'Windows Hyper-V Remote Code Execution Vulnerability'.
inetshell/CVE-2020-0910
CVE-2020-0976 (2020-04-15)
A spoofing vulnerability exists when Microsoft SharePoint Server does not properly sanitize a specially crafted web request to an affected SharePoint server, aka 'Microsoft SharePoint Spoofing Vulnerability'. This CVE ID is unique from CVE-2020-0972, CVE-2020-0975, CVE-2020-0977.
ericzhong2010/GUI-Check-CVE-2020-0976
CVE-2020-1
full-disclosure/FDEU-CVE-2020-1FC5
CVE-2020-1015 (2020-04-15)
An elevation of privilege vulnerability exists in the way that the User-Mode Power Service (UMPS) handles objects in memory, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-0934, CVE-2020-0983, CVE-2020-1009, CVE-2020-1011.
0xeb-bp/cve-2020-1015
CVE-2020-1034 (2020-09-11)
An elevation of privilege vulnerability exists in the way that the Windows Kernel handles objects in memory, aka 'Windows Kernel Elevation of Privilege Vulnerability'.
yardenshafir/CVE-2020-1034
CVE-2020-1048 (2020-05-21)
An elevation of privilege vulnerability exists when the Windows Print Spooler service improperly allows arbitrary writing to the file system, aka 'Windows Print Spooler Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1070.
zveriu/CVE-2009-0229-PoC
shubham0d/CVE-2020-1048
Ken-Abruzzi/CVE-2020-1048
CVE-2020-1054 (2020-05-21)
An elevation of privilege vulnerability exists in Windows when the Windows kernel-mode driver fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1143.
0xeb-bp/cve-2020-1054
Iamgublin/CVE-2020-1054
KaLendsi/CVE-2020-1054
Graham382/CVE-2020-1054
CVE-2020-1066 (2020-05-21)
An elevation of privilege vulnerability exists in .NET Framework which could allow an attacker to elevate their privilege level.To exploit the vulnerability, an attacker would first have to access the local machine, and then run a malicious program.The update addresses the vulnerability by correcting how .NET Framework activates COM objects., aka '.NET Framework Elevation of Privilege Vulnerability'.
cbwang505/CVE-2020-1066-EXP
CVE-2020-1102 (2020-05-21)
A remote code execution vulnerability exists in Microsoft SharePoint when the software fails to check the source markup of an application package, aka 'Microsoft SharePoint Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2020-1023, CVE-2020-1024.
DanielRuf/snyk-js-jquery-565129
CVE-2020-1206 (2020-06-09)
An information disclosure vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Information Disclosure Vulnerability'.
ZecOps/CVE-2020-1206-POC
Info-Security-Solution-Kolkata/CVE-2020-1206-Exploit
Info-Security-Solution-Kolkata/Smbleed-CVE-2020-1206-Exploit
CVE-2020-1283 (2020-06-09)
A denial of service vulnerability exists when Windows improperly handles objects in memory, aka 'Windows Denial of Service Vulnerability'.
RedyOpsResearchLabs/CVE-2020-1283_Windows-Denial-of-Service-Vulnerability
CVE-2020-1301 (2020-06-09)
A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 1.0 (SMBv1) server handles certain requests, aka 'Windows SMB Remote Code Execution Vulnerability'.
P1kAju/CVE-2020-1301
shubham0d/CVE-2020-1301
CVE-2020-1313 (2020-06-09)
An elevation of privilege vulnerability exists when the Windows Update Orchestrator Service improperly handles file operations, aka 'Windows Update Orchestrator Service Elevation of Privilege Vulnerability'.
irsl/CVE-2020-1313
CVE-2020-1337 (2020-08-17)
An elevation of privilege vulnerability exists when the Windows Print Spooler service improperly allows arbitrary writing to the file system, aka 'Windows Print Spooler Elevation of Privilege Vulnerability'.
math1as/CVE-2020-1337-exploit
VoidSec/CVE-2020-1337
neofito/CVE-2020-1337
sailay1996/cve-2020-1337-poc
CVE-2020-1349 (2020-07-14)
A remote code execution vulnerability exists in Microsoft Outlook software when it fails to properly handle objects in memory, aka 'Microsoft Outlook Remote Code Execution Vulnerability'.
0neb1n/CVE-2020-1349
CVE-2020-1350 (2020-07-14)
A remote code execution vulnerability exists in Windows Domain Name System servers when they fail to properly handle requests, aka 'Windows DNS Server Remote Code Execution Vulnerability'.
psc4re/NSE-scripts
mr-r3b00t/CVE-2020-1350
zoomerxsec/Fake_CVE-2020-1350
T13nn3s/CVE-2020-1350
corelight/SIGRed
jmaddington/dRMM-CVE-2020-1350-response
maxpl0it/CVE-2020-1350-DoS
captainGeech42/CVE-2020-1350
connormcgarr/CVE-2020-1350
graph-inc/CVE-2020-1350
CVEmaster/CVE-2020-1350
Secuora-Org/CVE-2020-1350-checker.ps1
gdwnet/cve-2020-1350
simeononsecurity/CVE-2020-1350-Fix
CVE-2020-1362 (2020-07-14)
An elevation of privilege vulnerability exists in the way that the Windows WalletService handles objects in memory, aka 'Windows WalletService Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1344, CVE-2020-1369.
Q4n/CVE-2020-1362
CVE-2020-1472 (2020-08-17)
An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.
Tobey123/CVE-2020-1472-visualizer
SecuraBV/CVE-2020-1472
cube0x0/CVE-2020-1472
dirkjanm/CVE-2020-1472
VoidSec/CVE-2020-1472
risksense/zerologon
bb00/zer0dump
0xkami/CVE-2020-1472
NAXG/CVE-2020-1472
s0wr0b1ndef/CVE-2020-1472
harshil-shah004/zerologon-CVE-2020-1472
k8gege/CVE-2020-1472-EXP
422926799/CVE-2020-1472
scv-m/zabbix-template-CVE-2020-1472
mstxq17/cve-2020-1472
Fa1c0n35/CVE-2020-1472
Fa1c0n35/SecuraBV-CVE-2020-1472
CanciuCostin/CVE-2020-1472
0xcccc666/cve-2020-1472_Tool-collection
murataydemir/CVE-2020-1472
npocmak/CVE-2020-1472
victim10wq3/CVE-2020-1472
zeronetworks/zerologon
sv3nbeast/CVE-2020-1472
midpipps/CVE-2020-1472-Easy
hectorgie/CVE-2020-1472
johnpathe/zerologon-cve-2020-1472-notes
t31m0/CVE-2020-1472
grupooruss/CVE-2020-1472
striveben/CVE-2020-1472
Fa1c0n35/CVE-2020-1472-02-
Whippet0/CVE-2020-1472
WiIs0n/Zerologon_CVE-2020-1472
Privia-Security/ADZero
Ken-Abruzzi/cve-2020-1472
rhymeswithmogul/Set-ZerologonMitigation
shanfenglan/cve-2020-1472
maikelnight/zerologon
CPO-EH/CVE-2020-1472_ZeroLogonChecker
puckiestyle/CVE-2020-1472
mingchen-script/CVE-2020-1472-visualizer
Qazeer/dirkjanm_CVE-2020-1472_static_binaries
JayP232/The_big_Zero
b1ack0wl/CVE-2020-1472
SaharAttackit/CVE-2020-1472
wrathfulDiety/zerologon
CVE-2020-1493 (2020-08-17)
An information disclosure vulnerability exists when attaching files to Outlook messages, aka 'Microsoft Outlook Information Disclosure Vulnerability'.
0neb1n/CVE-2020-1493
CVE-2020-1611 (2020-01-15)
A Local File Inclusion vulnerability in Juniper Networks Junos Space allows an attacker to view all files on the target when the device receives malicious HTTP packets. This issue affects: Juniper Networks Junos Space versions prior to 19.4R1.
Ibonok/CVE-2020-1611
CVE-2020-1764 (2020-03-26)
A hard-coded cryptographic key vulnerability in the default configuration file was found in Kiali, all versions prior to 1.15.1. A remote attacker could abuse this flaw by creating their own JWT signed tokens and bypass Kiali authentication mechanisms, possibly gaining privileges to view and alter the Istio configuration.
jpts/cve-2020-1764-poc
CVE-2020-1937 (2020-02-24)
Kylin has some restful apis which will concatenate SQLs with the user input string, a user is likely to be able to run malicious database queries.
shanika04/apache_kylin
CVE-2020-1938 (2020-02-24)
When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.
0nise/CVE-2020-1938
xindongzhuaizhuai/CVE-2020-1938
nibiwodong/CNVD-2020-10487-Tomcat-ajp-POC
bkfish/CNVD-2020-10487-Tomcat-Ajp-lfi-Scanner
laolisafe/CVE-2020-1938
DaemonShao/CVE-2020-1938
sv3nbeast/CVE-2020-1938-Tomact-file_include-file_read
fairyming/CVE-2020-1938
dacade/CVE-2020-1938
woaiqiukui/CVE-2020-1938TomcatAjpScanner
fatal0/tomcat-cve-2020-1938-check
ze0r/GhostCat-LFI-exp
delsadan/CNVD-2020-10487-Bulk-verification
00theway/Ghostcat-CNVD-2020-10487
shaunmclernon/ghostcat-verification
Zaziki1337/Ghostcat-CVE-2020-1938
w4fz5uck5/CVE-2020-1938-Clean-Version
Just1ceP4rtn3r/CVE-2020-1938-Tool
ZhengHaoCHeng/CNVD-2020-10487
I-Runtime-Error/CVE-2020-1938
Umesh2807/Ghostcat
MateoSec/ghostcatch
kukudechen-chen/cve-2020-1938
CVE-2020-1947 (2020-03-11)
In Apache ShardingSphere(incubator) 4.0.0-RC3 and 4.0.0, the ShardingSphere's web console uses the SnakeYAML library for parsing YAML inputs to load datasource configuration. SnakeYAML allows to unmarshal data to a Java type By using the YAML tag. Unmarshalling untrusted data can lead to security flaws of RCE.
5l1v3r1/CVE-2020-1947
jas502n/CVE-2020-1947
wsfengfan/CVE-2020-1947
shadowsock5/ShardingSphere_CVE-2020-1947
HexChristmas/CVE-2020-1947
CVE-2020-1948 (2020-07-14)
This vulnerability can affect all Dubbo users stay on version 2.7.6 or lower. An attacker can send RPC requests with unrecognized service name or method name along with some malicious parameter payloads. When the malicious parameter is deserialized, it will execute some malicious code. More details can be found below.
ctlyz123/CVE-2020-1948
txrw/Dubbo-CVE-2020-1948
M3g4Byt3/cve-2020-1948-poc
L0kiii/Dubbo-deserialization
CVE-2020-1958 (2020-04-01)
When LDAP authentication is enabled in Apache Druid 0.17.0, callers of Druid APIs with a valid set of LDAP credentials can bypass the credentialsValidator.userSearch filter barrier that determines if a valid LDAP user is allowed to authenticate with Druid. They are still subject to role-based authorization checks, if configured. Callers of Druid APIs can also retrieve any LDAP attribute values of users that exist on the LDAP server, so long as that information is visible to the Druid server. This information disclosure does not require the caller itself to be a valid LDAP user.
ggolawski/CVE-2020-1958
CVE-2020-1967 (2020-04-21)
Server or client applications that call the SSL_check_chain() function during or after a TLS 1.3 handshake may crash due to a NULL pointer dereference as a result of incorrect handling of the "signature_algorithms_cert" TLS extension. The crash occurs if an invalid or unrecognised signature algorithm is received from the peer. This could be exploited by a malicious peer in a Denial of Service attack. OpenSSL version 1.1.1d, 1.1.1e, and 1.1.1f are affected by this issue. This issue did not affect OpenSSL versions prior to 1.1.1d. Fixed in OpenSSL 1.1.1g (Affected 1.1.1d-1.1.1f).
irsl/CVE-2020-1967
CVE-2020-1971 (2020-12-08)
The X.509 GeneralName type is a generic type for representing different types of names. One of those name types is known as EDIPartyName. OpenSSL provides a function GENERAL_NAME_cmp which compares different instances of a GENERAL_NAME to see if they are equal or not. This function behaves incorrectly when both GENERAL_NAMEs contain an EDIPARTYNAME. A NULL pointer dereference and a crash may occur leading to a possible denial of service attack. OpenSSL itself uses the GENERAL_NAME_cmp function for two purposes: 1) Comparing CRL distribution point names between an available CRL and a CRL distribution point embedded in an X509 certificate 2) When verifying that a timestamp response token signer matches the timestamp authority name (exposed via the API functions TS_RESP_verify_response and TS_RESP_verify_token) If an attacker can control both items being compared then that attacker could trigger a crash. For example if the attacker can trick a client or server into checking a malicious certificate against a malicious CRL then this may occur. Note that some applications automatically download CRLs based on a URL embedded in a certificate. This checking happens prior to the signatures on the certificate and CRL being verified. OpenSSL's s_server, s_client and verify tools have support for the "-crl_download" option which implements automatic CRL downloading and this attack has been demonstrated to work against those tools. Note that an unrelated bug means that affected versions of OpenSSL cannot parse or construct correct encodings of EDIPARTYNAME. However it is possible to construct a malformed EDIPARTYNAME that OpenSSL's parser will accept and hence trigger this attack. All OpenSSL 1.1.1 and 1.0.2 versions are affected by this issue. Other OpenSSL releases are out of support and have not been checked. Fixed in OpenSSL 1.1.1i (Affected 1.1.1-1.1.1h). Fixed in OpenSSL 1.0.2x (Affected 1.0.2-1.0.2w).
MBHudson/CVE-2020-1971
CVE-2020-1983 (2020-04-22)
A use after free vulnerability in ip_reass() in ip_input.c of libslirp 4.2.0 and prior releases allows crafted packets to cause a denial of service.
wuzuowei/CVE-2020-1983
CVE-2020-2034 (2020-07-08)
An OS Command Injection vulnerability in the PAN-OS GlobalProtect portal allows an unauthenticated network based attacker to execute arbitrary OS commands with root privileges. An attacker requires some knowledge of the firewall to exploit this issue. This issue can not be exploited if GlobalProtect portal feature is not enabled. This issue impacts PAN-OS 9.1 versions earlier than PAN-OS 9.1.3; PAN-OS 8.1 versions earlier than PAN-OS 8.1.15; PAN-OS 9.0 versions earlier than PAN-OS 9.0.9; all versions of PAN-OS 8.0 and PAN-OS 7.1. Prisma Access services are not impacted by this vulnerability.
blackhatethicalhacking/CVE-2020-2034-POC
CVE-2020-2333
section-c/CVE-2020-2333
CVE-2020-2546 (2020-01-15)
Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Application Container - JavaEE). Supported versions that are affected are 10.3.6.0.0 and 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
hktalent/CVE_2020_2546
CVE-2020-2551 (2020-01-15)
Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
0xn0ne/weblogicScanner
hktalent/CVE-2020-2551
0nise/CVE-2020-2551
Y4er/CVE-2020-2551
cnsimo/CVE-2020-2551
zzwlpx/weblogicPoc
Dido1960/Weblogic-CVE-2020-2551-To-Internet
CVE-2020-2555 (2020-01-15)
Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Caching,CacheStore,Invocation). Supported versions that are affected are 3.7.1.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle Coherence. Successful attacks of this vulnerability can result in takeover of Oracle Coherence. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
Hu3sky/CVE-2020-2555
wsfengfan/CVE-2020-2555
0nise/CVE-2020-2555
Y4er/CVE-2020-2555
Maskhe/cve-2020-2555
Uvemode/CVE-2020-2555
CVE-2020-2655 (2020-01-15)
Vulnerability in the Java SE product of Oracle Java SE (component: JSSE). Supported versions that are affected are Java SE: 11.0.5 and 13.0.1. Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTPS to compromise Java SE. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Java SE accessible data as well as unauthorized read access to a subset of Java SE accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.0 Base Score 4.8 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N).
RUB-NDS/CVE-2020-2655-DemoServer
CVE-2020-2883 (2020-04-15)
Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
Y4er/CVE-2020-2883
MagicZer0/Weblogic_CVE-2020-2883_POC
ZZZWD/CVE-2020-2883
Y4er/WebLogic-Shiro-shell
FancyDoesSecurity/CVE-2020-2883
Al1ex/CVE-2020-2883
CVE-2020-2978 (2020-07-15)
Vulnerability in the Oracle Database - Enterprise Edition component of Oracle Database Server. Supported versions that are affected are 12.1.0.2, 12.2.0.1, 18c and 19c. Easily exploitable vulnerability allows high privileged attacker having DBA role account privilege with network access via Oracle Net to compromise Oracle Database - Enterprise Edition. While the vulnerability is in Oracle Database - Enterprise Edition, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Database - Enterprise Edition accessible data. CVSS 3.1 Base Score 4.1 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:N).
emad-almousa/CVE-2020-2978
CVE-2020-3153 (2020-02-19)
A vulnerability in the installer component of Cisco AnyConnect Secure Mobility Client for Windows could allow an authenticated local attacker to copy user-supplied files to system level directories with system level privileges. The vulnerability is due to the incorrect handling of directory paths. An attacker could exploit this vulnerability by creating a malicious file and copying the file to a system directory. An exploit could allow the attacker to copy malicious files to arbitrary locations with system level privileges. This could include DLL pre-loading, DLL hijacking, and other related attacks. To exploit this vulnerability, the attacker needs valid credentials on the Windows system.
shubham0d/CVE-2020-3153
raspberry-pie/CVE-2020-3153
goichot/CVE-2020-3153
CVE-2020-3161 (2020-04-15)
A vulnerability in the web server for Cisco IP Phones could allow an unauthenticated, remote attacker to execute code with root privileges or cause a reload of an affected IP phone, resulting in a denial of service (DoS) condition. The vulnerability is due to a lack of proper input validation of HTTP requests. An attacker could exploit this vulnerability by sending a crafted HTTP request to the web server of a targeted device. A successful exploit could allow the attacker to remotely execute code with root privileges or cause a reload of an affected IP phone, resulting in a DoS condition.
abood05972/CVE-2020-3161
uromulou/CVE-2020-3161-REMAKE
CVE-2020-3187 (2020-05-06)
A vulnerability in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct directory traversal attacks and obtain read and delete access to sensitive files on a targeted system. The vulnerability is due to a lack of proper input validation of the HTTP URL. An attacker could exploit this vulnerability by sending a crafted HTTP request containing directory traversal character sequences. An exploit could allow the attacker to view or delete arbitrary files on the targeted system. When the device is reloaded after exploitation of this vulnerability, any files that were deleted are restored. The attacker can only view and delete files within the web services file system. This file system is enabled when the affected device is configured with either WebVPN or AnyConnect features. This vulnerability can not be used to obtain access to ASA or FTD system files or underlying operating system (OS) files. Reloading the affected device will restore all files within the web services file system.
pry0cc/CVE-2020-3187
Ph4nt0m-b/CVE-2020-3187
CVE-2020-3433 (2020-08-17)
A vulnerability in the interprocess communication (IPC) channel of Cisco AnyConnect Secure Mobility Client for Windows could allow an authenticated, local attacker to perform a DLL hijacking attack. To exploit this vulnerability, the attacker would need to have valid credentials on the Windows system. The vulnerability is due to insufficient validation of resources that are loaded by the application at run time. An attacker could exploit this vulnerability by sending a crafted IPC message to the AnyConnect process. A successful exploit could allow the attacker to execute arbitrary code on the affected machine with SYSTEM privileges. To exploit this vulnerability, the attacker would need to have valid credentials on the Windows system.
goichot/CVE-2020-3433
CVE-2020-3452 (2020-07-22)
A vulnerability in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct directory traversal attacks and read sensitive files on a targeted system. The vulnerability is due to a lack of proper input validation of URLs in HTTP requests processed by an affected device. An attacker could exploit this vulnerability by sending a crafted HTTP request containing directory traversal character sequences to an affected device. A successful exploit could allow the attacker to view arbitrary files within the web services file system on the targeted device. The web services file system is enabled when the affected device is configured with either WebVPN or AnyConnect features. This vulnerability cannot be used to obtain access to ASA or FTD system files or underlying operating system (OS) files.
XDev05/CVE-2020-3452-PoC
Loneyers/cve-2020-3452
PR3R00T/CVE-2020-3452-Cisco-Scanner
mr-r3b00t/CVE-2020-3452
foulenzer/CVE-2020-3452
Gh0st0ne/http-vuln-cve2020-3452.nse
0x5ECF4ULT/CVE-2020-3452
paran0id34/CVE-2020-3452
murataydemir/CVE-2020-3452
ludy-dev/Cisco-ASA-LFI
3ndG4me/CVE-2020-3452-Exploit
grim3/CVE-2020-3452
cygenta/CVE-2020-3452
darklotuskdb/CISCO-CVE-2020-3452-Scanner-Exploiter
CVE-2020-3766 (2020-03-25)
Adobe Genuine Integrity Service versions Version 6.4 and earlier have an insecure file permissions vulnerability. Successful exploitation could lead to privilege escalation.
hessandrew/CVE-2020-3766_APSB20-12
CVE-2020-3833 (2020-02-27)
An inconsistent user interface issue was addressed with improved state management. This issue is fixed in Safari 13.0.5. Visiting a malicious website may lead to address bar spoofing.
c0d3G33k/Safari-Address-Bar-Spoof-CVE-2020-3833-
CVE-2020-3952 (2020-04-10)
Under certain conditions, vmdir that ships with VMware vCenter Server, as part of an embedded or external Platform Services Controller (PSC), does not correctly implement access controls.
commandermoon/CVE-2020-3952
frustreated/CVE-2020-3952
guardicore/vmware_vcenter_cve_2020_3952
gelim/CVE-2020-3952
Fa1c0n35/vmware_vcenter_cve_2020_3952
CVE-2020-3956 (2020-05-20)
VMware Cloud Director 10.0.x before 10.0.0.2, 9.7.0.x before 9.7.0.5, 9.5.0.x before 9.5.0.6, and 9.1.0.x before 9.1.0.4 do not properly handle input leading to a code injection vulnerability. An authenticated actor may be able to send malicious traffic to VMware Cloud Director which may lead to arbitrary remote code execution. This vulnerability can be exploited through the HTML5- and Flex-based UIs, the API Explorer interface and API access.
aaronsvk/CVE-2020-3956
CVE-2020-3992 (2020-10-20)
OpenSLP as used in VMware ESXi (7.0 before ESXi_7.0.1-0.0.16850804, 6.7 before ESXi670-202010401-SG, 6.5 before ESXi650-202010401-SG) has a use-after-free issue. A malicious actor residing in the management network who has access to port 427 on an ESXi machine may be able to trigger a use-after-free in the OpenSLP service resulting in remote code execution.
HynekPetrak/CVE-2019-5544_CVE-2020-3992
CVE-2020-4040 (2020-06-08)
Bolt CMS before version 3.7.1 lacked CSRF protection in the preview generating endpoint. Previews are intended to be generated by the admins, developers, chief-editors, and editors, who are authorized to create content in the application. But due to lack of proper CSRF protection, unauthorized users could generate a preview. This has been fixed in Bolt 3.7.1
jpvispo/RCE-Exploit-Bolt-3.7.0-CVE-2020-4040-4041
CVE-2020-4276 (2020-03-26)
IBM WebSphere Application Server 7.0, 8.0, 8.5, and 9.0 traditional is vulnerable to a privilege escalation vulnerability when using token-based authentication in an admin request over the SOAP connector. X-Force ID: 175984.
mekoko/CVE-2020-4276
CVE-2020-4463 (2020-07-29)
IBM Maximo Asset Management 7.6.0.1 and 7.6.0.2 is vulnerable to an XML External Entity Injection (XXE) attack when processing XML data. A remote attacker could exploit this vulnerability to expose sensitive information or consume memory resources. IBM X-Force ID: 181484.
Ibonok/CVE-2020-4463
CVE-2020-5236 (2020-02-03)
Waitress version 1.4.2 allows a DOS attack When waitress receives a header that contains invalid characters. When a header like "Bad-header: xxxxxxxxxxxxxxx\x10" is received, it will cause the regular expression engine to catastrophically backtrack causing the process to use 100% CPU time and blocking any other interactions. This allows an attacker to send a single request with an invalid header and take the service offline. This issue was introduced in version 1.4.2 when the regular expression was updated to attempt to match the behaviour required by errata associated with RFC7230. The regular expression that is used to validate incoming headers has been updated in version 1.4.3, it is recommended that people upgrade to the new version of Waitress as soon as possible.
motikan2010/CVE-2020-5236
CVE-2020-5248 (2020-05-12)
GLPI before before version 9.4.6 has a vulnerability involving a default encryption key. GLPIKEY is public and is used on every instance. This means anyone can decrypt sensitive data stored using this key. It is possible to change the key before installing GLPI. But on existing instances, data must be reencrypted with the new key. Problem is we can not know which columns or rows in the database are using that; espcially from plugins. Changing the key without updating data would lend in bad password sent from glpi; but storing them again from the UI will work.
indevi0us/CVE-2020-5248
CVE-2020-5250 (2020-03-05)
In PrestaShop before version 1.7.6.4, when a customer edits their address, they can freely change the id_address in the form, and thus steal someone else's address. It is the same with CustomerForm, you are able to change the id_customer and change all information of all accounts. The problem is patched in version 1.7.6.4.
drkbcn/lblfixer_cve2020_5250
CVE-2020-5254 (2020-03-10)
In NetHack before 3.6.6, some out-of-bound values for the hilite_status option can be exploited. NetHack 3.6.6 resolves this issue.
dpmdpm2/CVE-2020-5254
CVE-2020-5260 (2020-04-14)
Affected versions of Git have a vulnerability whereby Git can be tricked into sending private credentials to a host controlled by an attacker. Git uses external "credential helper" programs to store and retrieve passwords or other credentials from secure storage provided by the operating system. Specially-crafted URLs that contain an encoded newline can inject unintended values into the credential helper protocol stream, causing the credential helper to retrieve the password for one server (e.g., good.example.com) for an HTTP request being made to another server (e.g., evil.example.com), resulting in credentials for the former being sent to the latter. There are no restrictions on the relationship between the two, meaning that an attacker can craft a URL that will present stored credentials for any host to a host of their choosing. The vulnerability can be triggered by feeding a malicious URL to git clone. However, the affected URLs look rather suspicious; the likely vector would be through systems which automatically clone URLs not visible to the user, such as Git submodules, or package systems built around Git. The problem has been patched in the versions published on April 14th, 2020, going back to v2.17.x. Anyone wishing to backport the change further can do so by applying commit 9a6bbee (the full release includes extra checks for git fsck, but that commit is sufficient to protect clients against the vulnerability). The patched versions are: 2.17.4, 2.18.3, 2.19.4, 2.20.3, 2.21.2, 2.22.3, 2.23.2, 2.24.2, 2.25.3, 2.26.1.
brompwnie/cve-2020-5260
Asgavar/CVE-2020-5260
sv3nbeast/CVE-2020-5260
CVE-2020-5267 (2020-03-19)
In ActionView before versions 6.0.2.2 and 5.2.4.2, there is a possible XSS vulnerability in ActionView's JavaScript literal escape helpers. Views that use the `j` or `escape_javascript` methods may be susceptible to XSS attacks. The issue is fixed in versions 6.0.2.2 and 5.2.4.2.
GUI/legacy-rails-CVE-2020-5267-patch
CVE-2020-5398 (2020-01-16)
In Spring Framework, versions 5.2.x prior to 5.2.3, versions 5.1.x prior to 5.1.13, and versions 5.0.x prior to 5.0.16, an application is vulnerable to a reflected file download (RFD) attack when it sets a "Content-Disposition" header in the response where the filename attribute is derived from user supplied input.
motikan2010/CVE-2020-5398
CVE-2020-5410 (2020-06-02)
Spring Cloud Config, versions 2.2.x prior to 2.2.3, versions 2.1.x prior to 2.1.9, and older unsupported versions allow applications to serve arbitrary configuration files through the spring-cloud-config-server module. A malicious user, or attacker, can send a request using a specially crafted URL that can lead to a directory traversal attack.
dead5nd/config-demo
osamahamad/CVE-2020-5410-POC
mugisyahid/ki-vuln-cve-2020-5410
CVE-2020-5421 (2020-09-18)
In Spring Framework versions 5.2.0 - 5.2.8, 5.1.0 - 5.1.17, 5.0.0 - 5.0.18, 4.3.0 - 4.3.28, and older unsupported versions, the protections against RFD attacks from CVE-2015-5211 may be bypassed depending on the browser used through the use of a jsessionid path parameter.
pandaMingx/CVE-2020-5421
CVE-2020-5837 (2020-05-11)
Symantec Endpoint Protection, prior to 14.3, may not respect file permissions when writing to log files that are replaced by symbolic links, which can lead to a potential elevation of privilege.
RedyOpsResearchLabs/SEP-14.2-Arbitrary-Write
CVE-2020-5844 (2020-03-16)
index.php?sec=godmode/extensions&sec2=extensions/files_repo in Pandora FMS v7.0 NG allows authenticated administrators to upload malicious PHP scripts, and execute them via base64 decoding of the file location. This affects v7.0NG.742_FIX_PERL2020.
TheCyberGeek/CVE-2020-5844
CVE-2020-5902 (2020-07-01)
In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.
dwisiswant0/CVE-2020-5902
aqhmal/CVE-2020-5902-Scanner
jas502n/CVE-2020-5902
ar0dd/CVE-2020-5902
yassineaboukir/CVE-2020-5902
rwincey/CVE-2020-5902-NSE
Un4gi/CVE-2020-5902
nsflabs/CVE-2020-5902
yasserjanah/CVE-2020-5902
JaneMandy/CVE-2020-5902
JSec1337/RCE-CVE-2020-5902
dunderhay/CVE-2020-5902
r0ttenbeef/cve-2020-5902
sv3nbeast/CVE-2020-5902_RCE
cybersecurityworks553/scanner-CVE-2020-5902
lijiaxing1997/CVE-2020-5902-POC-EXP
qlkwej/poc-CVE-2020-5902
Zinkuth/F5-BIG-IP-CVE-2020-5902
0xAbdullah/CVE-2020-5902
jinnywc/CVE-2020-5902
GoodiesHQ/F5-Patch
jiansiting/CVE-2020-5902
wdlid/CVE-2020-5902-fix
Any3ite/CVE-2020-5902-F5BIG
k3nundrum/CVE-2020-5902
inho28/CVE-2020-5902-F5-BIGIP
cristiano-corrado/f5_scanner
ajdumanhug/CVE-2020-5902
zhzyker/CVE-2020-5902
GovindPalakkal/EvilRip
dnerzker/CVE-2020-5902
renanhsilva/checkvulnCVE2020590
halencarjunior/f5scan
deepsecurity-pe/GoF5-CVE-2020-5902
Shu1L/CVE-2020-5902-fofa-scan
d4rk007/F5-Big-IP-CVE-2020-5902-mass-exploiter
TheCyberViking/CVE-2020-5902-Vuln-Checker
itsjeffersonli/CVE-2020-5902
MrCl0wnLab/checker-CVE-2020-5902
qiong-qi/CVE-2020-5902-POC
theLSA/f5-bigip-rce-cve-2020-5902
pwnhacker0x18/CVE-2020-5902-Mass
Al1ex/CVE-2020-5902
momika233/cve-2020-5902
rockmelodies/CVE-2020-5902-rce-gui
f5devcentral/cve-2020-5902-ioc-bigip-checker
corelight/CVE-2020-5902-F5BigIP
PushpenderIndia/CVE-2020-5902-Scanner
murataydemir/CVE-2020-5902
superzerosec/cve-2020-5902
ludy-dev/BIG-IP-F5-TMUI-RCE-Vulnerability
CVE-2020-5903 (2020-07-01)
In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, a Cross-Site Scripting (XSS) vulnerability exists in an undisclosed page of the BIG-IP Configuration utility.
ltvthang/CVE-2020-5903
CVE-2020-6207 (2020-03-10)
SAP Solution Manager (User Experience Monitoring), version- 7.2, due to Missing Authentication Check does not perform any authentication for a service resulting in complete compromise of all SMDAgents connected to the Solution Manager.
chipik/SAP_EEM_CVE-2020-6207
CVE-2020-6286 (2020-07-14)
The insufficient input path validation of certain parameter in the web service of SAP NetWeaver AS JAVA (LM Configuration Wizard), versions - 7.30, 7.31, 7.40, 7.50, allows an unauthenticated attacker to exploit a method to download zip files to a specific directory, leading to Path Traversal.
murataydemir/CVE-2020-6286
CVE-2020-6287 (2020-07-14)
SAP NetWeaver AS JAVA (LM Configuration Wizard), versions - 7.30, 7.31, 7.40, 7.50, does not perform an authentication check which allows an attacker without prior authentication to execute configuration tasks to perform critical actions against the SAP Java system, including the ability to create an administrative user, and therefore compromising Confidentiality, Integrity and Availability of the system, leading to Missing Authentication Check.
chipik/SAP_RECON
duc-nt/CVE-2020-6287-exploit
Onapsis/CVE-2020-6287_RECON-scanner
ynsmroztas/CVE-2020-6287-Sap-Add-User
murataydemir/CVE-2020-6287
CVE-2020-6308 (2020-10-20)
SAP BusinessObjects Business Intelligence Platform (Web Services) versions - 410, 420, 430, allows an unauthenticated attacker to inject arbitrary values as CMS parameters to perform lookups on the internal network which is otherwise not accessible externally. On successful exploitation, attacker can scan internal network to determine internal infrastructure and gather information for further attacks like remote file inclusion, retrieve server files, bypass firewall and force the vulnerable server to perform malicious requests, resulting in a Server-Side Request Forgery vulnerability.
Mulvun/CVE-2020-6308-mass-exploiter
InitRoot/CVE-2020-6308-PoC
CVE-2020-6418 (2020-02-27)
Type confusion in V8 in Google Chrome prior to 80.0.3987.122 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.
ChoKyuWon/CVE-2020-6418
Goyotan/CVE-2020-6418-PoC
CVE-2020-6468 (2020-05-20)
Type confusion in V8 in Google Chrome prior to 83.0.4103.61 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.
Goyotan/CVE-2020-6468-PoC
CVE-2020-6514 (2020-07-22)
Inappropriate implementation in WebRTC in Google Chrome prior to 84.0.4147.89 allowed an attacker in a privileged network position to potentially exploit heap corruption via a crafted SCTP stream.
cudi1999/CVE-2020-6514
CVE-2020-6519 (2020-07-22)
Policy bypass in CSP in Google Chrome prior to 84.0.4147.89 allowed a remote attacker to bypass content security policy via a crafted HTML page.
PerimeterX/CVE-2020-6519
CVE-2020-6650 (2020-03-23)
UPS companion software v1.05 & Prior is affected by ‘Eval Injection’ vulnerability. The software does not neutralize or incorrectly neutralizes code syntax before using the input in a dynamic evaluation call e.g.”eval” in “Update Manager” class when software attempts to see if there are updates available. This results in arbitrary code execution on the machine where software is installed.
RavSS/Eaton-UPS-Companion-Exploit
CVE-2020-6861 (2020-05-06)
A flawed protocol design in the Ledger Monero app before 1.5.1 for Ledger Nano and Ledger S devices allows a local attacker to extract the master spending key by sending crafted messages to this app selected on a PIN-entered Ledger connected to a host PC.
ph4r05/ledger-app-monero-1.42-vuln
CVE-2020-6888
section-c/CVE-2020-6888
CVE-2020-7048 (2020-01-16)
The WordPress plugin, WP Database Reset through 3.1, contains a flaw that allowed any unauthenticated user to reset any table in the database to the initial WordPress set-up state (deleting all site content stored in that table), as demonstrated by a wp-admin/admin-post.php?db-reset-tables[]=comments URI.
ElmouradiAmine/CVE-2020-7048
CVE-2020-7200 (2020-12-18)
A potential security vulnerability has been identified in HPE Systems Insight Manager (SIM) version 7.6. The vulnerability could be exploited to allow remote code execution.
alexfrancow/CVE-2020-7200
CVE-2020-7209 (2020-02-12)
LinuxKI v6.0-1 and earlier is vulnerable to an remote code execution which is resolved in release 6.0-2.
cwinfosec/CVE-2020-7209
CVE-2020-7246 (2020-01-21)
A remote code execution (RCE) vulnerability exists in qdPM 9.1 and earlier. An attacker can upload a malicious PHP code file via the profile photo functionality, by leveraging a path traversal vulnerability in the users['photop_preview'] delete photo feature, allowing bypass of .htaccess protection. NOTE: this issue exists because of an incomplete fix for CVE-2015-3884.
lnxcrew/CVE-2020-7246
CVE-2020-7247 (2020-01-29)
smtp_mailaddr in smtp_session.c in OpenSMTPD 6.6, as used in OpenBSD 6.6 and other products, allows remote attackers to execute arbitrary commands as root via a crafted SMTP session, as demonstrated by shell metacharacters in a MAIL FROM field. This affects the "uncommented" default configuration. The issue exists because of an incorrect return value upon failure of input validation.
FiroSolutions/cve-2020-7247-exploit
superzerosec/cve-2020-7247
r0lh/CVE-2020-7247
CVE-2020-7283 (2020-07-03)
Privilege Escalation vulnerability in McAfee Total Protection (MTP) before 16.0.R26 allows local users to create and edit files via symbolic link manipulation in a location they would otherwise not have access to. This is achieved through running a malicious script or program on the target machine.
RedyOpsResearchLabs/CVE-2020-7283-McAfee-Total-Protection-MTP-16.0.R26-EoP
CVE-2020-7471 (2020-02-03)
Django 1.11 before 1.11.28, 2.2 before 2.2.10, and 3.0 before 3.0.3 allows SQL Injection if untrusted data is used as a StringAgg delimiter (e.g., in Django applications that offer downloads of data as a series of rows with a user-specified column delimiter). By passing a suitably crafted delimiter to a contrib.postgres.aggregates.StringAgg instance, it was possible to break escaping and inject malicious SQL.
Saferman/CVE-2020-7471
secoba/DjVul_StringAgg
SNCKER/CVE-2020-7471
victomteng1997/cve-2020-7471-Time_Blind_SQLi-
CVE-2020-7473 (2020-05-07)
In certain situations, all versions of Citrix ShareFile StorageZones (aka storage zones) Controller, including the most recent 5.10.x releases as of May 2020, allow unauthenticated attackers to access the documents and folders of ShareFile users. NOTE: unlike most CVEs, exploitability depends on the product version that was in use when a particular setup step was performed, NOT the product version that is in use during a current assessment of a CVE consumer's product inventory. Specifically, the vulnerability can be exploited if a storage zone was created by one of these product versions: 5.9.0, 5.8.0, 5.7.0, 5.6.0, 5.5.0, or earlier. This CVE differs from CVE-2020-8982 and CVE-2020-8983 but has essentially the same risk.
DimitriNL/CTX-CVE-2020-7473
CVE-2020-7661 (2020-06-04)
all versions of url-regex are vulnerable to Regular Expression Denial of Service. An attacker providing a very long string in String.test can cause a Denial of Service.
niftylettuce/url-regex-safe
CVE-2020-7693 (2020-07-09)
Incorrect handling of Upgrade header with the value websocket leads in crashing of containers hosting sockjs apps. This affects the package sockjs before 0.3.20.
andsnw/sockjs-dos-py
CVE-2020-7799 (2020-01-28)
An issue was discovered in FusionAuth before 1.11.0. An authenticated user, allowed to edit e-mail templates (Home -> Settings -> Email Templates) or themes (Home -> Settings -> Themes), can execute commands on the underlying operating system by abusing freemarker.template.utility.Execute in the Apache FreeMarker engine that processes custom templates.
Pikaqi/cve-2020-7799
ianxtianxt/CVE-2020-7799
CVE-2020-7897
mooneee/cve-2020-7897
CVE-2020-7931 (2020-01-23)
In JFrog Artifactory 5.x and 6.x, insecure FreeMarker template processing leads to remote code execution, e.g., by modifying a .ssh/authorized_keys file. Patches are available for various versions between 5.11.8 and 6.16.0. The issue exists because use of the DefaultObjectWrapper class makes certain Java functions accessible to a template.
gquere/CVE-2020-7931
CVE-2020-7934 (2020-01-28)
In LifeRay Portal CE 7.1.0 through 7.2.1 GA2, the First Name, Middle Name, and Last Name fields for user accounts in MyAccountPortlet are all vulnerable to a persistent XSS issue. Any user can modify these fields with a particular XSS payload, and it will be stored in the database. The payload will then be rendered when a user utilizes the search feature to search for other users (i.e., if a user with modified fields occurs in the search results). This issue was fixed in Liferay Portal CE version 7.3.0 GA1.
3ndG4me/liferay-xss-7.2.1GA2-poc-report-CVE-2020-7934
CVE-2020-7961 (2020-03-20)
Deserialization of Untrusted Data in Liferay Portal prior to 7.2.1 CE GA2 allows remote attackers to execute arbitrary code via JSON web services (JSONWS).
mzer0one/CVE-2020-7961-POC
wcxxxxx/CVE-2020-7961
thelostworldFree/CVE-2020-7961-payloads
shacojx/GLiferay
shacojx/POC-CVE-2020-7961-Token-iterate
Udyz/CVE-2020-7961-Mass
ShutdownRepo/CVE-2020-7961
CVE-2020-7980 (2020-01-25)
Intellian Aptus Web 1.24 allows remote attackers to execute arbitrary OS commands via the Q field within JSON data to the cgi-bin/libagent.cgi URI. NOTE: a valid sid cookie for a login to the intellian default account might be needed.
Xh4H/Satellian-CVE-2020-7980
CVE-2020-8004 (2020-04-06)
STMicroelectronics STM32F1 devices have Incorrect Access Control.
wuxx/CVE-2020-8004
CVE-2020-8012 (2020-02-17)
CA Unified Infrastructure Management (Nimsoft/UIM) 9.20 and below contains a buffer overflow vulnerability in the robot (controller) component. A remote attacker can execute arbitrary code.
wetw0rk/Exploit-Development
CVE-2020-8103 (2020-06-05)
A vulnerability in the improper handling of symbolic links in Bitdefender Antivirus Free can allow an unprivileged user to substitute a quarantined file, and restore it to a privileged location. This issue affects Bitdefender Antivirus Free versions prior to 1.0.17.178.
RedyOpsResearchLabs/-CVE-2020-8103-Bitdefender-Antivirus-Free-EoP
CVE-2020-8163 (2020-07-02)
The is a code injection vulnerability in versions of Rails prior to 5.0.1 that wouldallow an attacker who controlled the `locals` argument of a `render` call to perform a RCE.
sh286/CVE-2020-8163
h4ms1k/CVE-2020-8163
CVE-2020-8165 (2020-06-19)
A deserialization of untrusted data vulnernerability exists in rails < 5.2.4.3, rails < 6.0.3.1 that can allow an attacker to unmarshal user-provided objects in MemCacheStore and RedisCacheStore potentially resulting in an RCE.
masahiro331/CVE-2020-8165
umiterkol/CVE-2020-8165--Auto-Shell
taipansec/CVE-2020-8165
hybryx/CVE-2020-8165
macosta-42/CVE-2020-8165
AssassinUKG/CVE-2020-8165
progfay/CVE-2020-8165
CVE-2020-8175 (2020-07-24)
Uncontrolled resource consumption in `jpeg-js` before 0.4.0 may allow attacker to launch denial of service attacks using specially a crafted JPEG image.
sysollie/get-pixels-updated
sysollie/save-pixels-updated
CVE-2020-8193 (2020-07-10)
Improper access control in Citrix ADC and Citrix Gateway versions before 13.0-58.30, 12.1-57.18, 12.0-63.21, 11.1-64.14 and 10.5-70.18 and Citrix SDWAN WAN-OP versions before 11.1.1a, 11.0.3d and 10.2.7 allows unauthenticated access to certain URL endpoints.
jas502n/CVE-2020-8193
Airboi/Citrix-ADC-RCE-CVE-2020-8193
Zeop-CyberSec/citrix_adc_netscaler_lfi
PR3R00T/CVE-2020-8193-Citrix-Scanner
ctlyz123/CVE-2020-8193
CVE-2020-8209 (2020-08-17)
Improper access control in Citrix XenMobile Server 10.12 before RP2, Citrix XenMobile Server 10.11 before RP4, Citrix XenMobile Server 10.10 before RP6 and Citrix XenMobile Server before 10.9 RP5 and leads to the ability to read arbitrary files.
B1anda0/CVE-2020-8209
CVE-2020-8218 (2020-07-30)
A code injection vulnerability exists in Pulse Connect Secure <9.1R8 that allows an attacker to crafted a URI to perform an arbitrary code execution via the admin web interface.
withdk/pulse-gosecure-rce-poc
CVE-2020-8241 (2020-10-28)
A vulnerability in the Pulse Secure Desktop Client < 9.1R9 could allow the attacker to perform a MITM Attack if end users are convinced to connect to a malicious server.
withdk/pulse-secure-vpn-mitm-research
CVE-2020-8277 (2020-11-18)
A Node.js application that allows an attacker to trigger a DNS request for a host of their choice could trigger a Denial of Service in versions < 15.2.1, < 14.15.1, and < 12.19.1 by getting the application to resolve a DNS record with a larger number of responses. This is fixed in 15.2.1, 14.15.1, and 12.19.1.
masahiro331/CVE-2020-8277
CVE-2020-8287 (2021-01-06)
Node.js versions before 10.23.1, 12.20.1, 14.15.4, 15.5.1 allow two copies of a header field in an HTTP request (for example, two Transfer-Encoding header fields). In this case, Node.js identifies the first header field and ignores the second. This can lead to HTTP Request Smuggling.
progfay/nodejs-http-transfer-encoding-smuggling-poc
CVE-2020-8289 (2020-12-26)
Backblaze for Windows before 7.0.1.433 and Backblaze for macOS before 7.0.1.434 suffer from improper certificate validation in `bztransmit` helper due to hardcoded whitelist of strings in URLs where validation is disabled leading to possible remote code execution via client update functionality.
geffner/CVE-2020-8289
CVE-2020-8290 (2020-12-26)
Backblaze for Windows and Backblaze for macOS before 7.0.0.439 suffer from improper privilege management in `bztransmit` helper due to lack of permission handling and validation before creation of client update directories allowing for local escalation of privilege via rogue client update binary.
geffner/CVE-2020-8290
CVE-2020-8417 (2020-01-28)
The Code Snippets plugin before 2.14.0 for WordPress allows CSRF because of the lack of a Referer check on the import menu.
vulncrate/wp-codesnippets-cve-2020-8417
waleweewe12/CVE-2020-8417
Rapidsafeguard/codesnippets_CVE-2020-8417
CVE-2020-8437 (2020-03-02)
The bencoding parser in BitTorrent uTorrent through 3.5.5 (build 45505) misparses nested bencoded dictionaries, which allows a remote attacker to cause a denial of service.
guywhataguy/uTorrent-CVE-2020-8437
CVE-2020-8515 (2020-02-01)
DrayTek Vigor2960 1.3.1_Beta, Vigor3900 1.4.4_Beta, and Vigor300B 1.3.3_Beta, 1.4.2.1_Beta, and 1.4.4_Beta devices allow remote code execution as root (without authentication) via shell metacharacters to the cgi-bin/mainfunction.cgi URI. This issue has been fixed in Vigor3900/2960/300B v1.5.1.
imjdl/CVE-2020-8515-PoC
CVE-2020-8554
rancher/externalip-webhook
jrmurray000/CVE-2020-8554
twistlock/k8s-cve-2020-8554-mitigations
CVE-2020-8558 (2020-07-27)
The Kubelet and kube-proxy components in versions 1.1.0-1.16.10, 1.17.0-1.17.6, and 1.18.0-1.18.3 were found to contain a security issue which allows adjacent hosts to reach TCP and UDP services bound to 127.0.0.1 running on the node or in the node's network namespace. Such a service is generally thought to be reachable only by other processes on the same host, but due to this defeect, could be reachable by other hosts on the same LAN as the node, or by containers running on the same node as the service.
tabbysable/POC-2020-8558
rhysemmas/martian-packets
CVE-2020-8559 (2020-07-22)
The Kubernetes kube-apiserver in versions v1.6-v1.15, and versions prior to v1.16.13, v1.17.9 and v1.18.6 are vulnerable to an unvalidated redirect on proxied upgrade requests that could allow an attacker to escalate privileges from a node compromise to a full cluster compromise.
tabbysable/POC-2020-8559
tdwyer/CVE-2020-8559
CVE-2020-8597 (2020-02-03)
eap.c in pppd in ppp 2.4.2 through 2.4.8 has an rhostname buffer overflow in the eap_request and eap_response functions.
marcinguy/CVE-2020-8597
WinMin/CVE-2020-8597
Dilan-Diaz/Point-to-Point-Protocol-Daemon-RCE-Vulnerability-CVE-2020-8597-
CVE-2020-8617 (2020-05-19)
Using a specially-crafted message, an attacker may potentially cause a BIND server to reach an inconsistent state if the attacker knows (or successfully guesses) the name of a TSIG key used by the server. Since BIND, by default, configures a local session key even on servers whose configuration does not otherwise make use of it, almost all current BIND servers are vulnerable. In releases of BIND dating from March 2018 and after, an assertion check in tsig.c detects this inconsistent state and deliberately exits. Prior to the introduction of the check the server would continue operating in an inconsistent state, with potentially harmful results.
knqyf263/CVE-2020-8617
rmkn/cve-2020-8617
CVE-2020-8635 (2020-03-06)
Wing FTP Server v6.2.3 for Linux, macOS, and Solaris sets insecure permissions on installation directories and configuration files. This allows local users to arbitrarily create FTP users with full privileges, and escalate privileges within the operating system by modifying system files.
Al1ex/CVE-2020-8635
CVE-2020-8644 (2020-02-05)
PlaySMS before 1.4.3 does not sanitize inputs from a malicious string.
FancyDoesSecurity/CVE-2020-8644
CVE-2020-8809 (2020-02-25)
Gurux GXDLMS Director prior to 8.5.1905.1301 downloads updates to add-ins and OBIS code over an unencrypted HTTP connection. A man-in-the-middle attacker can prompt the user to download updates by modifying the contents of gurux.fi/obis/files.xml and gurux.fi/updates/updates.xml. Then, the attacker can modify the contents of downloaded files. In the case of add-ins (if the user is using those), this will lead to code execution. In case of OBIS codes (which the user is always using as they are needed to communicate with the energy meters), this can lead to code execution when combined with CVE-2020-8810.
seqred-s-a/gxdlmsdirector-cve
CVE-2020-8813 (2020-02-21)
graph_realtime.php in Cacti 1.2.8 allows remote attackers to execute arbitrary OS commands via shell metacharacters in a cookie, if a guest user has the graph real-time privilege.
mhaskar/CVE-2020-8813
CVE-2020-8816 (2020-05-29)
Pi-hole Web v4.3.2 (aka AdminLTE) allows Remote Code Execution by privileged dashboard users via a crafted DHCP static lease.
AndreyRainchik/CVE-2020-8816
MartinSohn/CVE-2020-8816
cybervaca/CVE-2020-8816
team0se7en/CVE-2020-8816
CVE-2020-8825 (2020-02-10)
index.php?p=/dashboard/settings/branding in Vanilla 2.6.3 allows stored XSS.
hacky1997/CVE-2020-8825
CVE-2020-8835 (2020-04-02)
In the Linux kernel 5.5.0 and newer, the bpf verifier (kernel/bpf/verifier.c) did not properly restrict the register bounds for 32-bit operations, leading to out-of-bounds reads and writes in kernel memory. The vulnerability also affects the Linux 5.4 stable series, starting with v5.4.7, as the introducing commit was backported to that branch. This vulnerability was fixed in 5.6.1, 5.5.14, and 5.4.29. (issue is aka ZDI-CAN-10780)
Prabhashaka/IT19147192-CVE-2020-8835
snappyJack/Rick_write_exp_CVE-2020-8835
ret2hell/CVE-2020-8835
SplendidSky/CVE-2020-8835
CVE-2020-8840 (2020-02-10)
FasterXML jackson-databind 2.0.0 through 2.9.10.2 lacks certain xbean-reflect/JNDI blocking, as demonstrated by org.apache.xbean.propertyeditor.JndiConverter.
jas502n/jackson-CVE-2020-8840
Wfzsec/FastJson1.2.62-RCE
fairyming/CVE-2020-8840
0nise/CVE-2020-8840
Blyth0He/CVE-2020-8840
Veraxy01/CVE-2020-8840
CVE-2020-8888
SnipJoe/CVE-2020-8888
CVE-2020-8950 (2020-02-12)
The AUEPLauncher service in Radeon AMD User Experience Program Launcher through 1.0.0.1 on Windows allows elevation of privilege by placing a crafted file in %PROGRAMDATA%\AMD\PPC\upload and then creating a symbolic link in %PROGRAMDATA%\AMD\PPC\temp that points to an arbitrary folder with an arbitrary file name.
sailay1996/amd_eop_poc
CVE-2020-8958 (2020-07-15)
Guangzhou 1GE ONU V2801RW 1.9.1-181203 through 2.9.0-181024 and V2804RGW 1.9.1-181203 through 2.9.0-181024 devices allow remote attackers to execute arbitrary OS commands via shell metacharacters in the boaform/admin/formPing Dest IP Address field.
qurbat/gpon
CVE-2020-9006 (2020-02-17)
The Popup Builder plugin 2.2.8 through 2.6.7.6 for WordPress is vulnerable to SQL injection (in the sgImportPopups function in sg_popup_ajax.php) via PHP Deserialization on attacker-controlled data with the attachmentUrl POST variable. This allows creation of an arbitrary WordPress Administrator account, leading to possible Remote Code Execution because Administrators can run PHP code on Wordpress instances. (This issue has been fixed in the 3.x branch of popup-builder.)
tz4678/cve-2020-9006
CVE-2020-9008 (2020-02-25)
Stored Cross-site scripting (XSS) vulnerability in Blackboard Learn/PeopleTool v9.1 allows users to inject arbitrary web script via the Tile widget in the People Tool profile editor.
kyletimmermans/blackboard-xss
CVE-2020-9038 (2020-02-17)
Joplin through 1.0.184 allows Arbitrary File Read via XSS.
JavierOlmedo/CVE-2020-9038
CVE-2020-9047 (2020-06-26)
A vulnerability exists that could allow the execution of unauthorized code or operating system commands on systems running exacqVision Web Service versions 20.06.3.0 and prior and exacqVision Enterprise Manager versions 20.06.4.0 and prior. An attacker with administrative privileges could potentially download and run a malicious executable that could allow OS command injection on the system.
norrismw/CVE-2020-9047
CVE-2020-9273 (2020-02-20)
In ProFTPD 1.3.7, it is possible to corrupt the memory pool by interrupting the data transfer channel. This triggers a use-after-free in alloc_pool in pool.c, and possible remote code execution.
ptef/CVE-2020-9273
CVE-2020-9283 (2020-02-20)
golang.org/x/crypto before v0.0.0-20200220183623-bac4c82f6975 for Go allows a panic during signature verification in the golang.org/x/crypto/ssh package. A client can attack an SSH server that accepts public keys. Also, a server can attack any SSH client.
brompwnie/CVE-2020-9283
CVE-2020-9332 (2020-06-17)
ftusbbus2.sys in FabulaTech USB for Remote Desktop through 2020-02-19 allows privilege escalation via crafted IoCtl code related to a USB HID device.
Sentinel-One/CVE-2020-9332
CVE-2020-9375 (2020-03-25)
TP-Link Archer C50 V3 devices before Build 200318 Rel. 62209 allows remote attackers to cause a denial of service via a crafted HTTP Header containing an unexpected Referer field.
thewhiteh4t/cve-2020-9375
CVE-2020-9376 (2020-07-09)
** UNSUPPORTED WHEN ASSIGNED ** D-Link DIR-610 devices allow Information Disclosure via SERVICES=DEVICE.ACCOUNT%0AAUTHORIZED_GROUP=1 to getcfg.php. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.
renatoalencar/dlink-dir610-exploits
CVE-2020-9380 (2020-03-05)
IPTV Smarters WEB TV PLAYER through 2020-02-22 allows attackers to execute OS commands by uploading a script.
migueltarga/CVE-2020-9380
CVE-2020-9442 (2020-02-28)
OpenVPN Connect 3.1.0.361 on Windows has Insecure Permissions for %PROGRAMDATA%\OpenVPN Connect\drivers\tap\amd64\win10, which allows local users to gain privileges by copying a malicious drvstore.dll there.
hessandrew/CVE-2020-9442
CVE-2020-9460 (2020-04-14)
Octech Oempro 4.7 through 4.11 allow XSS by an authenticated user. The parameter CampaignName in Campaign.Create is vulnerable.
g-rubert/CVE-2020-9460
CVE-2020-9461 (2020-04-14)
Octech Oempro 4.7 through 4.11 allow stored XSS by an authenticated user. The FolderName parameter of the Media.CreateFolder command is vulnerable.
g-rubert/CVE-2020-9461
CVE-2020-9470 (2020-03-06)
An issue was discovered in Wing FTP Server 6.2.5 before February 2020. Due to insecure permissions when handling session cookies, a local user may view the contents of the session and session_admin directories, which expose active session cookies within the Wing FTP HTTP interface and administration panel. These cookies may be used to hijack user and administrative sessions, including the ability to execute Lua commands as root within the administration panel.
Al1ex/CVE-2020-9470
CVE-2020-9483 (2020-06-30)
**Resolved** When use H2/MySQL/TiDB as Apache SkyWalking storage, the metadata query through GraphQL protocol, there is a SQL injection vulnerability, which allows to access unpexcted data. Apache SkyWalking 6.0.0 to 6.6.0, 7.0.0 H2/MySQL/TiDB storage implementations don't use the appropriate way to set SQL parameters.
shanika04/apache_skywalking
CVE-2020-9484 (2020-05-20)
When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to 7.0.103 if a) an attacker is able to control the contents and name of a file on the server; and b) the server is configured to use the PersistenceManager with a FileStore; and c) the PersistenceManager is configured with sessionAttributeValueClassNameFilter="null" (the default unless a SecurityManager is used) or a sufficiently lax filter to allow the attacker provided object to be deserialized; and d) the attacker knows the relative file path from the storage location used by FileStore to the file the attacker has control over; then, using a specifically crafted request, the attacker will be able to trigger remote code execution via deserialization of the file under their control. Note that all of conditions a) to d) must be true for the attack to succeed.
threedr3am/tomcat-cluster-session-sync-exp
masahiro331/CVE-2020-9484
IdealDreamLast/CVE-2020-9484
qerogram/CVE-2020-9484
osamahamad/CVE-2020-9484-Mass-Scan
DeviantSec/CVE-2020-9484-Scanner
anjai94/CVE-2020-9484-exploit
PenTestical/CVE-2020-9484
Proxysec/-CVE-2020-9484-
Proxysec/-CVE-2020-9484
CVE-2020-9495 (2020-06-19)
Apache Archiva login service before 2.2.5 is vulnerable to LDAP injection. A attacker is able to retrieve user attribute data from the connected LDAP server by providing special values to the login form. With certain characters it is possible to modify the LDAP filter used to query the LDAP users. By measuring the response time for the login request, arbitrary attribute data can be retrieved from LDAP user objects.
ggolawski/CVE-2020-9495
CVE-2020-9496 (2020-07-15)
XML-RPC request are vulnerable to unsafe deserialization and Cross-Site Scripting issues in Apache OFBiz 17.12.03
dwisiswant0/CVE-2020-9496
CVE-2020-9547 (2020-03-01)
FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig (aka ibatis-sqlmap).
fairyming/CVE-2020-9547
CVE-2020-9548 (2020-03-01)
FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to br.com.anteros.dbcp.AnterosDBCPConfig (aka anteros-core).
fairyming/CVE-2020-9548
CVE-2020-9758 (2020-03-09)
An issue was discovered in chat.php in LiveZilla Live Chat 8.0.1.3 (Helpdesk). A blind JavaScript injection lies in the name parameter. Triggering this can fetch the username and passwords of the helpdesk employees in the URI. This leads to a privilege escalation, from unauthenticated to user-level access, leading to full account takeover. The attack fetches multiple credentials because they are stored in the database (stored XSS). This affects the mobile/chat URI via the lgn and psswrd parameters.
ari034/CVE-2020-9758
CVE-2020-9767 (2020-08-14)
A vulnerability related to Dynamic-link Library (“DLL”) loading in the Zoom Sharing Service would allow an attacker who had local access to a machine on which the service was running with elevated privileges to elevate their system privileges as well through use of a malicious DLL. Zoom addressed this issue, which only applies to Windows users, in the 5.0.4 client release.
shubham0d/Zoom-dll-hijacking
CVE-2020-9768 (2020-04-01)
A use after free issue was addressed with improved memory management. This issue is fixed in iOS 13.4 and iPadOS 13.4, tvOS 13.4, watchOS 6.2. An application may be able to execute arbitrary code with system privileges.
krisanovdev/CVE-2020-9768
CVE-2020-9781 (2020-04-01)
The issue was addressed by clearing website permission prompts after navigation. This issue is fixed in iOS 13.4 and iPadOS 13.4. A user may grant website permissions to a site they didn't intend to.
c0d3G33k/Safari-Video-Permission-Spoof-CVE-2020-9781
CVE-2020-9934 (2020-10-16)
An issue existed in the handling of environment variables. This issue was addressed with improved validation. This issue is fixed in iOS 13.6 and iPadOS 13.6, macOS Catalina 10.15.6. A local user may be able to view sensitive user information.
mattshockl/CVE-2020-9934
CVE-2020-9992 (2020-10-16)
This issue was addressed by encrypting communications over the network to devices running iOS 14, iPadOS 14, tvOS 14, and watchOS 7. This issue is fixed in iOS 14.0 and iPadOS 14.0, Xcode 12.0. An attacker in a privileged network position may be able to execute arbitrary code on a paired device during a debug session over the network.
c0ntextomy/c0ntextomy
CVE-2020-10135 (2020-05-19)
Legacy pairing and secure-connections pairing authentication in Bluetooth BR/EDR Core Specification v5.2 and earlier may allow an unauthenticated user to complete authentication without pairing credentials via adjacent access. An unauthenticated, adjacent attacker could impersonate a Bluetooth BR/EDR master or slave to pair with a previously paired remote device to successfully complete the authentication procedure without knowing the link key.
marcinguy/CVE-2020-10135-BIAS
CVE-2020-10148 (2020-12-29)
The SolarWinds Orion API is vulnerable to an authentication bypass that could allow a remote attacker to execute API commands. This vulnerability could allow a remote attacker to bypass authentication and execute API commands which may result in a compromise of the SolarWinds instance. SolarWinds Orion Platform versions 2019.4 HF 5, 2020.2 with no hotfix installed, and 2020.2 HF 1 are affected.
rdoix/CVE-2020-10148-Solarwinds-Orion
Udyz/CVE-2020-10148-Solarwinds-Orion
B1anda0/CVE-2020-10148
CVE-2020-10189 (2020-03-06)
Zoho ManageEngine Desktop Central before 10.0.474 allows remote code execution because of deserialization of untrusted data in getChartImage in the FileStorage class. This is related to the CewolfServlet and MDMLogUploaderServlet servlets.
zavke/CVE-2020-10189-ManageEngine
CVE-2020-10199 (2020-04-01)
Sonatype Nexus Repository before 3.21.2 allows JavaEL Injection (issue 1 of 2).
wsfengfan/CVE-2020-10199-10204
jas502n/CVE-2020-10199
magicming200/CVE-2020-10199_CVE-2020-10204
zhzyker/CVE-2020-10199_POC-EXP
aleenzz/CVE-2020-10199
CVE-2020-10204 (2020-04-01)
Sonatype Nexus Repository before 3.21.2 allows Remote Code Execution.
duolaoa333/CVE-2020-10204
zhzyker/CVE-2020-10204
CVE-2020-10238 (2020-03-16)
An issue was discovered in Joomla! before 3.9.16. Various actions in com_templates lack the required ACL checks, leading to various potential attack vectors.
HoangKien1020/CVE-2020-10238
CVE-2020-10239 (2020-03-16)
An issue was discovered in Joomla! before 3.9.16. Incorrect Access Control in the SQL fieldtype of com_fields allows access for non-superadmin users.
HoangKien1020/CVE-2020-10239
CVE-2020-10558 (2020-03-20)
The driving interface of Tesla Model 3 vehicles in any release before 2020.4.10 allows Denial of Service to occur due to improper process separation, which allows attackers to disable the speedometer, web browser, climate controls, turn signal visual and sounds, navigation, autopilot notifications, along with other miscellaneous functions from the main screen.
nuzzl/CVE-2020-10558
CVE-2020-10560 (2020-03-30)
An issue was discovered in Open Source Social Network (OSSN) through 5.3. A user-controlled file path with a weak cryptographic rand() can be used to read any file with the permissions of the webserver. This can lead to further compromise. The attacker must conduct a brute-force attack against the SiteKey to insert into a crafted URL for components/OssnComments/ossn_com.php and/or libraries/ossn.lib.upgrade.php.
LucidUnicorn/CVE-2020-10560-Key-Recovery
kevthehermit/CVE-2020-10560
CVE-2020-10663 (2020-04-28)
The JSON gem through 2.2.0 for Ruby, as used in Ruby 2.4 through 2.4.9, 2.5 through 2.5.7, and 2.6 through 2.6.5, has an Unsafe Object Creation Vulnerability. This is quite similar to CVE-2013-0269, but does not rely on poor garbage-collection behavior within Ruby. Specifically, use of JSON parsing methods can lead to creation of a malicious object within the interpreter, with adverse effects that are application-dependent.
rails-lts/json_cve_2020_10663
CVE-2020-10665 (2020-03-18)
Docker Desktop allows local privilege escalation to NT AUTHORITY\SYSTEM because it mishandles the collection of diagnostics with Administrator privileges, leading to arbitrary DACL permissions overwrites and arbitrary file writes. This affects Docker Desktop Enterprise before 2.1.0.9, Docker Desktop for Windows Stable before 2.2.0.4, and Docker Desktop for Windows Edge before 2.2.2.0.
spaceraccoon/CVE-2020-10665
CVE-2020-10673 (2020-03-18)
FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to com.caucho.config.types.ResourceRef (aka caucho-quercus).
0nise/CVE-2020-10673
Al1ex/CVE-2020-10673
CVE-2020-10713 (2020-07-30)
A flaw was found in grub2, prior to version 2.06. An attacker may use the GRUB 2 flaw to hijack and tamper the GRUB verification process. This flaw also allows the bypass of Secure Boot protections. In order to load an untrusted or modified kernel, an attacker would first need to establish access to the system such as gaining physical access, obtain the ability to alter a pxe-boot network, or have remote access to a networked system with root access. With this access, an attacker could then craft a string to cause a buffer overflow by injecting a malicious payload that leads to arbitrary code execution within GRUB. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.
eclypsium/BootHole
CVE-2020-10749 (2020-06-03)
A vulnerability was found in all versions of containernetworking/plugins before version 0.8.6, that allows malicious containers in Kubernetes clusters to perform man-in-the-middle (MitM) attacks. A malicious container can exploit this flaw by sending rogue IPv6 router advertisements to the host or other containers, to redirect traffic to the malicious container.
knqyf263/CVE-2020-10749
CVE-2020-10759 (2020-09-15)
A PGP signature bypass flaw was found in fwupd (all versions), which could lead to the installation of unsigned firmware. As per upstream, a signature bypass is theoretically possible, but not practical because the Linux Vendor Firmware Service (LVFS) is either not implemented or enabled in versions of fwupd shipped with Red Hat Enterprise Linux 7 and 8. The highest threat from this vulnerability is to confidentiality and integrity.
justinsteven/CVE-2020-10759-poc
CVE-2020-10977 (2020-04-08)
GitLab EE/CE 8.5 to 12.9 is vulnerable to a an path traversal when moving an issue between projects.
thewhiteh4t/cve-2020-10977
JustMichi/CVE-2020-10977.py
CVE-2020-11076 (2020-05-22)
In Puma (RubyGem) before 4.3.4 and 3.12.5, an attacker could smuggle an HTTP response, by using an invalid transfer-encoding header. The problem has been fixed in Puma 3.12.5 and Puma 4.3.4.
dentarg/cougar
CVE-2020-11107 (2020-04-02)
An issue was discovered in XAMPP before 7.2.29, 7.3.x before 7.3.16 , and 7.4.x before 7.4.4 on Windows. An unprivileged user can change a .exe configuration in xampp-contol.ini for all users (including admins) to enable arbitrary command execution.
S1lkys/CVE-2020-11107
andripwn/CVE-2020-11107
CVE-2020-11108 (2020-05-11)
The Gravity updater in Pi-hole through 4.4 allows an authenticated adversary to upload arbitrary files. This can be abused for Remote Code Execution by writing to a PHP file in the web directory. (Also, it can be used in conjunction with the sudo rule for the www-data user to escalate privileges to root.) The code error is in gravity_DownloadBlocklistFromUrl in gravity.sh.
Frichetten/CVE-2020-11108-PoC
CVE-2020-11113 (2020-03-31)
FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.apache.openjpa.ee.WASRegistryManagedRuntime (aka openjpa).
Al1ex/CVE-2020-11113
CVE-2020-11444 (2020-04-02)
Sonatype Nexus Repository Manager 3.x up to and including 3.21.2 has Incorrect Access Control.
zhzyker/CVE-2020-11444
CVE-2020-11492 (2020-06-05)
An issue was discovered in Docker Desktop through 2.2.0.5 on Windows. If a local attacker sets up their own named pipe prior to starting Docker with the same name, this attacker can intercept a connection attempt from Docker Service (which runs as SYSTEM), and then impersonate their privileges.
joshfinley/CVE-2020-11492
CrackerCat/CVE-2020-11492
CVE-2020-11493 (2020-09-03)
In Foxit Reader and PhantomPDF before 10.0.1, and PhantomPDF before 9.7.3, attackers can obtain sensitive information about an uninitialized object because of direct transformation from PDF Object to Stream without concern for a crafted XObject.
fengjixuchui/CVE-2020-11493
CVE-2020-11519 (2020-06-22)
The SDDisk2k.sys driver of WinMagic SecureDoc v8.5 and earlier allows local users to read or write to physical disc sectors via a \\.\SecureDocDevice handle. Exploiting this vulnerability results in privileged code execution.
patois/winmagic_sd
CVE-2020-11539 (2020-04-22)
An issue was discovered on Tata Sonata Smart SF Rush 1.12 devices. It has been identified that the smart band has no pairing (mode 0 Bluetooth LE security level) The data being transmitted over the air is not encrypted. Adding to this, the data being sent to the smart band doesn't have any authentication or signature verification. Thus, any attacker can control a parameter of the device.
the-girl-who-lived/CVE-2020-11539
CVE-2020-11547 (2020-04-04)
PRTG Network Monitor before 20.1.57.1745 allows remote unauthenticated attackers to obtain information about probes running or the server itself (CPU usage, memory, Windows version, and internal statistics) via an HTTP request, as demonstrated by type=probes to login.htm or index.htm.
ch-rigu/CVE-2020-11547--PRTG-Network-Monitor-Information-Disclosure
CVE-2020-11579 (2020-09-03)
An issue was discovered in Chadha PHPKB 9.0 Enterprise Edition. installer/test-connection.php (part of the installation process) allows a remote unauthenticated attacker to disclose local files on hosts running PHP before 7.2.16, or on hosts where the MySQL ALLOW LOCAL DATA INFILE option is enabled.
ShielderSec/CVE-2020-11579
CVE-2020-11650 (2020-04-08)
An issue was discovered in iXsystems FreeNAS (and TrueNAS) 11.2 before 11.2-u8 and 11.3 before 11.3-U1. It allows a denial of service. The login authentication component has no limits on the length of an authentication message or the rate at which such messages are sent.
weinull/CVE-2020-11650
CVE-2020-11651 (2020-04-30)
An issue was discovered in SaltStack Salt before 2019.2.4 and 3000 before 3000.2. The salt-master process ClearFuncs class does not properly validate method calls. This allows a remote user to access some methods without authentication. These methods can be used to retrieve user tokens from the salt master and/or run arbitrary commands on salt minions.
chef-cft/salt-vulnerabilities
rossengeorgiev/salt-security-backports
dozernz/cve-2020-11651
0xc0d/CVE-2020-11651
jasperla/CVE-2020-11651-poc
Imanfeng/SaltStack-Exp
bravery9/SaltStack-Exp
kevthehermit/CVE-2020-11651
lovelyjuice/cve-2020-11651-exp-plus
heikanet/CVE-2020-11651-CVE-2020-11652-EXP
RakhithJK/CVE-2020-11651
appcheck-ng/salt-rce-scanner-CVE-2020-11651-CVE-2020-11652
CVE-2020-11652 (2020-04-30)
An issue was discovered in SaltStack Salt before 2019.2.4 and 3000 before 3000.2. The salt-master process ClearFuncs class allows access to some methods that improperly sanitize paths. These methods allow arbitrary directory access to authenticated users.
fanjq99/CVE-2020-11652
Al1ex/CVE-2020-11652
CVE-2020-11794
w4cky/CVE-2020-11794
CVE-2020-11851 (2020-11-16)
Arbitrary code execution vulnerability on Micro Focus ArcSight Logger product, affecting all version prior to 7.1.1. The vulnerability could be remotely exploited resulting in the execution of arbitrary code.
ch1nghz/CVE-2020-11851
CVE-2020-11881 (2020-09-14)
An array index error in MikroTik RouterOS 6.41.3 through 6.46.5, and 7.x through 7.0 Beta5, allows an unauthenticated remote attacker to crash the SMB server via modified setup-request packets, aka SUP-12964.
botlabsDev/CVE-2020-11881
CVE-2020-11890 (2020-04-21)
An issue was discovered in Joomla! before 3.9.17. Improper input validations in the usergroup table class could lead to a broken ACL configuration.
HoangKien1020/CVE-2020-11890
CVE-2020-11896 (2020-06-17)
The Treck TCP/IP stack before 6.0.1.66 allows Remote Code Execution, related to IPv4 tunneling.
Fans0n-Fan/Treck20-Related
CVE-2020-11932 (2020-05-12)
It was discovered that the Subiquity installer for Ubuntu Server logged the LUKS full disk encryption password if one was entered.
ProjectorBUg/CVE-2020-11932
Staubgeborener/CVE-2020-11932
CVE-2020-11975 (2020-06-05)
Apache Unomi allows conditions to use OGNL scripting which offers the possibility to call static Java classes from the JDK that could execute code with the permission level of the running Java process.
1135/unomi_exploit
CVE-2020-11989 (2020-06-22)
Apache Shiro before 1.5.3, when using Apache Shiro with Spring dynamic controllers, a specially crafted request may cause an authentication bypass.
HYWZ36/HYWZ36-CVE-2020-11989-code
CVE-2020-11996 (2020-06-26)
A specially crafted sequence of HTTP/2 requests sent to Apache Tomcat 10.0.0-M1 to 10.0.0-M5, 9.0.0.M1 to 9.0.35 and 8.5.0 to 8.5.55 could trigger high CPU usage for several seconds. If a sufficient number of such requests were made on concurrent HTTP/2 connections, the server could become unresponsive.
rusakovichma/tomcat-embed-core-9.0.31-CVE-2020-11996
CVE-2020-12078 (2020-04-28)
An issue was discovered in Open-AudIT 3.3.1. There is shell metacharacter injection via attributes to an open-audit/configuration/ URI. An attacker can exploit this by adding an excluded IP address to the global discovery settings (internally called exclude_ip). This exclude_ip value is passed to the exec function in the discoveries_helper.php file (inside the all_ip_list function) without being filtered, which means that the attacker can provide a payload instead of a valid IP address.
mhaskar/CVE-2020-12078
84KaliPleXon3/CVE-2020-12078
CVE-2020-12112 (2020-04-23)
BigBlueButton before 2.2.5 allows remote attackers to obtain sensitive files via Local File Inclusion.
tchenu/CVE-2020-12112
CVE-2020-12116 (2020-05-07)
Zoho ManageEngine OpManager Stable build before 124196 and Released build before 125125 allows an unauthenticated attacker to read arbitrary files on the server by sending a crafted request.
BeetleChunks/CVE-2020-12116
CVE-2020-12432 (2020-07-21)
The WOPI API integration for Vereign Collabora CODE through 4.2.2 does not properly restrict delivery of JavaScript to a victim's browser, and lacks proper MIME type access control, which could lead to XSS that steals account credentials via cookies or local storage. The attacker must first obtain an API access token, which can be accomplished if the attacker is able to upload a .docx or .odt file. The associated API endpoints for exploitation are /wopi/files and /wopi/getAccessToken.
d7x/CVE-2020-12432
CVE-2020-12629 (2020-05-04)
include/class.sla.php in osTicket before 1.14.2 allows XSS via the SLA Name.
mkelepce/CVE-2020-12629
CVE-2020-12688
TheCyberGeek/Centreon-20.04
CVE-2020-12695 (2020-06-08)
The Open Connectivity Foundation UPnP specification before 2020-04-17 does not forbid the acceptance of a subscription request with a delivery URL on a different network segment than the fully qualified event-subscription URL, aka the CallStranger issue.
yunuscadirci/CallStranger
corelight/callstranger-detector
CVE-2020-12696 (2020-05-07)
The iframe plugin before 4.5 for WordPress does not sanitize a URL.
g-rubert/CVE-2020-12696
CVE-2020-12712 (2020-06-11)
A vulnerability based on insecure user/password encryption in the JOE (job editor) component of SOS JobScheduler 1.12 and 1.13 allows attackers to decrypt the user/password that is optionally stored with a user's profile.
SanderUbink/CVE-2020-12712
CVE-2020-12717 (2020-05-14)
The COVIDSafe (Australia) app 1.0 and 1.1 for iOS allows a remote attacker to crash the app, and consequently interfere with COVID-19 contact tracing, via a Bluetooth advertisement containing manufacturer data that is too short. This occurs because of an erroneous OpenTrace manuData.subdata call. The ABTraceTogether (Alberta), ProteGO (Poland), and TraceTogether (Singapore) apps were also affected.
wabzqem/covidsafe-CVE-2020-12717-exploit
CVE-2020-12753 (2020-05-11)
An issue was discovered on LG mobile devices with Android OS 7.2, 8.0, 8.1, 9, and 10 software. Arbitrary code execution can occur via the bootloader because of an EL1/EL3 coldboot vulnerability involving raw_resources. The LG ID is LVE-SMP-200006 (May 2020).
shinyquagsire23/CVE-2020-12753-PoC
CVE-2020-12800 (2020-06-08)
The drag-and-drop-multiple-file-upload-contact-form-7 plugin before 1.3.3.3 for WordPress allows Unrestricted File Upload and remote code execution by setting supported_type to php% and uploading a .php% file.
amartinsec/CVE-2020-12800
CVE-2020-12828 (2020-05-21)
An issue was discovered in AnchorFree VPN SDK before 1.3.3.218. The VPN SDK service takes certain executable locations over a socket bound to localhost. Binding to the socket and providing a path where a malicious executable file resides leads to executing the malicious executable file with SYSTEM privileges.
0xsha/ZombieVPN
CVE-2020-12832 (2020-05-13)
WordPress Plugin Simple File List before 4.2.8 is prone to a vulnerability that lets attackers delete arbitrary files because the application fails to properly verify user-supplied input.
0x05010705/simplefilelist1.7
CVE-2020-12856 (2020-05-17)
OpenTrace, as used in COVIDSafe through v1.0.17, TraceTogether, ABTraceTogether, and other applications on iOS and Android, allows remote attackers to conduct long-term re-identification attacks and possibly have unspecified other impact, because of how Bluetooth is used.
alwentiu/COVIDSafe-CVE-2020-12856
CVE-2020-12928 (2020-10-13)
A vulnerability in a dynamically loaded AMD driver in AMD Ryzen Master V15 may allow any authenticated user to escalate privileges to NT authority system.
ekknod/EC_PRO-LAN
CVE-2020-13094 (2020-05-18)
Dolibarr before 11.0.4 allows XSS.
mkelepce/CVE-2020-13094
CVE-2020-13151 (2020-08-05)
Aerospike Community Edition 4.9.0.5 allows for unauthenticated submission and execution of user-defined functions (UDFs), written in Lua, as part of a database query. It attempts to restrict code execution by disabling os.execute() calls, but this is insufficient. Anyone with network access can use a crafted UDF to execute arbitrary OS commands on all nodes of the cluster at the permission level of the user running the Aerospike service.
b4ny4n/CVE-2020-13151
CVE-2020-13158 (2020-06-22)
Artica Proxy before 4.30.000000 Community Edition allows Directory Traversal via the fw.progrss.details.php popup parameter.
InfoSec4Fun/CVE-2020-13158
CVE-2020-13159 (2020-06-22)
Artica Proxy before 4.30.000000 Community Edition allows OS command injection via the Netbios name, Server domain name, dhclient_mac, Hostname, or Alias field. NOTE: this may overlap CVE-2020-10818.
InfoSec4Fun/CVE-2020-13159
CVE-2020-13162 (2020-06-16)
A time-of-check time-of-use vulnerability in PulseSecureService.exe in Pulse Secure Client versions prior to 9.1.6 down to 5.3 R70 for Windows (which runs as NT AUTHORITY/SYSTEM) allows unprivileged users to run a Microsoft Installer executable with elevated privileges.
redtimmy/tu-TOCTOU-kaiu-TOCMEU-CVE-2020-13162-
CVE-2020-13254 (2020-06-03)
An issue was discovered in Django 2.2 before 2.2.13 and 3.0 before 3.0.7. In cases where a memcached backend does not perform key validation, passing malformed cache keys could result in a key collision, and potential data leakage.
danpalmer/django-cve-2020-13254
CVE-2020-13259 (2020-09-16)
A vulnerability in the web-based management interface of RAD SecFlow-1v os-image SF_0290_2.3.01.26 could allow an unauthenticated, remote attacker to conduct a cross-site request forgery (CSRF) attack on an affected system. The vulnerability is due to insufficient CSRF protections for the web UI on an affected device. An attacker could exploit this vulnerability by persuading a user of the interface to follow a malicious link. A successful exploit could allow the attacker to perform arbitrary actions with the privilege level of the affected user. This could be exploited in conjunction with CVE-2020-13260.
UrielYochpaz/CVE-2020-13259
CVE-2020-13277 (2020-06-19)
An authorization issue in the mirroring logic allowed read access to private repositories in GitLab CE/EE 10.6 and later through 13.0.5
lyy289065406/CVE-2020-13277
CVE-2020-13424 (2020-05-23)
The XCloner component before 3.5.4 for Joomla! allows Authenticated Local File Disclosure.
mkelepce/CVE-2020-13424
CVE-2020-13457
alt3kx/CVE-2020-13457
CVE-2020-13640 (2020-06-18)
A SQL injection issue in the gVectors wpDiscuz plugin 5.3.5 and earlier for WordPress allows remote attackers to execute arbitrary SQL commands via the order parameter of a wpdLoadMoreComments request. (No 7.x versions are affected.)
asterite3/CVE-2020-13640
CVE-2020-13646 (2020-06-05)
In Cheetah free WiFi 5.1, the driver file (liebaonat.sys) allows local users to cause a denial of service (BSOD) or possibly have unspecified other impact because of not validating input values from IOCtl 0x830020f8, 0x830020E0, 0x830020E4, or 0x8300210c.
y5s5k5/CVE-2020-13646
CVE-2020-13777 (2020-06-04)
GnuTLS 3.6.x before 3.6.14 uses incorrect cryptography for encrypting a session ticket (a loss of confidentiality in TLS 1.2, and an authentication bypass in TLS 1.3). The earliest affected version is 3.6.4 (2018-09-24) because of an error in a 2018-09-18 commit. Until the first key rotation, the TLS server always uses wrong data in place of an encryption key derived from an application.
0xxon/cve-2020-13777
shigeki/challenge_CVE-2020-13777
prprhyt/PoC_TLS1_3_CVE-2020-13777
CVE-2020-13884 (2020-06-08)
Citrix Workspace App before 1912 on Windows has Insecure Permissions and an Unquoted Path vulnerability which allows local users to gain privileges during the uninstallation of the application.
hessandrew/CVE-2020-13884
CVE-2020-13885 (2020-06-08)
Citrix Workspace App before 1912 on Windows has Insecure Permissions which allows local users to gain privileges during the uninstallation of the application.
hessandrew/CVE-2020-13885
CVE-2020-13886 (2020-11-26)
Intelbras TIP 200 60.61.75.15, TIP 200 LITE 60.61.75.15, and TIP 300 65.61.75.22 devices allow cgi-bin/cgiServer.exx?page=../ Directory Traversal.
lucxssouza/CVE-2020-13886
CVE-2020-13889 (2020-06-06)
showAlert() in the administration panel in Bludit 3.12.0 allows XSS.
gh0st56/CVE-2020-13889
CVE-2020-13925 (2020-07-14)
Similar to CVE-2020-1956, Kylin has one more restful API which concatenates the API inputs into OS commands and then executes them on the server; while the reported API misses necessary input validation, which causes the hackers to have the possibility to execute OS command remotely. Users of all previous versions after 2.3 should upgrade to 3.1.0.
bit4woo/CVE-2020-13925
CVE-2020-13933 (2020-08-17)
Apache Shiro before 1.6.0, when using Apache Shiro, a specially crafted HTTP request may cause an authentication bypass.
lyy289065406/CVE-2020-13933
0xkami/cve-2020-13933
CVE-2020-13935 (2020-07-14)
The payload length in a WebSocket frame was not correctly validated in Apache Tomcat 10.0.0-M1 to 10.0.0-M6, 9.0.0.M1 to 9.0.36, 8.5.0 to 8.5.56 and 7.0.27 to 7.0.104. Invalid payload lengths could trigger an infinite loop. Multiple requests with invalid payload lengths could lead to a denial of service.
RedTeamPentesting/CVE-2020-13935
CVE-2020-13937 (2020-10-19)
Apache Kylin 2.0.0, 2.1.0, 2.2.0, 2.3.0, 2.3.1, 2.3.2, 2.4.0, 2.4.1, 2.5.0, 2.5.1, 2.5.2, 2.6.0, 2.6.1, 2.6.2, 2.6.3, 2.6.4, 2.6.5, 2.6.6, 3.0.0-alpha, 3.0.0-alpha2, 3.0.0-beta, 3.0.0, 3.0.1, 3.0.2, 3.1.0, 4.0.0-alpha has one restful api which exposed Kylin's configuration information without any authentication, so it is dangerous because some confidential information entries will be disclosed to everyone.
yaunsky/CVE-2020-13937
CVE-2020-13942 (2020-11-24)
It is possible to inject malicious OGNL or MVEL scripts into the /context.json public endpoint. This was partially fixed in 1.5.1 but a new attack vector was found. In Apache Unomi version 1.5.2 scripts are now completely filtered from the input. It is highly recommended to upgrade to the latest available version of the 1.5.x release to fix this problem.
lp008/CVE-2020-13942
eugenebmx/CVE-2020-13942
shifa123/CVE-2020-13942-POC-
blackmarketer/CVE-2020-13942
yaunsky/Unomi-CVE-2020-13942
hoanx4/apche_unomi_rce
CVE-2020-13996 (2020-06-09)
The J2Store plugin before 3.3.13 for Joomla! allows a SQL injection attack by a trusted store manager.
mkelepce/CVE-2020-13996
CVE-2020-14064 (2020-07-15)
IceWarp Email Server 12.3.0.1 has Incorrect Access Control for user accounts.
networksecure/CVE-2020-14064
masoud-zivari/CVE-2020-14064
CVE-2020-14065 (2020-07-15)
IceWarp Email Server 12.3.0.1 allows remote attackers to upload files and consume disk space.
networksecure/CVE-2020-14065
masoud-zivari/CVE-2020-14065
CVE-2020-14066 (2020-07-15)
IceWarp Email Server 12.3.0.1 allows remote attackers to upload JavaScript files that are dangerous for clients to access.
networksecure/CVE-2020-14066
masoud-zivari/CVE-2020-14066
CVE-2020-14179 (2020-09-20)
Affected versions of Atlassian Jira Server and Data Center allow remote, unauthenticated attackers to view custom field names and custom SLA names via an Information Disclosure vulnerability in the /secure/QueryComponent!Default.jspa endpoint. The affected versions are before version 8.5.8, and from version 8.6.0 before 8.11.1.
c0brabaghdad1/CVE-2020-14179
CVE-2020-14181 (2020-09-16)
Affected versions of Atlassian Jira Server and Data Center allow an unauthenticated user to enumerate users via an Information Disclosure vulnerability in the /ViewUserHover.jspa endpoint. The affected versions are before version 7.13.6, from version 8.0.0 before 8.5.7, and from version 8.6.0 before 8.12.0.
Rival420/CVE-2020-14181
CVE-2020-14195 (2020-06-16)
FasterXML jackson-databind 2.x before 2.9.10.5 mishandles the interaction between serialization gadgets and typing, related to org.jsecurity.realm.jndi.JndiRealmFactory (aka org.jsecurity).
Al1ex/CVE-2020-14195
CVE-2020-14199 (2020-06-16)
BIP-143 in the Bitcoin protocol specification mishandles the signing of a Segwit transaction, which allows attackers to trick a user into making two signatures in certain cases, potentially leading to a huge transaction fee. NOTE: this affects all hardware wallets. It was fixed in 1.9.1 for the Trezor One and 2.3.1 for the Trezor Model T.
nondejus/CVE-2020-14199
CVE-2020-14292 (2020-09-09)
In the COVIDSafe application through 1.0.21 for Android, unsafe use of the Bluetooth transport option in the GATT connection allows attackers to trick the application into establishing a connection over Bluetooth BR/EDR transport, which reveals the public Bluetooth address of the victim's phone without authorisation, bypassing the Bluetooth address randomisation protection in the user's phone.
alwentiu/CVE-2020-14292
CVE-2020-14293 (2020-10-02)
conf_datetime in Secudos DOMOS 5.8 allows remote attackers to execute arbitrary commands as root via shell metacharacters in the zone field (obtained from the web interface).
patrickhener/CVE-2020-14293
CVE-2020-14294 (2020-10-02)
An issue was discovered in Secudos Qiata FTA 1.70.19. The comment feature allows persistent XSS that is executed when reading transfer comments or the global notice board.
patrickhener/CVE-2020-14294
CVE-2020-14321
HoangKien1020/CVE-2020-14321
CVE-2020-14386 (2020-09-16)
A flaw was found in the Linux kernel before 5.9-rc4. Memory corruption can be exploited to gain root privileges from unprivileged processes. The highest threat from this vulnerability is to data confidentiality and integrity.
cgwalters/cve-2020-14386
CVE-2020-14644 (2020-07-15)
Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
0xkami/cve-2020-14644
CVE-2020-14645 (2020-07-15)
Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
Y4er/CVE-2020-14645
DaBoQuan/CVE-2020-14645
ChenZIDu/CVE-2020-14645
HYWZ36/CVE-2020-14645-code
Schira4396/CVE-2020-14645
CVE-2020-14750 (2020-11-01)
Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
pprietosanchez/CVE-2020-14750
kkhacklabs/CVE-2020-14750
CVE-2020-14882 (2020-10-21)
Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
zhzyker/exphub
zhzyker/vulmap
jas502n/CVE-2020-14882
s1kr10s/CVE-2020-14882
Umarovm/-Patched-McMaster-University-Blind-Command-Injection
RedTeamWing/CVE-2020-14882
0thm4n3/cve-2020-14882
wsfengfan/cve-2020-14882
alexfrancow/CVE-2020-14882
sickwell/CVE-2020-14882
GGyao/CVE-2020-14882_POC
ludy-dev/Weblogic_Unauthorized-bypass-RCE
GGyao/CVE-2020-14882_ALL
ovProphet/CVE-2020-14882-checker
NS-Sp4ce/CVE-2020-14882
mmioimm/cve-2020-14882
QmF0c3UK/CVE-2020-14882
murataydemir/CVE-2020-14882
AirEvan/CVE-2020-14882-GUI-Test
corelight/CVE-2020-14882-weblogicRCE
x51/CVE-2020-14882
BabyTeam1024/CVE-2020-14882
xkx518/CodeTest
securitysqs/poc
CVE-2020-14883 (2020-10-21)
Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 7.2 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H).
murataydemir/CVE-2020-14883
B1anda0/CVE-2020-14883
CVE-2020-14947 (2020-06-30)
OCS Inventory NG 2.7 allows Remote Command Execution via shell metacharacters to require/commandLine/CommandLine.php because mib_file in plugins/main_sections/ms_config/ms_snmp_config.php is mishandled in get_mib_oid.
mhaskar/CVE-2020-14947
CVE-2020-14955 (2020-06-26)
In Jiangmin Antivirus 16.0.13.129, the driver file (KVFG.sys) allows local users to cause a denial of service (BSOD) or possibly have unspecified other impact because of not validating input values from IOCtl 0x220440.
y5s5k5/CVE-2020-14955
intrigus-lgtm/CVE-2020-14955
CVE-2020-14957 (2020-06-30)
In Windows cleaning assistant 3.2, the driver file (AtpKrnl.sys) allows local users to cause a denial of service (BSOD) or possibly have unspecified other impact because of not validating input values from IOCtl 0x223CCD.
y5s5k5/CVE-2020-14957
CVE-2020-14965 (2020-06-23)
On TP-Link TL-WR740N v4 and TL-WR740ND v4 devices, an attacker with access to the admin panel can inject HTML code and change the HTML context of the target pages and stations in the access-control settings via targets_lists_name or hosts_lists_name. The vulnerability can also be exploited through a CSRF, requiring no authentication as an administrator.
g-rubert/CVE-2020-14965
CVE-2020-15002 (2020-10-23)
OX App Suite through 7.10.3 allows SSRF via the the /ajax/messaging/message message API.
skr0x1c0/Blind-SSRF-CVE-2020-15002
skr0x1c0/SSRF-CVE-2020-15002
CVE-2020-15051 (2020-07-15)
An issue was discovered in Artica Proxy before 4.30.000000. Stored XSS exists via the Server Domain Name, Your Email Address, Group Name, MYSQL Server, Database, MYSQL Username, Group Name, and Task Description fields.
pratikshad19/CVE-2020-15051
CVE-2020-15052 (2020-07-20)
An issue was discovered in Artica Proxy CE before 4.28.030.418. SQL Injection exists via the Netmask, Hostname, and Alias fields.
pratikshad19/CVE-2020-15052
CVE-2020-15053 (2020-07-20)
An issue was discovered in Artica Proxy CE before 4.28.030.418. Reflected XSS exists via these search fields: real time request, System Events, Proxy Events, Proxy Objects, and Firewall objects.
pratikshad19/CVE-2020-15053
CVE-2020-15148 (2020-09-15)
Yii 2 (yiisoft/yii2) before version 2.0.38 is vulnerable to remote code execution if the application calls `unserialize()` on arbitrary user input. This is fixed in version 2.0.38. A possible workaround without upgrading is available in the linked advisory.
Maskhe/CVE-2020-15148-bypasses
0xkami/cve-2020-15148
CVE-2020-15169 (2020-09-11)
In Action View before versions 5.2.4.4 and 6.0.3.3 there is a potential Cross-Site Scripting (XSS) vulnerability in Action View's translation helpers. Views that allow the user to control the default (not found) value of the `t` and `translate` helpers could be susceptible to XSS attacks. When an HTML-unsafe string is passed as the default for a missing translation key named html or ending in _html, the default string is incorrectly marked as HTML-safe and not escaped. This is patched in versions 6.0.3.3 and 5.2.4.4. A workaround without upgrading is proposed in the source advisory.
glasses618/CVE-2020-15169
CVE-2020-15227 (2020-10-01)
Nette versions before 2.0.19, 2.1.13, 2.2.10, 2.3.14, 2.4.16, 3.0.6 are vulnerable to an code injection attack by passing specially formed parameters to URL that may possibly leading to RCE. Nette is a PHP/Composer MVC Framework.
Langriklol/CVE-2020-15227
hu4wufu/CVE-2020-15227
filipsedivy/CVE-2020-15227
CVE-2020-15228 (2020-10-01)
In the `@actions/core` npm module before version 1.2.6,`addPath` and `exportVariable` functions communicate with the Actions Runner over stdout by generating a string in a specific format. Workflows that log untrusted data to stdout may invoke these commands, resulting in the path or environment variables being modified without the intention of the workflow or action author. The runner will release an update that disables the `set-env` and `add-path` workflow commands in the near future. For now, users should upgrade to `@actions/core v1.2.6` or later, and replace any instance of the `set-env` or `add-path` commands in their workflows with the new Environment File Syntax. Workflows and actions using the old commands or older versions of the toolkit will start to warn, then error out during workflow execution.
guettli/fix-CVE-2020-15228
CVE-2020-15257 (2020-11-30)
containerd is an industry-standard container runtime and is available as a daemon for Linux and Windows. In containerd before versions 1.3.9 and 1.4.3, the containerd-shim API is improperly exposed to host network containers. Access controls for the shim’s API socket verified that the connecting process had an effective UID of 0, but did not otherwise restrict access to the abstract Unix domain socket. This would allow malicious containers running in the same network namespace as the shim, with an effective UID of 0 but otherwise reduced privileges, to cause new processes to be run with elevated privileges. This vulnerability has been fixed in containerd 1.3.9 and 1.4.3. Users should update to these versions as soon as they are released. It should be noted that containers started with an old version of containerd-shim should be stopped and restarted, as running containers will continue to be vulnerable even after an upgrade. If you are not providing the ability for untrusted users to start containers in the same network namespace as the shim (typically the "host" network namespace, for example with docker run --net=host or hostNetwork: true in a Kubernetes pod) and run with an effective UID of 0, you are not vulnerable to this issue. If you are running containers with a vulnerable configuration, you can deny access to all abstract sockets with AppArmor by adding a line similar to deny unix addr=@**, to your policy. It is best practice to run containers with a reduced set of privileges, with a non-zero UID, and with isolated namespaces. The containerd maintainers strongly advise against sharing namespaces with the host. Reducing the set of isolation mechanisms used for a container necessarily increases that container's privilege, regardless of what container runtime is used for running that container.
nccgroup/abstractshimmer
CVE-2020-15349 (2020-11-16)
BinaryNights ForkLift 3.x before 3.4 has a local privilege escalation vulnerability because the privileged helper tool implements an XPC interface that allows file operations to any process (copy, move, delete) as root and changing permissions.
Traxes/Forklift_LPE
CVE-2020-15367 (2020-07-07)
Venki Supravizio BPM 10.1.2 does not limit the number of authentication attempts. An unauthenticated user may exploit this vulnerability to launch a brute-force authentication attack against the Login page.
inflixim4be/CVE-2020-15367
CVE-2020-15392 (2020-07-07)
A user enumeration vulnerability flaw was found in Venki Supravizio BPM 10.1.2. This issue occurs during password recovery, where a difference in error messages could allow an attacker to determine if a username is valid or not, enabling a brute-force attack with valid usernames.
inflixim4be/CVE-2020-15392
CVE-2020-15399
mkelepce/CVE-2020-15399
CVE-2020-15492 (2020-07-23)
An issue was discovered in INNEO Startup TOOLS 2017 M021 12.0.66.3784 through 2018 M040 13.0.70.3804. The sut_srv.exe web application (served on TCP port 85) includes user input into a filesystem access without any further validation. This might allow an unauthenticated attacker to read files on the server via Directory Traversal, or possibly have unspecified other impact.
patrickhener/CVE-2020-15492
CVE-2020-15778 (2020-07-24)
scp in OpenSSH through 8.3p1 allows command injection in the scp.c toremote function, as demonstrated by backtick characters in the destination argument. NOTE: the vendor reportedly has stated that they intentionally omit validation of "anomalous argument transfers" because that could "stand a great chance of breaking existing workflows."
cpandya2909/CVE-2020-15778
CVE-2020-15873 (2020-07-21)
In LibreNMS before 1.65.1, an authenticated attacker can achieve SQL Injection via the customoid.inc.php device_id POST parameter to ajax_form.php.
limerencee/cs4239-cve-2020-15873
CVE-2020-15906 (2020-10-22)
tiki-login.php in Tiki before 21.2 sets the admin password to a blank value after 50 invalid login attempts.
S1lkys/CVE-2020-15906
CVE-2020-15931 (2020-10-20)
Netwrix Account Lockout Examiner before 5.1 allows remote attackers to capture the Net-NTLMv1/v2 authentication challenge hash of the Domain Administrator (that is configured within the product in its installation state) by generating a single Kerberos Pre-Authentication Failed (ID 4771) event on a Domain Controller.
optiv/CVE-2020-15931
CVE-2020-15956 (2020-08-04)
ActiveMediaServer.exe in ACTi NVR3 Standard Server 3.0.12.42 allows remote unauthenticated attackers to trigger a buffer overflow and application termination via a malformed payload.
megamagnus/cve-2020-15956
CVE-2020-15999 (2020-11-02)
Heap buffer overflow in Freetype in Google Chrome prior to 86.0.4240.111 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.
marcinguy/CVE-2020-15999
maarlo/CVE-2020-15999
Marmeus/CVE-2020-15999
CVE-2020-16012 (2021-01-08)
Side-channel information leakage in graphics in Google Chrome prior to 87.0.4280.66 allowed a remote attacker to leak cross-origin data via a crafted HTML page.
aleksejspopovs/cve-2020-16012
CVE-2020-16126 (2020-11-10)
An Ubuntu-specific modification to AccountsService in versions before 0.6.55-0ubuntu13.2, among other earlier versions, improperly dropped the ruid, allowing untrusted users to send signals to AccountService, thus stopping it from handling D-Bus messages in a timely fashion.
zev3n/Ubuntu-Gnome-privilege-escalation
CVE-2020-16152
eriknl/CVE-2020-16152
CVE-2020-16270 (2020-10-16)
OLIMPOKS under 3.3.39 allows Auth/Admin ErrorMessage XSS. Remote Attacker can use discovered vulnerability to inject malicious JavaScript payload to victim’s browsers in context of vulnerable applications. Executed code can be used to steal administrator’s cookies, influence HTML content of targeted application and perform phishing-related attacks. Vulnerable application used in more than 3000 organizations in different sectors from retail to industries.
Security-AVS/CVE-2020-16270
CVE-2020-16898 (2020-10-16)
A remote code execution vulnerability exists when the Windows TCP/IP stack improperly handles ICMPv6 Router Advertisement packets, aka 'Windows TCP/IP Remote Code Execution Vulnerability'.
advanced-threat-research/CVE-2020-16898
corelight/CVE-2020-16898
Maliek/CVE-2020-16898_Check
ZephrFish/CVE-2020-16898
esnet-security/cve-2020-16898
initconf/CVE-2020-16898-Bad-Neighbor
Q1984/CVE-2020-16898
0xeb-bp/cve-2020-16898
jiansiting/cve-2020-16898
CPO-EH/CVE-2020-16898_Workaround
CPO-EH/CVE-2020-16898_Checker
momika233/CVE-2020-16898-exp
komomon/CVE-2020-16898-EXP-POC
komomon/CVE-2020-16898--EXP-POC
CVE-2020-16899 (2020-10-16)
A denial of service vulnerability exists when the Windows TCP/IP stack improperly handles ICMPv6 Router Advertisement packets, aka 'Windows TCP/IP Denial of Service Vulnerability'.
advanced-threat-research/CVE-2020-16899
bkerler/CVE-2020-16899
CVE-2020-16938 (2020-10-16)
An information disclosure vulnerability exists when the Windows kernel improperly handles objects in memory, aka 'Windows Kernel Information Disclosure Vulnerability'. This CVE ID is unique from CVE-2020-16901.
ioncodes/CVE-2020-16938
CVE-2020-16939 (2020-10-16)
An elevation of privilege vulnerability exists when Group Policy improperly checks access, aka 'Group Policy Elevation of Privilege Vulnerability'.
rogue-kdc/CVE-2020-16939
CVE-2020-16947 (2020-10-16)
A remote code execution vulnerability exists in Microsoft Outlook software when the software fails to properly handle objects in memory, aka 'Microsoft Outlook Remote Code Execution Vulnerability'.
0neb1n/CVE-2020-16947
MasterSploit/CVE-2020-16947
CVE-2020-17008
jas502n/CVE-2020-17008
CVE-2020-17035 (2020-11-11)
Windows Kernel Elevation of Privilege Vulnerability
flamelu/CVE-2020-17035-patch-analysis
CVE-2020-17057 (2020-11-11)
Windows Win32k Elevation of Privilege Vulnerability
ze0r/cve-2020-17057
CVE-2020-17087 (2020-11-11)
Windows Kernel Local Elevation of Privilege Vulnerability
revengsh/CVE-2020-17087
CVE-2020-17144 (2020-12-09)
, aka 'Microsoft Exchange Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2020-17117, CVE-2020-17132, CVE-2020-17141, CVE-2020-17142.
Airboi/CVE-2020-17144-EXP
zcgonvh/CVE-2020-17144
CVE-2020-17382 (2020-10-02)
The MSI AmbientLink MsIo64 driver 1.0.0.8 has a Buffer Overflow (0x80102040, 0x80102044, 0x80102050,and 0x80102054).
uf0o/CVE-2020-17382
CVE-2020-17496 (2020-08-12)
vBulletin 5.5.4 through 5.6.2 allows remote command execution via crafted subWidgets data in an ajax/render/widget_tabbedcontainer_tab_panel request. NOTE: this issue exists because of an incomplete fix for CVE-2019-16759.
ctlyz123/CVE-2020-17496
ludy-dev/vBulletin_5.x-tab_panel-RCE
CVE-2020-17518 (2021-01-05)
Apache Flink 1.5.1 introduced a REST handler that allows you to write an uploaded file to an arbitrary location on the local file system, through a maliciously modified HTTP HEADER. The files can be written to any location accessible by Flink 1.5.1. All users should upgrade to Flink 1.11.3 or 1.12.0 if their Flink instance(s) are exposed. The issue was fixed in commit a5264a6f41524afe8ceadf1d8ddc8c80f323ebc4 from apache/flink:master.
QmF0c3UK/CVE-2020-17518
murataydemir/CVE-2020-17518
rakjong/Flink-CVE-2020-17518-getshell
CVE-2020-17519 (2021-01-05)
A change introduced in Apache Flink 1.11.0 (and released in 1.11.1 and 1.11.2 as well) allows attackers to read any file on the local filesystem of the JobManager through the REST interface of the JobManager process. Access is restricted to files accessible by the JobManager process. All users should upgrade to Flink 1.11.3 or 1.12.0 if their Flink instance(s) are exposed. The issue was fixed in commit b561010b0ee741543c3953306037f00d7a9f0801 from apache/flink:master.
B1anda0/CVE-2020-17519
QmF0c3UK/CVE-2020-17519
dolevf/apache-flink-directory-traversal.nse
hoanx4/CVE-2020-17519
murataydemir/CVE-2020-17519
radbsie/CVE-2020-17519-Exp
yaunsky/CVE-2020-17519-Apache-Flink
CVE-2020-17530 (2020-12-10)
Forced OGNL evaluation, when evaluated on raw user input in tag attributes, may lead to remote code execution. Affected software : Apache Struts 2.0.0 - Struts 2.5.25.
ka1n4t/CVE-2020-17530
wuzuowei/CVE-2020-17530
Al1ex/CVE-2020-17530
fengziHK/CVE-2020-17530-strust2-061
ludy-dev/freemarker_RCE_struts2_s2-061
CyborgSecurity/CVE-2020-17530
uzzzval/CVE-2020-17530
CVE-2020-17531 (2020-12-08)
A Java Serialization vulnerability was found in Apache Tapestry 4. Apache Tapestry 4 will attempt to deserialize the "sp" parameter even before invoking the page's validate method, leading to deserialization without authentication. Apache Tapestry 4 reached end of life in 2008 and no update to address this issue will be released. Apache Tapestry 5 versions are not vulnerable to this issue. Users of Apache Tapestry 4 should upgrade to the latest Apache Tapestry 5 version.
154802388/CVE-2020-17531
CVE-2020-23489 (2020-11-16)
The import.json.php file before 8.9 for Avideo is vulnerable to a File Deletion vulnerability. This allows the deletion of configuration.php, which leads to certain privilege checks not being in place, and therefore a user can escalate privileges to admin.
ahussam/AVideo3xploit
CVE-2020-23726 (2020-12-03)
There is a local denial of service vulnerability in Wise Care 365 5.5.4, attackers can cause computer crash (BSOD).
y5s5k5/CVE-2020-23726
CVE-2020-23727 (2020-12-03)
There is a local denial of service vulnerability in the Antiy Zhijia Terminal Defense System 5.0.2.10121559 and an attacker can cause a computer crash (BSOD).
y5s5k5/CVE-2020-23727
CVE-2020-23735 (2020-12-03)
In Saibo Cyber Game Accelerator 3.7.9 there is a local privilege escalation vulnerability. Attackers can use the constructed program to increase user privileges
y5s5k5/CVE-2020-23735
CVE-2020-23736 (2020-12-03)
There is a local denial of service vulnerability in DaDa accelerator 5.6.19.816,, attackers can use constructed programs to cause computer crashes (BSOD).
y5s5k5/CVE-2020-23736
CVE-2020-23738 (2020-12-03)
There is a local denial of service vulnerability in Advanced SystemCare 13 PRO 13.5.0.174. Attackers can use a constructed program to cause a computer crash (BSOD)
y5s5k5/CVE-2020-23738
CVE-2020-23740 (2020-12-03)
In DriverGenius 9.61.5480.28 there is a local privilege escalation vulnerability in the driver wizard, attackers can use constructed programs to increase user privileges.
y5s5k5/CVE-2020-23740
CVE-2020-23741 (2020-12-03)
In AnyView (network police) network monitoring software 4.6.0.1, there is a local denial of service vulnerability in AnyView, attackers can use a constructed program to cause a computer crash (BSOD).
y5s5k5/CVE-2020-23741
CVE-2020-23968 (2020-11-10)
Ilex International Sign&go Workstation Security Suite 7.1 allows elevation of privileges via a symlink attack on ProgramData\Ilex\S&G\Logs\000-sngWSService1.log.
ricardojba/CVE-2020-23968-ILEX-SignGo-EoP
CVE-2020-24028 (2020-09-02)
ForLogic Qualiex v1 and v3 allows any authenticated customer to achieve privilege escalation via user creations, password changes, or user permission updates.
underprotection/CVE-2020-24028
CVE-2020-24029 (2020-09-02)
Because of unauthenticated password changes in ForLogic Qualiex v1 and v3, customer and admin permissions and data can be accessed via a simple request.
underprotection/CVE-2020-24029
CVE-2020-24030 (2020-09-02)
ForLogic Qualiex v1 and v3 has weak token expiration. This allows remote unauthenticated privilege escalation and access to sensitive data via token reuse.
underprotection/CVE-2020-24030
CVE-2020-24033 (2020-10-22)
An issue was discovered in fs.com S3900 24T4S 1.7.0 and earlier. The form does not have an authentication or token authentication mechanism that allows remote attackers to forge requests on behalf of a site administrator to change all settings including deleting users, creating new users with escalated privileges.
M0NsTeRRR/CVE-2020-24033
CVE-2020-24227 (2020-11-23)
Playground Sessions v2.5.582 (and earlier) for Windows, stores the user credentials in plain text allowing anyone with access to UserProfiles.sol to extract the email and password.
nathunandwani/CVE-2020-24227
CVE-2020-24572 (2020-08-24)
An issue was discovered in includes/webconsole.php in RaspAP 2.5. With authenticated access, an attacker can use a misconfigured (and virtually unrestricted) web console to attack the underlying OS (Raspberry Pi) running this software, and execute commands on the system (including ones for uploading of files and execution of code).
lb0x/cve-2020-24572
CVE-2020-24597
HoangKien1020/CVE-2020-24597
CVE-2020-24616 (2020-08-25)
FasterXML jackson-databind 2.x before 2.9.10.6 mishandles the interaction between serialization gadgets and typing, related to br.com.anteros.dbcp.AnterosDBCPDataSource (aka Anteros-DBCP).
0xkami/cve-2020-24616-poc
CVE-2020-24765 (2020-10-20)
InterMind iMind Server through 3.13.65 allows remote unauthenticated attackers to read the self-diagnostic archive via a direct api/rs/monitoring/rs/api/system/dump-diagnostic-info?server=127.0.0.1 request.
trump88/CVE-2020-24765
CVE-2020-24955 (2020-09-01)
SUPERAntiSyware Professional X Trial 10.0.1206 is vulnerable to local privilege escalation because it allows unprivileged users to restore a malicious DLL from quarantine into the system32 folder via an NTFS directory junction, as demonstrated by a crafted ualapi.dll file that is detected as malware.
b1nary0x1/CVE-2020-24955
CVE-2020-25068 (2020-09-03)
Setelsa Conacwin v3.7.1.2 is vulnerable to a local file inclusion vulnerability. This vulnerability allows a remote unauthenticated attacker to read internal files on the server via an http:IP:PORT/../../path/file_to_disclose Directory Traversal URI. NOTE: The manufacturer indicated that the affected version does not exist. Furthermore, they indicated that they detected this problem in an internal audit more than 3 years ago and fixed it in 2017.
bryanroma/CVE-2020-25068
CVE-2020-25200 (2020-10-01)
** DISPUTED ** Pritunl 1.29.2145.25 allows attackers to enumerate valid VPN usernames via a series of /auth/session login attempts. Initially, the server will return error 401. However, if the username is valid, then after 20 login attempts, the server will start responding with error 400. Invalid usernames will receive error 401 indefinitely. Note: This has been disputed by the vendor as not a vulnerability. They argue that this is an intended design.
lukaszstu/pritunl-CVE-2020-25200
CVE-2020-25213 (2020-09-09)
The File Manager (wp-file-manager) plugin before 6.9 for WordPress allows remote attackers to upload and execute arbitrary PHP code because it renames an unsafe example elFinder connector file to have the .php extension. This, for example, allows attackers to run the elFinder upload (or mkfile and put) command to write PHP code into the wp-content/plugins/wp-file-manager/lib/files/ directory. This was exploited in the wild in August and September 2020.
mansoorr123/wp-file-manager-CVE-2020-25213
kakamband/WPKiller
forse01/CVE-2020-25213
CVE-2020-25265 (2020-12-02)
AppImage libappimage before 1.0.3 allows attackers to trigger an overwrite of a system-installed .desktop file by providing a .desktop file that contains Name= with path components.
refi64/CVE-2020-25265-25266
CVE-2020-25270 (2020-10-08)
PHPGurukul hostel-management-system 2.1 allows XSS via Guardian Name, Guardian Relation, Guardian Contact no, Address, or City.
Ko-kn3t/CVE-2020-25270
CVE-2020-25271 (2020-10-08)
PHPGurukul hospital-management-system-in-php 4.0 allows XSS via admin/patient-search.php, doctor/search.php, book-appointment.php, doctor/appointment-history.php, or admin/appointment-history.php.
Ko-kn3t/CVE-2020-25271
CVE-2020-25272 (2020-10-08)
In SourceCodester Online Bus Booking System 1.0, there is XSS through the name parameter in book_now.php.
Ko-kn3t/CVE-2020-25272
CVE-2020-25273 (2020-10-08)
In SourceCodester Online Bus Booking System 1.0, there is Authentication bypass on the Admin Login screen in admin.php via username or password SQL injection.
Ko-kn3t/CVE-2020-25273
CVE-2020-25398 (2020-11-05)
CSV Injection exists in InterMind iMind Server through 3.13.65 via the csv export functionality.
h3llraiser/CVE-2020-25398
CVE-2020-25399 (2020-11-05)
Stored XSS in InterMind iMind Server through 3.13.65 allows any user to hijack another user's session by sending a malicious file in the chat.
h3llraiser/CVE-2020-25399
CVE-2020-25487 (2020-09-22)
PHPGURUKUL Zoo Management System Using PHP and MySQL version 1.0 is affected by: SQL Injection via zms/animal-detail.php.
Ko-kn3t/CVE-2020-25487
CVE-2020-25488
Ko-kn3t/CVE-2020-25488
CVE-2020-25498 (2021-01-06)
Cross Site Scripting (XSS) vulnerability in Beetel router 777VR1 can be exploited via the NTP server name in System Time and "Keyword" in URL Filter.
the-girl-who-lived/CVE-2020-25498
CVE-2020-25514 (2020-09-22)
Sourcecodester Simple Library Management System 1.0 is affected by Incorrect Access Control via the Login Panel, http://<site>/lms/admin.php.
Ko-kn3t/CVE-2020-25514
CVE-2020-25515 (2020-09-22)
Sourcecodester Simple Library Management System 1.0 is affected by Insecure Permissions via Books > New Book , http://<site>/lms/index.php?page=books.
Ko-kn3t/CVE-2020-25515
CVE-2020-25518
g-rubert/wordpress_DoS
CVE-2020-25540 (2020-09-14)
ThinkAdmin v6 is affected by a directory traversal vulnerability. An unauthorized attacker can read arbitrarily file on a remote server via GET request encode parameter.
Schira4396/CVE-2020-25540
CVE-2020-25637 (2020-10-06)
A double free memory issue was found to occur in the libvirt API, in versions before 6.8.0, responsible for requesting information about network interfaces of a running QEMU domain. This flaw affects the polkit access control driver. Specifically, clients connecting to the read-write socket with limited ACL permissions could use this flaw to crash the libvirt daemon, resulting in a denial of service, or potentially escalate their privileges on the system. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.
brahmiboudjema/CVE-2020-25637-libvirt-double-free
CVE-2020-25705 (2020-11-16)
A flaw in the way reply ICMP packets are limited in the Linux kernel functionality was found that allows to quickly scan open UDP ports. This flaw allows an off-path remote user to effectively bypassing source port UDP randomization. The highest threat from this vulnerability is to confidentiality and possibly integrity, because software that relies on UDP source port randomization are indirectly affected as well. Kernel versions before 5.10 may be vulnerable to this issue.
tdwyer/CVE-2020-25705
CVE-2020-25747 (2020-09-24)
The Telnet service of Rubetek RV-3406, RV-3409, and RV-3411 cameras (firmware versions v342, v339) can allow a remote attacker to gain access to RTSP and ONFIV services without authentication. Thus, the attacker can watch live streams from the camera, rotate the camera, change some settings (brightness, clarity, time), restart the camera, or reset it to factory settings.
jet-pentest/CVE-2020-25747
CVE-2020-25748 (2020-09-24)
A Cleartext Transmission issue was discovered on Rubetek RV-3406, RV-3409, and RV-3411 cameras (firmware versions v342, v339). Someone in the middle can intercept and modify the video data from the camera, which is transmitted in an unencrypted form. One can also modify responses from NTP and RTSP servers and force the camera to use the changed values.
jet-pentest/CVE-2020-25748
CVE-2020-25749 (2020-09-24)
The Telnet service of Rubetek cameras RV-3406, RV-3409, and RV-3411 cameras (firmware versions v342, v339) could allow an remote attacker to take full control of the device with a high-privileged account. The vulnerability exists because a system account has a default and static password. The Telnet service cannot be disabled and this password cannot be changed via standard functionality.
jet-pentest/CVE-2020-25749
CVE-2020-25769
lagartojuancho/CVE-2020-25769
CVE-2020-25790 (2020-09-19)
** DISPUTED ** Typesetter CMS 5.x through 5.1 allows admins to upload and execute arbitrary PHP code via a .php file inside a ZIP archive. NOTE: the vendor disputes the significance of this report because "admins are considered trustworthy"; however, the behavior "contradicts our security policy" and is being fixed for 5.2.
t0gu/CVE-2020-25790
7Mitu/CVE-2020-25790
CVE-2020-25860 (2020-12-21)
The install.c module in the Pengutronix RAUC update client prior to version 1.5 has a Time-of-Check Time-of-Use vulnerability, where signature verification on an update file takes place before the file is reopened for installation. An attacker who can modify the update file just before it is reopened can install arbitrary code on the device.
rauc/rauc-1.5-integration
CVE-2020-25867 (2020-10-07)
SoPlanning before 1.47 doesn't correctly check the security key used to publicly share plannings. It allows a bypass to get access without authentication.
thomasfady/CVE-2020-25867
CVE-2020-26061 (2020-10-05)
ClickStudios Passwordstate Password Reset Portal prior to build 8501 is affected by an authentication bypass vulnerability. The ResetPassword function does not validate whether the user has successfully authenticated using security questions. An unauthenticated, remote attacker can send a crafted HTTP request to the /account/ResetPassword page to set a new password for any registered user.
missing0x00/CVE-2020-26061
CVE-2020-26217 (2020-11-16)
XStream before version 1.4.14 is vulnerable to Remote Code Execution.The vulnerability may allow a remote attacker to run arbitrary shell commands only by manipulating the processed input stream. Only users who rely on blocklists are affected. Anyone using XStream's Security Framework allowlist is not affected. The linked advisory provides code workarounds for users who cannot upgrade. The issue is fixed in version 1.4.14.
novysodope/CVE-2020-26217-XStream-RCE-POC
CVE-2020-26259 (2020-12-15)
XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.15, is vulnerable to an Arbitrary File Deletion on the local host when unmarshalling. The vulnerability may allow a remote attacker to delete arbitrary know files on the host as log as the executing process has sufficient rights only by manipulating the processed input stream. If you rely on XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.15. The reported vulnerability does not exist running Java 15 or higher. No user is affected, who followed the recommendation to setup XStream's Security Framework with a whitelist! Anyone relying on XStream's default blacklist can immediately switch to a whilelist for the allowed types to avoid the vulnerability. Users of XStream 1.4.14 or below who still want to use XStream default blacklist can use a workaround described in more detailed in the referenced advisories.
jas502n/CVE-2020-26259
CVE-2020-26525 (2020-10-02)
Damstra Smart Asset 2020.7 has SQL injection via the API/api/Asset originator parameter. This allows forcing the database and server to initiate remote connections to third party DNS servers.
lukaszstu/SmartAsset-SQLinj-CVE-2020-26525
CVE-2020-26526 (2020-10-02)
An issue was discovered in Damstra Smart Asset 2020.7. It is possible to enumerate valid usernames on the login page. The application sends a different server response when the username is invalid than when the username is valid ("Unable to find an APIDomain" versus "Wrong email or password").
lukaszstu/SmartAsset-UE-CVE-2020-26526
CVE-2020-26527 (2020-10-02)
An issue was discovered in API/api/Version in Damstra Smart Asset 2020.7. Cross-origin resource sharing trusts random origins by accepting the arbitrary 'Origin: example.com' header and responding with 200 OK and a wildcard 'Access-Control-Allow-Origin: *' header.
lukaszstu/SmartAsset-CORS-CVE-2020-26527
CVE-2020-26732 (2021-01-14)
Skyworth GN542VF Boa version 0.94.13 does not set the Secure flag for the session cookie in an HTTPS session, which makes it easier for remote attackers to capture this cookie by intercepting its transmission within an HTTP session.
swzhouu/CVE-2020-26732
CVE-2020-26733 (2021-01-14)
Cross Site Scripting (XSS) in Configuration page in SKYWORTH GN542VF Hardware Version 2.0 and Software Version 2.0.0.16 allows authenticated attacker to inject their own script into the page via DDNS Configuration Section.
swzhouu/CVE-2020-26733
CVE-2020-27151 (2020-12-07)
An issue was discovered in Kata Containers through 1.11.3 and 2.x through 2.0-rc1. The runtime will execute binaries given using annotations without any kind of validation. Someone who is granted access rights to a cluster will be able to have kata-runtime execute arbitrary binaries as root on the worker nodes.
kata-containers/runtime-CVE-2020-27151
CVE-2020-27190
qlh831/x-CVE-2020-27190
CVE-2020-27194 (2020-10-16)
An issue was discovered in the Linux kernel before 5.8.15. scalar32_min_max_or in kernel/bpf/verifier.c mishandles bounds tracking during use of 64-bit values, aka CID-5b9fbeb75b6a.
willinin/CVE-2020-27194-exp
xmzyshypnc/CVE-2020-27194
CVE-2020-27199 (2020-12-16)
The Magic Home Pro application 1.5.1 for Android allows Authentication Bypass. The security control that the application currently has in place is a simple Username and Password authentication function. Using enumeration, an attacker is able to forge a User specific token without the need for correct password to gain access to the mobile application as that victim user.
9lyph/CVE-2020-27199
CVE-2020-27358 (2020-10-31)
An issue was discovered in REDCap 8.11.6 through 9.x before 10. The messenger's CSV feature (that allows users to export their conversation threads as CSV) allows non-privileged users to export one another's conversation threads by changing the thread_id parameter in the request to the endpoint Messenger/messenger_download_csv.php?title=Hey&thread_id={THREAD_ID}.
seb1055/cve-2020-27358-27359
CVE-2020-27368 (2021-01-14)
Directory Indexing in Login Portal of Login Portal of TOTOLINK-A702R-V1.0.0-B20161227.1023 allows attacker to access /icons/ directories via GET Parameter.
swzhouu/CVE-2020-27368
CVE-2020-27603 (2020-10-21)
BigBlueButton before 2.2.27 has an unsafe JODConverter setting in which LibreOffice document conversions can access external files.
hannob/CVE-2020-27603-bbb-libreoffice-poc
CVE-2020-27662 (2020-11-26)
In GLPI before 9.5.3, ajax/comments.php has an Insecure Direct Object Reference (IDOR) vulnerability that allows an attacker to read data from any database table (e.g., glpi_tickets, glpi_users, etc.).
indevi0us/CVE-2020-27662
CVE-2020-27663 (2020-11-26)
In GLPI before 9.5.3, ajax/getDropdownValue.php has an Insecure Direct Object Reference (IDOR) vulnerability that allows an attacker to read data from any itemType (e.g., Ticket, Users, etc.).
indevi0us/CVE-2020-27663
CVE-2020-27688 (2020-11-05)
RVToolsPasswordEncryption.exe in RVTools 4.0.6 allows users to encrypt passwords to be used in the configuration files. This encryption used a static IV and key, and thus using the Decrypt() method from VISKD.cs from the RVTools.exe executable allows for decrypting the encrypted passwords. The accounts used in the configuration files have access to vSphere instances.
matthiasmaes/CVE-2020-27688
CVE-2020-27747 (2020-10-29)
An issue was discovered in Click Studios Passwordstate 8.9 (Build 8973).If the user of the system has assigned himself a PIN code for entering from a mobile device using the built-in generator (4 digits), a remote attacker has the opportunity to conduct a brute force attack on this PIN code. As result, remote attacker retrieves all passwords from another systems, available for affected account.
jet-pentest/CVE-2020-27747
CVE-2020-27935
LIJI32/SnatchBox
CVE-2020-27949
seemoo-lab/dtrace-memaccess_cve-2020-27949
CVE-2020-27950 (2020-12-08)
A memory initialization issue was addressed. This issue is fixed in macOS Big Sur 11.0.1, watchOS 7.1, iOS 12.4.9, watchOS 6.2.9, Security Update 2020-006 High Sierra, Security Update 2020-006 Mojave, iOS 14.2 and iPadOS 14.2, watchOS 5.3.9, macOS Catalina 10.15.7 Supplemental Update, macOS Catalina 10.15.7 Update. A malicious application may be able to disclose kernel memory.
synacktiv/CVE-2020-27950
CVE-2020-27955 (2020-11-05)
Git LFS 2.12.0 allows Remote Code Execution.
ExploitBox/git-lfs-RCE-exploit-CVE-2020-27955
ExploitBox/git-lfs-RCE-exploit-CVE-2020-27955-Go
yhsung/cve-2020-27955-poc
r00t4dm/CVE-2020-27955
WizZYou/git-lfs-RCE-exploit-CVE-2020-27955-revshell
shubham0d/CVE-2020-27955
SilverSkyFlyingFeather/CVE-2020-27955-TEST
TheTh1nk3r/cve-2020-27955
dennyson120/CVE-2020-27955
CVE-2020-27976 (2020-10-28)
osCommerce Phoenix CE before 1.0.5.4 allows OS command injection remotely. Within admin/mail.php, a from POST parameter can be passed to the application. This affects the PHP mail function, and the sendmail -f option.
k0rnh0li0/CVE-2020-27976
CVE-2020-28052 (2020-12-17)
An issue was discovered in Legion of the Bouncy Castle BC Java 1.65 and 1.66. The OpenBSDBCrypt.checkPassword utility method compared incorrect data when checking the password, allowing incorrect passwords to indicate they were matching with previously hashed ones that were different.
madstap/bouncy-castle-generative-test-poc
kurenaif/CVE-2020-28052_PoC
CVE-2020-28054 (2020-11-19)
JamoDat TSMManager Collector version up to 6.5.0.21 is vulnerable to an Authorization Bypass because the Collector component is not properly validating an authenticated session with the Viewer. If the Viewer has been modified (binary patched) and the Bypass Login functionality is being used, an attacker can request every Collector's functionality as if they were a properly logged-in user: administrating connected instances, reviewing logs, editing configurations, accessing the instances' consoles, accessing hardware configurations, etc.Exploiting this vulnerability won't grant an attacker access nor control on remote ISP servers as no credentials is sent with the request.
VoidSec/Tivoli-Madness
CVE-2020-28169 (2020-12-24)
The td-agent-builder plugin before 2020-12-18 for Fluentd allows attackers to gain privileges because the bin directory is writable by a user account, but a file in bin is executed as NT AUTHORITY\SYSTEM.
zubrahzz/FluentD-TD-agent-Exploit-CVE-2020-28169
CVE-2020-28175 (2020-12-03)
There is a local privilege escalation vulnerability in Alfredo Milani Comparetti SpeedFan 4.52. Attackers can use constructed programs to increase user privileges
y5s5k5/CVE-2020-28175
CVE-2020-28328 (2020-11-06)
SuiteCRM before 7.11.17 is vulnerable to remote code execution via the system settings Log File Name setting. In certain circumstances involving admin account takeover, logger_file_name can refer to an attacker-controlled .php file under the web root.
mcorybillington/SuiteCRM-RCE
CVE-2020-28351 (2020-11-08)
The conferencing component on Mitel ShoreTel 19.46.1802.0 devices could allow an unauthenticated attacker to conduct a reflected cross-site scripting (XSS) attack (via the PATH_INFO to index.php) due to insufficient validation for the time_zone object in the HOME_MEETING& page.
dievus/CVE-2020-28351
CVE-2020-28413 (2020-12-30)
In MantisBT 2.24.3, SQL Injection can occur in the parameter "access" of the mc_project_get_users function through the API SOAP.
EthicalHCOP/CVE-2020-28413_Mantis2.24.3-SQLi-SOAP
CVE-2020-28414 (2020-11-12)
A reflected cross-site scripting (XSS) vulnerability exists in the TranzWare Payment Gateway 3.1.12.3.2. A remote unauthenticated attacker is able to execute arbitrary HTML code via crafted url (different vector than CVE-2020-28415).
jet-pentest/CVE-2020-28414
CVE-2020-28415 (2020-11-12)
A reflected cross-site scripting (XSS) vulnerability exists in the TranzWare Payment Gateway 3.1.12.3.2. A remote unauthenticated attacker is able to execute arbitrary HTML code via crafted url (different vector than CVE-2020-28414).
jet-pentest/CVE-2020-28415
CVE-2020-28647 (2020-11-17)
In Progress MOVEit Transfer before 2020.1, a malicious user could craft and store a payload within the application. If a victim within the MOVEit Transfer instance interacts with the stored payload, it could invoke and execute arbitrary code within the context of the victim's browser (XSS).
SECFORCE/Progress-MOVEit-Transfer-2020.1-Stored-XSS-CVE-2020-28647
CVE-2020-28948 (2020-11-19)
Archive_Tar through 1.4.10 allows an unserialization attack because phar: is blocked but PHAR: is not blocked.
0x240x23elu/CVE-2020-28948-and-CVE-2020-28949
CVE-2020-29007
seqred-s-a/cve-2020-29007
CVE-2020-29070 (2020-11-25)
osCommerce 2.3.4.1 has XSS vulnerability via the authenticated user entering the XSS payload into the title section of newsletters.
aslanemre/cve-2020-29070
CVE-2020-29156 (2020-12-27)
The WooCommerce plugin before 4.7.0 for WordPress allows remote attackers to view the status of arbitrary orders via the order_id parameter in a fetch_order_status action.
Ko-kn3t/CVE-2020-29156
CVE-2020-29254 (2020-12-11)
TikiWiki 21.2 allows templates to be edited without CSRF protection. This could allow an unauthenticated, remote attacker to conduct a cross-site request forgery (CSRF) attack and perform arbitrary actions on an affected system. The vulnerability is due to insufficient CSRF protections for the web-based management interface of the affected system. An attacker could exploit this vulnerability by persuading a user of the interface to follow a maliciously crafted link. A successful exploit could allow the attacker to perform arbitrary actions on an affected system with the privileges of the user. These action include allowing attackers to submit their own code through an authenticated user resulting in local file Inclusion. If an authenticated user who is able to edit TikiWiki templates visits an malicious website, template code can be edited.
S1lkys/CVE-2020-29254
CVE-2020-29364 (2020-11-30)
In NetArt News Lister 1.0.0, the news headlines vulnerable to stored xss attacks. Attackers can inject codes in news titles.
aslanemre/CVE-2020-29364
CVE-2020-29583 (2020-12-22)
Firmware version 4.60 of Zyxel USG devices contains an undocumented account (zyfwp) with an unchangeable password. The password for this account can be found in cleartext in the firmware. This account can be used by someone to login to the ssh server or web interface with admin privileges.
2d4d/scan_CVE-2020-29583
CVE-2020-29666 (2020-12-10)
In Lan ATMService M3 ATM Monitoring System 6.1.0, due to a directory-listing vulnerability, a remote attacker can view log files, located in /websocket/logs/, that contain a user's cookie values and the predefined developer's cookie value.
jet-pentest/CVE-2020-29666
CVE-2020-29667 (2020-12-10)
In Lan ATMService M3 ATM Monitoring System 6.1.0, a remote attacker able to use a default cookie value, such as PHPSESSID=LANIT-IMANAGER, can achieve control over the system because of Insufficient Session Expiration.
jet-pentest/CVE-2020-29667
CVE-2020-29669 (2020-12-13)
In the Macally WIFISD2-2A82 Media and Travel Router 2.000.010, the Guest user is able to reset its own password. This process has a vulnerability which can be used to take over the administrator account and results in shell access. As the admin user may read the /etc/shadow file, the password hashes of each user (including root) can be dumped. The root hash can be cracked easily which results in a complete system compromise.
code-byter/CVE-2020-29669
CVE-2020-35262 (2021-01-06)
Cross Site Scripting (XSS) vulnerability in Digisol DG-HR3400 can be exploited via the NTP server name in Time and date module and "Keyword" in URL Filter.
the-girl-who-lived/CVE-2020-35262
CVE-2020-35488 (2021-01-05)
The fileop module of the NXLog service in NXLog Community Edition 2.10.2150 allows remote attackers to cause a denial of service (daemon crash) via a crafted Syslog payload to the Syslog service. This attack requires a specific configuration. Also, the name of the directory created must use a Syslog field. (For example, on Linux it is not possible to create a .. directory. On Windows, it is not possible to create a CON directory.)
GuillaumePetit84/CVE-2020-35488
CVE-2020-35489 (2020-12-17)
The contact-form-7 (aka Contact Form 7) plugin before 5.3.2 for WordPress allows Unrestricted File Upload and remote code execution because a filename may contain special characters.
dn9uy3n/Check-WP-CVE-2020-35489
CVE-2020-35590 (2020-12-21)
LimitLoginAttempts.php in the limit-login-attempts-reloaded plugin before 2.17.4 for WordPress allows a bypass of (per IP address) rate limits because the X-Forwarded-For header can be forged. When the plugin is configured to accept an arbitrary header for the client source IP address, a malicious user is not limited to perform a brute force attack, because the client IP header accepts any arbitrary string. When randomizing the header input, the login count does not ever reach the maximum allowed retries.
N4nj0/CVE-2020-35590
CVE-2020-35606 (2020-12-21)
Arbitrary command execution can occur in Webmin through 1.962. Any user authorized for the Package Updates module can execute arbitrary commands with root privileges via vectors involving %0A and %0C. NOTE: this issue exists because of an incomplete fix for CVE-2019-12840.
anasbousselham/webminscan
CVE-2020-35717 (2021-01-01)
zonote through 0.4.0 allows XSS via a crafted note, with resultant Remote Code Execution (because nodeIntegration in webPreferences is true).
hmartos/cve-2020-35717
CVE-2020-35728 (2020-12-26)
FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to com.oracle.wls.shaded.org.apache.xalan.lib.sql.JNDIConnectionPool (aka embedded Xalan in org.glassfish.web/javax.servlet.jsp.jstl).
Al1ex/CVE-2020-35728
CVE-2020-36179 (2021-01-06)
FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to oadd.org.apache.commons.dbcp.cpdsadapter.DriverAdapterCPDS.
Al1ex/CVE-2020-36179
CVE-2020-36184 (2021-01-06)
FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.tomcat.dbcp.dbcp2.datasources.PerUserPoolDataSource.
Al1ex/CVE-2020-36184
CVE-2020-36188 (2021-01-06)
FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to com.newrelic.agent.deps.ch.qos.logback.core.db.JNDIConnectionSource.
Al1ex/CVE-2020-36188
CVE-2020-72381
jdordonezn/CVE-2020-72381
2019
CVE-2019-0053 (2019-07-11)
Insufficient validation of environment variables in the telnet client supplied in Junos OS can lead to stack-based buffer overflows, which can be exploited to bypass veriexec restrictions on Junos OS. A stack-based overflow is present in the handling of environment variables when connecting via the telnet client to remote telnet servers. This issue only affects the telnet client — accessible from the CLI or shell — in Junos OS. Inbound telnet services are not affected by this issue. This issue affects: Juniper Networks Junos OS: 12.3 versions prior to 12.3R12-S13; 12.3X48 versions prior to 12.3X48-D80; 14.1X53 versions prior to 14.1X53-D130, 14.1X53-D49; 15.1 versions prior to 15.1F6-S12, 15.1R7-S4; 15.1X49 versions prior to 15.1X49-D170; 15.1X53 versions prior to 15.1X53-D237, 15.1X53-D496, 15.1X53-D591, 15.1X53-D69; 16.1 versions prior to 16.1R3-S11, 16.1R7-S4; 16.2 versions prior to 16.2R2-S9; 17.1 versions prior to 17.1R3; 17.2 versions prior to 17.2R1-S8, 17.2R2-S7, 17.2R3-S1; 17.3 versions prior to 17.3R3-S4; 17.4 versions prior to 17.4R1-S6, 17.4R2-S3, 17.4R3; 18.1 versions prior to 18.1R2-S4, 18.1R3-S3; 18.2 versions prior to 18.2R1-S5, 18.2R2-S2, 18.2R3; 18.2X75 versions prior to 18.2X75-D40; 18.3 versions prior to 18.3R1-S3, 18.3R2; 18.4 versions prior to 18.4R1-S2, 18.4R2.
dreamsmasher/inetutils-CVE-2019-0053-Patched-PKGBUILD
CVE-2019-0162 (2019-04-17)
Memory access in virtual memory mapping for some microprocessors may allow an authenticated user to potentially enable information disclosure via local access.
saadislamm/SPOILER
CVE-2019-0192 (2019-03-07)
In Apache Solr versions 5.0.0 to 5.5.5 and 6.0.0 to 6.6.5, the Config API allows to configure the JMX server via an HTTP POST request. By pointing it to a malicious RMI server, an attacker could take advantage of Solr's unsafe deserialization to trigger remote code execution on the Solr side.
mpgn/CVE-2019-0192
Rapidsafeguard/Solr-RCE-CVE-2019-0192
CVE-2019-0193 (2019-08-01)
In Apache Solr, the DataImportHandler, an optional but popular module to pull in data from databases and other sources, has a feature in which the whole DIH configuration can come from a request's "dataConfig" parameter. The debug mode of the DIH admin screen uses this to allow convenient debugging / development of a DIH config. Since a DIH config can contain scripts, this parameter is a security risk. Starting with version 8.2.0 of Solr, use of this parameter requires setting the Java System property "enable.dih.dataConfigParam" to true.
xConsoIe/CVE-2019-0193
jas502n/CVE-2019-0193
1135/solr_exploit
jaychouzzk/CVE-2019-0193-exp
CVE-2019-0211 (2019-04-08)
In Apache HTTP Server 2.4 releases 2.4.17 to 2.4.38, with MPM event, worker or prefork, code executing in less-privileged child processes or threads (including scripts executed by an in-process scripting interpreter) could execute arbitrary code with the privileges of the parent process (usually root) by manipulating the scoreboard. Non-Unix systems are not affected.
ozkanbilge/Apache-Exploit-2019
CVE-2019-0227 (2019-05-01)
A Server Side Request Forgery (SSRF) vulnerability affected the Apache Axis 1.4 distribution that was last released in 2006. Security and bug commits commits continue in the projects Axis 1.x Subversion repository, legacy users are encouraged to build from source. The successor to Axis 1.x is Axis2, the latest version is 1.7.9 and is not vulnerable to this issue.
ianxtianxt/cve-2019-0227
CVE-2019-0230 (2020-09-14)
Apache Struts 2.0.0 to 2.5.20 forced double OGNL evaluation, when evaluated on raw user input in tag attributes, may lead to remote code execution.
PrinceFPF/CVE-2019-0230
ramoncjs3/CVE-2019-0230
f8al/CVE-2019-0230-PoC
Al1ex/CVE-2019-0230
soshewh97/CVE-2019-0230_Struts2S2-059
CVE-2019-0232 (2019-04-15)
When running on Windows with enableCmdLineArguments enabled, the CGI Servlet in Apache Tomcat 9.0.0.M1 to 9.0.17, 8.5.0 to 8.5.39 and 7.0.0 to 7.0.93 is vulnerable to Remote Code Execution due to a bug in the way the JRE passes command line arguments to Windows. The CGI Servlet is disabled by default. The CGI option enableCmdLineArguments is disable by default in Tomcat 9.0.x (and will be disabled by default in all versions in response to this vulnerability). For a detailed explanation of the JRE behaviour, see Markus Wulftange's blog (https://codewhitesec.blogspot.com/2016/02/java-and-command-line-injections-in-windows.html) and this archived MSDN blog (https://web.archive.org/web/20161228144344/https://blogs.msdn.microsoft.com/twistylittlepassagesallalike/2011/04/23/everyone-quotes-command-line-arguments-the-wrong-way/).
pyn3rd/CVE-2019-0232
jas502n/CVE-2019-0232
CherishHair/CVE-2019-0232-EXP
setrus/CVE-2019-0232
0xmanjoos/CVE-2019-0232
CVE-2019-0539 (2019-01-08)
A remote code execution vulnerability exists in the way that the Chakra scripting engine handles objects in memory in Microsoft Edge, aka "Chakra Scripting Engine Memory Corruption Vulnerability." This affects Microsoft Edge, ChakraCore. This CVE ID is unique from CVE-2019-0567, CVE-2019-0568.
0x43434343/CVE-2019-0539
CVE-2019-0604 (2019-03-05)
A remote code execution vulnerability exists in Microsoft SharePoint when the software fails to check the source markup of an application package, aka 'Microsoft SharePoint Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-0594.
linhlhq/CVE-2019-0604
likescam/CVE-2019-0604_sharepoint_CVE
k8gege/CVE-2019-0604
m5050/CVE-2019-0604
boxhg/CVE-2019-0604
CVE-2019-0623 (2019-03-05)
An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'.
DreamoneOnly/CVE-2019-0623-32-exp
CVE-2019-0678 (2019-04-08)
An elevation of privilege vulnerability exists when Microsoft Edge does not properly enforce cross-domain policies, which could allow an attacker to access information from one domain and inject it into another domain.In a web-based attack scenario, an attacker could host a website that is used to attempt to exploit the vulnerability, aka 'Microsoft Edge Elevation of Privilege Vulnerability'.
c0d3G33k/CVE-2019-0678
CVE-2019-0708 (2019-05-16)
A remote code execution vulnerability exists in Remote Desktop Services formerly known as Terminal Services when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Remote Desktop Services Remote Code Execution Vulnerability'.
hook-s3c/CVE-2019-0708-poc
SherlockSec/CVE-2019-0708
yetiddbb/CVE-2019-0708-PoC
p0p0p0/CVE-2019-0708-exploit
rockmelodies/CVE-2019-0708-Exploit
matengfei000/CVE-2019-0708
xiyangzuishuai/Dark-Network-CVE-2019-0708
temp-user-2014/CVE-2019-0708
areusecure/CVE-2019-0708
pry0cc/cve-2019-0708-2
sbkcbig/CVE-2019-0708-EXPloit
sbkcbig/CVE-2019-0708-EXPloit-3389
YSheldon/MS_T120
k8gege/CVE-2019-0708
hotdog777714/RDS_CVE-2019-0708
jiansiting/CVE-2019-0708
NullByteSuiteDevs/CVE-2019-0708
thugcrowd/CVE-2019-0708
blacksunwen/CVE-2019-0708
infenet/CVE-2019-0708
n0auth/CVE-2019-0708
gildaaa/CVE-2019-0708
sbkcbig/CVE-2019-0708-Poc-exploit
HackerJ0e/CVE-2019-0708
syriusbughunt/CVE-2019-0708
Barry-McCockiner/CVE-2019-0708
ShadowBrokers-ExploitLeak/CVE-2019-0708
safly/CVE-2019-0708
Jaky5155/cve-2019-0708-exp
fourtwizzy/CVE-2019-0708-Check-Device-Patch-Status
303sec/CVE-2019-0708
f8al/CVE-2019-0708-POC
blockchainguard/CVE-2019-0708
haoge8090/CVE-2019-0708
yushiro/CVE-2019-0708
skyshell20082008/CVE-2019-0708-PoC-Hitting-Path
ttsite/CVE-2019-0708-
ttsite/CVE-2019-0708
biggerwing/CVE-2019-0708-poc
n1xbyte/CVE-2019-0708
freeide/CVE-2019-0708
edvacco/CVE-2019-0708-POC
pry0cc/BlueKeepTracker
zjw88282740/CVE-2019-0708-win7
zerosum0x0/CVE-2019-0708
herhe/CVE-2019-0708poc
l9c/rdp0708scanner
major203/cve-2019-0708-scan
SugiB3o/Check-vuln-CVE-2019-0708
gobysec/CVE-2019-0708
adalenv/CVE-2019-0708-Tool
smallFunction/CVE-2019-0708-POC
freeide/CVE-2019-0708-PoC-Exploit
robertdavidgraham/rdpscan
closethe/CVE-2019-0708-POC
krivegasa/Mass-scanner-for-CVE-2019-0708-RDP-RCE-Exploit
Rostelecom-CERT/bluekeepscan
Leoid/CVE-2019-0708
ht0Ruial/CVE-2019-0708Poc-BatchScanning
oneoy/BlueKeep
infiniti-team/CVE-2019-0708
haishanzheng/CVE-2019-0708-generate-hosts
Ekultek/BlueKeep
UraSecTeam/CVE-2019-0708
Gh0st0ne/rdpscan-BlueKeep
algo7/bluekeep_CVE-2019-0708_poc_to_exploit
JasonLOU/CVE-2019-0708
shun-gg/CVE-2019-0708
AdministratorGithub/CVE-2019-0708
umarfarook882/CVE-2019-0708
HynekPetrak/detect_bluekeep.py
Wileysec/CVE-2019-0708-Batch-Blue-Screen
Pa55w0rd/CVE-2019-0708
at0mik/CVE-2019-0708-PoC
cream-sec/CVE-2019-0708-Msf--
wdfcc/CVE-2019-0708
cvencoder/cve-2019-0708
ze0r/CVE-2019-0708-exp
mekhalleh/cve-2019-0708
cve-2019-0708-poc/cve-2019-0708
andripwn/CVE-2019-0708
0xeb-bp/bluekeep
ntkernel0/CVE-2019-0708
dorkerdevil/Remote-Desktop-Services-Remote-Code-Execution-Vulnerability-CVE-2019-0708-
turingcompl33t/bluekeep
fade-vivida/CVE-2019-0708-test
skommando/CVE-2019-0708
RickGeex/msf-module-CVE-2019-0708
wqsemc/CVE-2019-0708
mai-lang-chai/CVE-2019-0708-RCE
Micr067/CVE-2019-0708RDP-MSF
cpkkcb/CVE-2019-0708-BlueKeep
FrostsaberX/CVE-2019-0708
qing-root/CVE-2019-0708-EXP-MSF-
distance-vector/CVE-2019-0708
0xFlag/CVE-2019-0708-test
1aa87148377/CVE-2019-0708
coolboy4me/cve-2019-0708_bluekeep_rce
Cyb0r9/ispy
shishibabyq/CVE-2019-0708
pwnhacker0x18/Wincrash
R4v3nG/CVE-2019-0708-DOS
lwtz/CVE-2019-0708
ulisesrc/-2-CVE-2019-0708
worawit/CVE-2019-0708
cbwang505/CVE-2019-0708-EXP-Windows
eastmountyxz/CVE-2019-0708-Windows
JSec1337/Scanner-CVE-2019-0708
nochemax/bLuEkEeP-GUI
AaronWilsonGrylls/CVE-2019-0708-POC
alexa872/CVE-2019-0708
sinlee1/CVE-2019-0708
go-bi/CVE-2019-0708-EXP-Windows
CVE-2019-0709 (2019-06-12)
A remote code execution vulnerability exists when Windows Hyper-V on a host server fails to properly validate input from an authenticated user on a guest operating system, aka 'Windows Hyper-V Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-0620, CVE-2019-0722.
YHZX2013/CVE-2019-0709
qq431169079/CVE-2019-0709
CVE-2019-0752 (2019-04-09)
A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Internet Explorer, aka 'Scripting Engine Memory Corruption Vulnerability'. This CVE ID is unique from CVE-2019-0739, CVE-2019-0753, CVE-2019-0862.
CreatePhotonW/CVE-2019-0752
CVE-2019-0768 (2019-04-08)
A security feature bypass vulnerability exists when Internet Explorer VBScript execution policy does not properly restrict VBScript under specific conditions, and to allow requests that should otherwise be ignored, aka 'Internet Explorer Security Feature Bypass Vulnerability'. This CVE ID is unique from CVE-2019-0761.
ruthlezs/ie11_vbscript_exploit
CVE-2019-0785 (2019-07-15)
A memory corruption vulnerability exists in the Windows Server DHCP service when an attacker sends specially crafted packets to a DHCP failover server, aka 'Windows DHCP Server Remote Code Execution Vulnerability'.
Jaky5155/CVE-2019-0785
CVE-2019-0803 (2019-04-09)
An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-0685, CVE-2019-0859.
ExpLife0011/CVE-2019-0803
CVE-2019-0808 (2019-04-08)
An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-0797.
ze0r/cve-2019-0808-poc
rakesh143/CVE-2019-0808
exodusintel/CVE-2019-0808
DreamoneOnly/CVE-2019-0808-32-64-exp
CVE-2019-0841 (2019-04-09)
An elevation of privilege vulnerability exists when Windows AppX Deployment Service (AppXSVC) improperly handles hard links, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-0730, CVE-2019-0731, CVE-2019-0796, CVE-2019-0805, CVE-2019-0836.
rogue-kdc/CVE-2019-0841
likescam/CVE-2019-0841
0x00-0x00/CVE-2019-0841-BYPASS
CVE-2019-0859 (2019-04-09)
An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-0685, CVE-2019-0803.
Sheisback/CVE-2019-0859-1day-Exploit
CVE-2019-0887 (2019-07-15)
A remote code execution vulnerability exists in Remote Desktop Services - formerly known as Terminal Services - when an authenticated attacker abuses clipboard redirection, aka 'Remote Desktop Services Remote Code Execution Vulnerability'.
qianshuidewajueji/CVE-2019-0887
t43Wiu6/CVE-2019-0887
CVE-2019-0888 (2019-06-12)
A remote code execution vulnerability exists in the way that ActiveX Data Objects (ADO) handle objects in memory, aka 'ActiveX Data Objects (ADO) Remote Code Execution Vulnerability'.
sophoslabs/CVE-2019-0888
CVE-2019-0986 (2019-06-12)
An elevation of privilege vulnerability exists when the Windows User Profile Service (ProfSvc) improperly handles symlinks, aka 'Windows User Profile Service Elevation of Privilege Vulnerability'.
padovah4ck/CVE-2019-0986
CVE-2019-1040 (2019-06-12)
A tampering vulnerability exists in Microsoft Windows when a man-in-the-middle attacker is able to successfully bypass the NTLM MIC (Message Integrity Check) protection, aka 'Windows NTLM Tampering Vulnerability'.
Ridter/CVE-2019-1040
Ridter/CVE-2019-1040-dcpwn
lazaars/UltraRealy_with_CVE-2019-1040
fox-it/cve-2019-1040-scanner
wzxmt/CVE-2019-1040
QAX-A-Team/dcpwn
CVE-2019-1064 (2019-06-12)
An elevation of privilege vulnerability exists when Windows AppX Deployment Service (AppXSVC) improperly handles hard links, aka 'Windows Elevation of Privilege Vulnerability'.
RythmStick/CVE-2019-1064
0x00-0x00/CVE-2019-1064
attackgithub/CVE-2019-1064
CVE-2019-1069 (2019-06-12)
An elevation of privilege vulnerability exists in the way the Task Scheduler Service validates certain file operations, aka 'Task Scheduler Elevation of Privilege Vulnerability'.
S3cur3Th1sSh1t/SharpPolarBear
CVE-2019-1083 (2019-07-15)
A denial of service vulnerability exists when Microsoft Common Object Runtime Library improperly handles web requests, aka '.NET Denial of Service Vulnerability'.
stevenseeley/HowCVE-2019-1083Works
CVE-2019-1096 (2019-07-15)
An information disclosure vulnerability exists when the win32k component improperly provides kernel information, aka 'Win32k Information Disclosure Vulnerability'.
CrackerCat/cve-2019-1096-poc
CVE-2019-1108 (2019-07-29)
An information disclosure vulnerability exists when the Windows RDP client improperly discloses the contents of its memory, aka 'Remote Desktop Protocol Client Information Disclosure Vulnerability'.
Lanph3re/cve-2019-1108
CVE-2019-1125 (2019-09-03)
An information disclosure vulnerability exists when certain central processing units (CPU) speculatively access memory, aka 'Windows Kernel Information Disclosure Vulnerability'. This CVE ID is unique from CVE-2019-1071, CVE-2019-1073.
bitdefender/swapgs-attack-poc
CVE-2019-1132 (2019-07-29)
An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'.
Vlad-tri/CVE-2019-1132
petercc/CVE-2019-1132
CVE-2019-1181 (2019-08-14)
A remote code execution vulnerability exists in Remote Desktop Services â€“ formerly known as Terminal Services â€“ when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Remote Desktop ServicesÂ Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-1182, CVE-2019-1222, CVE-2019-1226.
major203/cve-2019-1181
CVE-2019-1215 (2019-09-11)
An elevation of privilege vulnerability exists in the way that ws2ifsl.sys (Winsock) handles objects in memory, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1253, CVE-2019-1278, CVE-2019-1303.
bluefrostsecurity/CVE-2019-1215
CVE-2019-1218 (2019-08-14)
A spoofing vulnerability exists in the way Microsoft Outlook iOS software parses specifically crafted email messages, aka 'Outlook iOS Spoofing Vulnerability'.
d0gukank/CVE-2019-1218
CVE-2019-1221 (2019-09-11)
A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Internet Explorer, aka 'Scripting Engine Memory Corruption Vulnerability'.
CreatePhotonW/CVE-2019-1221
CVE-2019-1253 (2019-09-11)
An elevation of privilege vulnerability exists when the Windows AppX Deployment Server improperly handles junctions.To exploit this vulnerability, an attacker would first have to gain execution on the victim system, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1215, CVE-2019-1278, CVE-2019-1303.
rogue-kdc/CVE-2019-1253
likescam/CVE-2019-1253
padovah4ck/CVE-2019-1253
sgabe/CVE-2019-1253
CVE-2019-1315 (2019-10-10)
An elevation of privilege vulnerability exists when Windows Error Reporting manager improperly handles hard links, aka 'Windows Error Reporting Manager Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1339, CVE-2019-1342.
Mayter/CVE-2019-1315
CVE-2019-1351 (2020-01-24)
A tampering vulnerability exists when Git for Visual Studio improperly handles virtual drive paths, aka 'Git for Visual Studio Tampering Vulnerability'.
JonasDL/PruebaCVE20191351
CVE-2019-1367 (2019-09-23)
A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Internet Explorer, aka 'Scripting Engine Memory Corruption Vulnerability'. This CVE ID is unique from CVE-2019-1221.
mandarenmanman/CVE-2019-1367
CVE-2019-1385 (2019-11-12)
An elevation of privilege vulnerability exists when the Windows AppX Deployment Extensions improperly performs privilege management, resulting in access to system files.To exploit this vulnerability, an authenticated attacker would need to run a specially crafted application to elevate privileges.The security update addresses the vulnerability by correcting how AppX Deployment Extensions manages privileges., aka 'Windows AppX Deployment Extensions Elevation of Privilege Vulnerability'.
klinix5/CVE-2019-1385
0x413x4/CVE-2019-1385
CVE-2019-1388 (2019-11-12)
An elevation of privilege vulnerability exists in the Windows Certificate Dialog when it does not properly enforce user privileges, aka 'Windows Certificate Dialog Elevation of Privilege Vulnerability'.
jas502n/CVE-2019-1388
jaychouzzk/CVE-2019-1388
sv3nbeast/CVE-2019-1388
CVE-2019-1402 (2019-11-12)
An information disclosure vulnerability exists in Microsoft Office software when the software fails to properly handle objects in memory, aka 'Microsoft Office Information Disclosure Vulnerability'.
lauxjpn/CorruptQueryAccessWorkaround
CVE-2019-1405 (2019-11-12)
An elevation of privilege vulnerability exists when the Windows Universal Plug and Play (UPnP) service improperly allows COM object creation, aka 'Windows UPnP Service Elevation of Privilege Vulnerability'.
apt69/COMahawk
CVE-2019-1422 (2019-11-12)
An elevation of privilege vulnerability exists in the way that the iphlpsvc.dll handles file creation allowing for a file overwrite, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1420, CVE-2019-1423.
ze0r/cve-2019-1422
CVE-2019-1458 (2019-12-10)
An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'.
piotrflorczyk/cve-2019-1458_POC
unamer/CVE-2019-1458
DreamoneOnly/CVE-2019-1458-malware
CVE-2019-1476 (2019-12-10)
An elevation of privilege vulnerability exists when Windows AppX Deployment Service (AppXSVC) improperly handles hard links, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1483.
sgabe/CVE-2019-1476
CVE-2019-1477 (2019-12-10)
An elevation of privilege vulnerability exists when the Windows Printer Service improperly validates file paths while loading printer drivers, aka 'Windows Printer Service Elevation of Privilege Vulnerability'.
intellee/CVE-2019-1477
CVE-2019-1579 (2019-07-19)
Remote Code Execution in PAN-OS 7.1.18 and earlier, PAN-OS 8.0.11-h1 and earlier, and PAN-OS 8.1.2 and earlier with GlobalProtect Portal or GlobalProtect Gateway Interface enabled may allow an unauthenticated remote attacker to execute arbitrary code.
securifera/CVE-2019-1579
Elsfa7-110/CVE-2019-1579
CVE-2019-1653 (2019-01-24)
A vulnerability in the web-based management interface of Cisco Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers could allow an unauthenticated, remote attacker to retrieve sensitive information. The vulnerability is due to improper access controls for URLs. An attacker could exploit this vulnerability by connecting to an affected device via HTTP or HTTPS and requesting specific URLs. A successful exploit could allow the attacker to download the router configuration or detailed diagnostic information. Cisco has released firmware updates that address this vulnerability.
shaheemirza/CiscoSpill
CVE-2019-1759 (2019-03-27)
A vulnerability in access control list (ACL) functionality of the Gigabit Ethernet Management interface of Cisco IOS XE Software could allow an unauthenticated, remote attacker to reach the configured IP addresses on the Gigabit Ethernet Management interface. The vulnerability is due to a logic error that was introduced in the Cisco IOS XE Software 16.1.1 Release, which prevents the ACL from working when applied against the management interface. An attacker could exploit this issue by attempting to access the device via the management interface.
r3m0t3nu11/CVE-2019-1759-csrf-js-rce
CVE-2019-1821 (2019-05-15)
A vulnerability in the web-based management interface of Cisco Prime Infrastructure (PI) and Cisco Evolved Programmable Network (EPN) Manager could allow an authenticated, remote attacker to execute code with root-level privileges on the underlying operating system. This vulnerability exist because the software improperly validates user-supplied input. An attacker could exploit this vulnerability by uploading a malicious file to the administrative web interface. A successful exploit could allow the attacker to execute code with root-level privileges on the underlying operating system.
k8gege/CiscoExploit
CVE-2019-1987 (2019-02-28)
In onSetSampleX of SkSwizzler.cpp, there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution with no additional execution privileges needed. User interaction is needed for exploitation. Product: Android. Versions: Android-7.0 Android-7.1.1 Android-7.1.2 Android-8.0 Android-8.1 Android-9. Android ID: A-118143775.
marcinguy/android-7-9-png-bug
CVE-2019-2107 (2019-07-08)
In ihevcd_parse_pps of ihevcd_parse_headers.c, there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution with no additional execution privileges needed. User interaction is needed for exploitation. Product: Android. Versions: Android-7.0 Android-7.1.1 Android-7.1.2 Android-8.0 Android-8.1 Android-9. Android ID: A-130024844.
marcinguy/CVE-2019-2107
infiniteLoopers/CVE-2019-2107
CVE-2019-2196 (2019-11-13)
In Download Provider, there is possible SQL injection. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9 Android-10Android ID: A-135269143
IOActive/AOSP-DownloadProviderDbDumperSQLiLimit
CVE-2019-2198 (2019-11-13)
In Download Provider, there is a possible SQL injection vulnerability. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9 Android-10Android ID: A-135270103
IOActive/AOSP-DownloadProviderDbDumperSQLiWhere
CVE-2019-2215 (2019-10-11)
A use-after-free in binder.c allows an elevation of privilege from an application to the Linux Kernel. No user interaction is required to exploit this vulnerability, however exploitation does require either the installation of a malicious local application or a separate vulnerability in a network facing application.Product: AndroidAndroid ID: A-141720095
timwr/CVE-2019-2215
raystyle/CVE-2019-2215
kangtastic/cve-2019-2215
marcinguy/CVE-2019-2215
LIznzn/CVE-2019-2215
DimitriFourny/cve-2019-2215
qre0ct/android-kernel-exploitation-ashfaq-CVE-2019-2215
sharif-dev/AndroidKernelVulnerability
c3r34lk1ll3r/CVE-2019-2215
CVE-2019-2525 (2019-01-16)
Vulnerability in the Oracle VM VirtualBox component of Oracle Virtualization (subcomponent: Core). Supported versions that are affected are prior to 5.2.24 and prior to 6.0.2. Difficult to exploit vulnerability allows low privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle VM VirtualBox accessible data. CVSS 3.0 Base Score 5.6 (Confidentiality impacts). CVSS Vector: (CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N).
Phantomn/VirtualBox_CVE-2019-2525-CVE-2019-2548
wotmd/VirtualBox-6.0.0-Exploit-1-day
CVE-2019-2615 (2019-04-23)
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 4.9 (Confidentiality impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N).
chiaifan/CVE-2019-2615
CVE-2019-2618 (2019-04-23)
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data as well as unauthorized update, insert or delete access to some of Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 5.5 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N).
pyn3rd/CVE-2019-2618
jas502n/cve-2019-2618
wsfengfan/CVE-2019-2618-
dr0op/WeblogicScan
he1dan/cve-2019-2618
ianxtianxt/cve-2019-2618
0xn0ne/weblogicScanner
CVE-2019-2725 (2019-04-26)
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services). Supported versions that are affected are 10.3.6.0.0 and 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
shack2/javaserializetools
SkyBlueEternal/CNVD-C-2019-48814-CNNVD-201904-961
iceMatcha/CNTA-2019-0014xCVE-2019-2725
lasensio/cve-2019-2725
davidmthomsen/CVE-2019-2725
leerina/CVE-2019-2725
zhusx110/cve-2019-2725
lufeirider/CVE-2019-2725
CVCLabs/cve-2019-2725
TopScrew/CVE-2019-2725
welove88888/CVE-2019-2725
jiansiting/CVE-2019-2725
kerlingcode/CVE-2019-2725
black-mirror/Weblogic
pimps/CVE-2019-2725
ianxtianxt/CVE-2019-2725
N0b1e6/CVE-2019-2725-POC
GGyao/weblogic_2019_2725_wls_batch
ludy-dev/Oracle-WLS-Weblogic-RCE
CVE-2019-2729 (2019-06-19)
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
waffl3ss/CVE-2019-2729
ruthlezs/CVE-2019-2729-Exploit
CVE-2019-2888 (2019-10-16)
Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: EJB Container). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized read access to a subset of Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 5.3 (Confidentiality impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N).
21superman/weblogic_cve-2019-2888
jas502n/CVE-2019-2888
CVE-2019-2890 (2019-10-16)
Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Web Services). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0. Easily exploitable vulnerability allows high privileged attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 7.2 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H).
ZO1RO/CVE-2019-2890
Ky0-HVA/CVE-2019-2890
SukaraLin/CVE-2019-2890
jas502n/CVE-2019-2890
ianxtianxt/CVE-2019-2890
zhzhdoai/Weblogic_Vuln
CVE-2019-3010 (2019-10-16)
Vulnerability in the Oracle Solaris product of Oracle Systems (component: XScreenSaver). The supported version that is affected is 11. Easily exploitable vulnerability allows low privileged attacker with logon to the infrastructure where Oracle Solaris executes to compromise Oracle Solaris. While the vulnerability is in Oracle Solaris, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Oracle Solaris. CVSS 3.0 Base Score 8.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H).
chaizeg/privilege-escalation-breach
CVE-2019-3394 (2019-08-29)
There was a local file disclosure vulnerability in Confluence Server and Confluence Data Center via page exporting. An attacker with permission to editing a page is able to exploit this issue to read arbitrary file on the server under <install-directory>/confluence/WEB-INF directory, which may contain configuration files used for integrating with other services, which could potentially leak credentials or other sensitive information such as LDAP credentials. The LDAP credential will be potentially leaked only if the Confluence server is configured to use LDAP as user repository. All versions of Confluence Server from 6.1.0 before 6.6.16 (the fixed version for 6.6.x), from 6.7.0 before 6.13.7 (the fixed version for 6.13.x), and from 6.14.0 before 6.15.8 (the fixed version for 6.15.x) are affected by this vulnerability.
jas502n/CVE-2019-3394
CVE-2019-3396 (2019-03-25)
The Widget Connector macro in Atlassian Confluence Server before version 6.6.12 (the fixed version for 6.6.x), from version 6.7.0 before 6.12.3 (the fixed version for 6.12.x), from version 6.13.0 before 6.13.3 (the fixed version for 6.13.x), and from version 6.14.0 before 6.14.2 (the fixed version for 6.14.x), allows remote attackers to achieve path traversal and remote code execution on a Confluence Server or Data Center instance via server-side template injection.
dothanthitiendiettiende/CVE-2019-3396
x-f1v3/CVE-2019-3396
xiaoshuier/CVE-2019-3396
Yt1g3r/CVE-2019-3396_EXP
jas502n/CVE-2019-3396
pyn3rd/CVE-2019-3396
s1xg0d/CVE-2019-3396
quanpt103/CVE-2019-3396
vntest11/confluence_CVE-2019-3396
tanw923/test1
skommando/CVE-2019-3396-confluence-poc
JonathanZhou348/CVE-2019-3396TEST
am6539/CVE-2019-3396
W2Ning/CVE-2019-3396
yuehanked/cve-2019-3396
CVE-2019-3398 (2019-04-18)
Confluence Server and Data Center had a path traversal vulnerability in the downloadallattachments resource. A remote attacker who has permission to add attachments to pages and / or blogs or to create a new space or a personal space or who has 'Admin' permissions for a space can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Confluence Server or Data Center. All versions of Confluence Server from 2.0.0 before 6.6.13 (the fixed version for 6.6.x), from 6.7.0 before 6.12.4 (the fixed version for 6.12.x), from 6.13.0 before 6.13.4 (the fixed version for 6.13.x), from 6.14.0 before 6.14.3 (the fixed version for 6.14.x), and from 6.15.0 before 6.15.2 are affected by this vulnerability.
superevr/cve-2019-3398
CVE-2019-3663 (2019-11-13)
Unprotected Storage of Credentials vulnerability in McAfee Advanced Threat Defense (ATD) prior to 4.8 allows local attacker to gain access to the root password via accessing sensitive files on the system. This was originally published with a CVSS rating of High, further investigation has resulted in this being updated to Critical. The root password is common across all instances of ATD prior to 4.8. See the Security bulletin for further details
funoverip/mcafee_atd_CVE-2019-3663
CVE-2019-3719 (2019-04-18)
Dell SupportAssist Client versions prior to 3.2.0.90 contain a remote code execution vulnerability. An unauthenticated attacker, sharing the network access layer with the vulnerable system, can compromise the vulnerable system by tricking a victim user into downloading and executing arbitrary executables via SupportAssist client from attacker hosted sites.
jiansiting/CVE-2019-3719
CVE-2019-3778 (2019-03-07)
Spring Security OAuth, versions 2.3 prior to 2.3.5, and 2.2 prior to 2.2.4, and 2.1 prior to 2.1.4, and 2.0 prior to 2.0.17, and older unsupported versions could be susceptible to an open redirector attack that can leak an authorization code. A malicious user or attacker can craft a request to the authorization endpoint using the authorization code grant type, and specify a manipulated redirection URI via the "redirect_uri" parameter. This can cause the authorization server to redirect the resource owner user-agent to a URI under the control of the attacker with the leaked authorization code. This vulnerability exposes applications that meet all of the following requirements: Act in the role of an Authorization Server (e.g. @EnableAuthorizationServer) and uses the DefaultRedirectResolver in the AuthorizationEndpoint. This vulnerability does not expose applications that: Act in the role of an Authorization Server and uses a different RedirectResolver implementation other than DefaultRedirectResolver, act in the role of a Resource Server only (e.g. @EnableResourceServer), act in the role of a Client only (e.g. @EnableOAuthClient).
BBB-man/CVE-2019-3778-Spring-Security-OAuth-2.3-Open-Redirection
CVE-2019-3799 (2019-05-06)
Spring Cloud Config, versions 2.1.x prior to 2.1.2, versions 2.0.x prior to 2.0.4, and versions 1.4.x prior to 1.4.6, and older unsupported versions allow applications to serve arbitrary configuration files through the spring-cloud-config-server module. A malicious user, or attacker, can send a request using a specially crafted URL that can lead a directory traversal attack.
mpgn/CVE-2019-3799
CVE-2019-3847 (2019-03-27)
A vulnerability was found in moodle before versions 3.6.3, 3.5.5, 3.4.8 and 3.1.17. Users with the "login as other users" capability (such as administrators/managers) can access other users' Dashboards, but the JavaScript those other users may have added to their Dashboard was not being escaped when being viewed by the user logging in on their behalf.
danielthatcher/moodle-login-csrf
CVE-2019-3929 (2019-04-30)
The Crestron AM-100 firmware 1.6.0.2, Crestron AM-101 firmware 2.7.0.1, Barco wePresent WiPG-1000P firmware 2.3.0.10, Barco wePresent WiPG-1600W before firmware 2.4.1.19, Extron ShareLink 200/250 firmware 2.0.3.4, Teq AV IT WIPS710 firmware 1.1.0.7, SHARP PN-L703WA firmware 1.4.2.3, Optoma WPS-Pro firmware 1.0.0.5, Blackbox HD WPS firmware 1.0.0.5, InFocus LiteShow3 firmware 1.0.16, and InFocus LiteShow4 2.0.0.7 are vulnerable to command injection via the file_transfer.cgi HTTP endpoint. A remote, unauthenticated attacker can use this vulnerability to execute operating system commands as root.
xfox64x/CVE-2019-3929
CVE-2019-3980 (2019-10-08)
The Solarwinds Dameware Mini Remote Client agent v12.1.0.89 supports smart card authentication which can allow a user to upload an executable to be executed on the DWRCS.exe host. An unauthenticated, remote attacker can request smart card login and upload and execute an arbitrary executable run under the Local System account.
warferik/CVE-2019-3980
CVE-2019-5010 (2019-10-31)
An exploitable denial-of-service vulnerability exists in the X509 certificate parser of Python.org Python 2.7.11 / 3.6.6. A specially crafted X509 certificate can cause a NULL pointer dereference, resulting in a denial of service. An attacker can initiate or accept TLS connections using crafted certificates to trigger this vulnerability.
JonathanWilbur/CVE-2019-5010
CVE-2019-5096 (2019-12-03)
An exploitable code execution vulnerability exists in the processing of multi-part/form-data requests within the base GoAhead web server application in versions v5.0.1, v.4.1.1 and v3.6.5. A specially crafted HTTP request can lead to a use-after-free condition during the processing of this request that can be used to corrupt heap structures that could lead to full code execution. The request can be unauthenticated in the form of GET or POST requests, and does not require the requested resource to exist on the server.
papinnon/CVE-2019-5096-GoAhead-Web-Server-Dos-Exploit
CVE-2019-5170 (2020-03-11)
An exploitable command injection vulnerability exists in the iocheckd service ‘I/O-Check’ function of the WAGO PFC 200 Firmware version 03.02.02(14). A specially crafted XML cache file written to a specific location on the device can be used to inject OS commands. An attacker can send a specially crafted packet to trigger the parsing of this cache file.At 0x1e87c the extracted hostname value from the xml file is used as an argument to /etc/config-tools/change_hostname hostname=<contents of hostname node> using sprintf(). This command is later executed via a call to system().
ClarotyICS/CVE-2019-5170
CVE-2019-5418 (2019-03-27)
There is a File Content Disclosure vulnerability in Action View <5.2.2.1, <5.1.6.2, <5.0.7.2, <4.2.11.1 and v3 where specially crafted accept headers can cause contents of arbitrary files on the target system's filesystem to be exposed.
mpgn/CVE-2019-5418
omarkurt/CVE-2019-5418
brompwnie/CVE-2019-5418-Scanner
mpgn/Rails-doubletap-RCE
takeokunn/CVE-2019-5418
Bad3r/RailroadBandit
ztgrace/CVE-2019-5418-Rails3
random-robbie/CVE-2019-5418
CVE-2019-5420 (2019-03-27)
A remote code execution vulnerability in development mode Rails <5.2.2.1, <6.0.0.beta3 can allow an attacker to guess the automatically generated development mode secret token. This secret token can be used in combination with other Rails internals to escalate to a remote code execution exploit.
knqyf263/CVE-2019-5420
cved-sources/cve-2019-5420
AnasTaoutaou/CVE-2019-5420
CVE-2019-5427 (2019-04-22)
c3p0 version < 0.9.5.4 may be exploited by a billion laughs attack when loading XML configuration due to missing protections against recursive entity expansion when loading configuration.
shanika04/cp30_XXE_partial_fix
CVE-2019-5454 (2019-07-30)
SQL Injection in the Nextcloud Android app prior to version 3.0.0 allows to destroy a local cache when a harmful query is executed requiring to resetup the account.
shanika04/nextcloud_android
CVE-2019-5475 (2019-09-03)
The Nexus Yum Repository Plugin in v2 is vulnerable to Remote Code Execution when instances using CommandLineExecutor.java are supplied vulnerable data, such as the Yum Configuration Capability.
jaychouzzk/CVE-2019-5475-Nexus-Repository-Manager-
rabbitmask/CVE-2019-5475-EXP
lyy289065406/CVE-2019-5475
CVE-2019-5489 (2019-01-07)
The mincore() implementation in mm/mincore.c in the Linux kernel through 4.19.13 allowed local attackers to observe page cache access patterns of other processes on the same system, potentially allowing sniffing of secret information. (Fixing this affects the output of the fincore program.) Limited remote exploitation may be possible, as demonstrated by latency differences in accessing public files from an Apache HTTP Server.
mmxsrup/CVE-2019-5489
CVE-2019-5544 (2019-12-06)
OpenSLP as used in ESXi and the Horizon DaaS appliances has a heap overwrite issue. VMware has evaluated the severity of this issue to be in the Critical severity range with a maximum CVSSv3 base score of 9.8.
HynekPetrak/CVE-2019-5544_CVE-2020-3992
CVE-2019-5624 (2019-04-30)
Rapid7 Metasploit Framework suffers from an instance of CWE-22, Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in the Zip import function of Metasploit. Exploiting this vulnerability can allow an attacker to execute arbitrary code in Metasploit at the privilege level of the user running Metasploit. This issue affects: Rapid7 Metasploit Framework version 4.14.0 and prior versions.
VoidSec/CVE-2019-5624
CVE-2019-5630 (2019-07-03)
A Cross-Site Request Forgery (CSRF) vulnerability was found in Rapid7 Nexpose InsightVM Security Console versions 6.5.0 through 6.5.68. This issue allows attackers to exploit CSRF vulnerabilities on API endpoints using Flash to circumvent a cross-domain pre-flight OPTIONS request.
rbeede/CVE-2019-5630
CVE-2019-5700 (2019-10-09)
NVIDIA Shield TV Experience prior to v8.0.1, NVIDIA Tegra software contains a vulnerability in the bootloader, where it does not validate the fields of the boot image, which may lead to code execution, denial of service, escalation of privileges, and information disclosure.
oscardagrach/CVE-2019-5700
CVE-2019-5736 (2019-02-11)
runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.
q3k/cve-2019-5736-poc
Frichetten/CVE-2019-5736-PoC
agppp/cve-2019-5736-poc
b3d3c/poc-cve-2019-5736
twistlock/RunC-CVE-2019-5736
yyqs2008/CVE-2019-5736-PoC-2
zyriuse75/CVE-2019-5736-PoC
stillan00b/CVE-2019-5736
milloni/cve-2019-5736-exp
13paulmurith/Docker-Runc-Exploit
RyanNgWH/CVE-2019-5736-POC
Lee-SungYoung/cve-2019-5736-study
chosam2/cve-2019-5736-poc
epsteina16/Docker-Escape-Miner
GiverOfGifts/CVE-2019-5736-Custom-Runtime
Billith/CVE-2019-5736-PoC
BBRathnayaka/POC-CVE-2019-5736
shen54/IT19172088
CVE-2019-5737 (2019-03-28)
In Node.js including 6.x before 6.17.0, 8.x before 8.15.1, 10.x before 10.15.2, and 11.x before 11.10.1, an attacker can cause a Denial of Service (DoS) by establishing an HTTP or HTTPS connection in keep-alive mode and by sending headers very slowly. This keeps the connection and associated resources alive for a long period of time. Potential attacks are mitigated by the use of a load balancer or other proxy layer. This vulnerability is an extension of CVE-2018-12121, addressed in November and impacts all active Node.js release lines including 6.x before 6.17.0, 8.x before 8.15.1, 10.x before 10.15.2, and 11.x before 11.10.1.
beelzebruh/cve-2019-5737
CVE-2019-5782 (2019-02-19)
Incorrect optimization assumptions in V8 in Google Chrome prior to 72.0.3626.81 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page.
CreatePhotonW/CVE-2019-5782_CVE-2019-13768
CVE-2019-5786 (2019-06-27)
Object lifetime issue in Blink in Google Chrome prior to 72.0.3626.121 allowed a remote attacker to potentially perform out of bounds memory access via a crafted HTML page.
exodusintel/CVE-2019-5786
CVE-2019-5822 (2019-06-27)
Inappropriate implementation in Blink in Google Chrome prior to 74.0.3729.108 allowed a remote attacker to bypass same origin policy via a crafted HTML page.
Silence-Rain/14-828_Exploitation_of_CVE-2019-5822
CVE-2019-5825 (2019-11-25)
Out of bounds write in JavaScript in Google Chrome prior to 73.0.3683.86 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.
timwr/CVE-2019-5825
CVE-2019-6111 (2019-01-31)
An issue was discovered in OpenSSH 7.9. Due to the scp implementation being derived from 1983 rcp, the server chooses which files/directories are sent to the client. However, the scp client only performs cursory validation of the object name returned (only directory traversal attacks are prevented). A malicious scp server (or Man-in-The-Middle attacker) can overwrite arbitrary files in the scp client target directory. If recursive operation (-r) is performed, the server can manipulate subdirectories as well (for example, to overwrite the .ssh/authorized_keys file).
53n7hu/SNP
CVE-2019-6203 (2020-04-17)
A logic issue was addressed with improved state management. This issue is fixed in iOS 12.2, macOS Mojave 10.14.4, tvOS 12.2. An attacker in a privileged network position may be able to intercept network traffic.
qingxp9/CVE-2019-6203-PoC
CVE-2019-6207 (2019-12-18)
An out-of-bounds read issue existed that led to the disclosure of kernel memory. This was addressed with improved input validation. This issue is fixed in iOS 12.2, macOS Mojave 10.14.4, tvOS 12.2, watchOS 5.2. A malicious application may be able to determine kernel memory layout.
dothanthitiendiettiende/CVE-2019-6207
maldiohead/CVE-2019-6207
DimitriFourny/cve-2019-6207
CVE-2019-6225 (2019-03-05)
A memory corruption issue was addressed with improved validation. This issue is fixed in iOS 12.1.3, macOS Mojave 10.14.3, tvOS 12.1.2. A malicious application may be able to elevate privileges.
TrungNguyen1909/CVE-2019-6225-macOS
raystyle/jailbreak-iOS12
CVE-2019-6249 (2019-01-13)
An issue was discovered in HuCart v5.7.4. There is a CSRF vulnerability that can add an admin account via /adminsys/index.php?load=admins&act=edit_info&act_type=add.
NMTech0x90/CVE-2019-6249_Hucart-cms
CVE-2019-6260 (2019-01-22)
The ASPEED ast2400 and ast2500 Baseband Management Controller (BMC) hardware and firmware implement Advanced High-performance Bus (AHB) bridges, which allow arbitrary read and write access to the BMC's physical address space from the host (or from the network in unusual cases where the BMC console uart is attached to a serial concentrator). This CVE applies to the specific cases of iLPC2AHB bridge Pt I, iLPC2AHB bridge Pt II, PCIe VGA P2A bridge, DMA from/to arbitrary BMC memory via X-DMA, UART-based SoC Debug interface, LPC2AHB bridge, PCIe BMC P2A bridge, and Watchdog setup.
amboar/cve-2019-6260
CVE-2019-6329 (2019-06-25)
HP Support Assistant 8.7.50 and earlier allows a user to gain system privilege and allows unauthorized modification of directories or files. Note: A different vulnerability than CVE-2019-6328.
ManhNDd/CVE-2019-6329
CVE-2019-6340 (2019-02-21)
Some field types do not properly sanitize data from non-form sources in Drupal 8.5.x before 8.5.11 and Drupal 8.6.x before 8.6.10. This can lead to arbitrary PHP code execution in some cases. A site is only affected by this if one of the following conditions is met: The site has the Drupal 8 core RESTful Web Services (rest) module enabled and allows PATCH or POST requests, or the site has another web services module enabled, like JSON:API in Drupal 8, or Services or RESTful Web Services in Drupal 7. (Note: The Drupal 7 Services module itself does not require an update at this time, but you should apply other contributed updates associated with this advisory if Services is in use.)
g0rx/Drupal-SA-CORE-2019-003
knqyf263/CVE-2019-6340
DevDungeon/CVE-2019-6340-Drupal-8.6.9-REST-Auth-Bypass
oways/CVE-2019-6340
cved-sources/cve-2019-6340
d1vious/cve-2019-6340-bits
jas502n/CVE-2019-6340
ludy-dev/drupal8-REST-RCE
CVE-2019-6440 (2019-01-15)
Zemana AntiMalware before 3.0.658 Beta mishandles update logic.
hexnone/CVE-2019-6440
CVE-2019-6446 (2019-01-16)
** DISPUTED ** An issue was discovered in NumPy 1.16.0 and earlier. It uses the pickle Python module unsafely, which allows remote attackers to execute arbitrary code via a crafted serialized object, as demonstrated by a numpy.load call. NOTE: third parties dispute this issue because it is a behavior that might have legitimate applications in (for example) loading serialized Python object arrays from trusted and authenticated sources.
RayScri/CVE-2019-6446
CVE-2019-6447 (2019-01-16)
The ES File Explorer File Manager application through 4.1.9.7.4 for Android allows remote attackers to read arbitrary files or execute applications via TCP port 59777 requests on the local Wi-Fi network. This TCP port remains open after the ES application has been launched once, and responds to unauthenticated application/json data over HTTP.
SandaRuFdo/ES-File-Explorer-Open-Port-Vulnerability---CVE-2019-6447
CVE-2019-6453 (2019-02-18)
mIRC before 7.55 allows remote command execution by using argument injection through custom URI protocol handlers. The attacker can specify an irc:// URI that loads an arbitrary .ini file from a UNC share pathname. Exploitation depends on browser-specific URI handling (Chrome is not exploitable).
proofofcalc/cve-2019-6453-poc
andripwn/mIRC-CVE-2019-6453
CVE-2019-6467 (2019-10-09)
A programming error in the nxdomain-redirect feature can cause an assertion failure in query.c if the alternate namespace used by nxdomain-redirect is a descendant of a zone that is served locally. The most likely scenario where this might occur is if the server, in addition to performing NXDOMAIN redirection for recursive clients, is also serving a local copy of the root zone or using mirroring to provide the root zone, although other configurations are also possible. Versions affected: BIND 9.12.0-> 9.12.4, 9.14.0. Also affects all releases in the 9.13 development branch.
knqyf263/CVE-2019-6467
CVE-2019-6690 (2019-03-17)
python-gnupg 0.4.3 allows context-dependent attackers to trick gnupg to decrypt other ciphertext than intended. To perform the attack, the passphrase to gnupg must be controlled by the adversary and the ciphertext should be trusted. Related to a "CWE-20: Improper Input Validation" issue affecting the affect functionality component.
stigtsp/CVE-2019-6690-python-gnupg-vulnerability
brianwrf/CVE-2019-6690
CVE-2019-6715 (2019-04-01)
pub/sns.php in the W3 Total Cache plugin before 0.9.4 for WordPress allows remote attackers to read arbitrary files via the SubscribeURL field in SubscriptionConfirmation JSON data.
random-robbie/cve-2019-6715
CVE-2019-7192 (2019-12-05)
This improper access control vulnerability allows remote attackers to gain unauthorized access to the system. To fix these vulnerabilities, QNAP recommend updating Photo Station to their latest versions.
cycraft-corp/cve-2019-7192-check
th3gundy/CVE-2019-7192_QNAP_Exploit
CVE-2019-7214 (2019-04-24)
SmarterTools SmarterMail 16.x before build 6985 allows deserialization of untrusted data. An unauthenticated attacker could run commands on the server when port 17001 was remotely accessible. This port is not accessible remotely by default after applying the Build 6985 patch.
devzspy/CVE-2019-7214
CVE-2019-7219 (2019-04-11)
Unauthenticated reflected cross-site scripting (XSS) exists in Zarafa Webapp 2.0.1.47791 and earlier. NOTE: this is a discontinued product. The issue was fixed in later Zarafa Webapp versions; however, some former Zarafa Webapp customers use the related Kopano product instead.
verifysecurity/CVE-2019-7219
CVE-2019-7238 (2019-03-21)
Sonatype Nexus Repository Manager before 3.15.0 has Incorrect Access Control.
mpgn/CVE-2019-7238
jas502n/CVE-2019-7238
verctor/nexus_rce_CVE-2019-7238
magicming200/CVE-2019-7238_Nexus_RCE_Tool
CVE-2019-7304 (2019-04-23)
Canonical snapd before version 2.37.1 incorrectly performed socket owner validation, allowing an attacker to run arbitrary commands as root. This issue affects: Canonical snapd versions prior to 2.37.1.
initstring/dirty_sock
CVE-2019-7356 (2020-11-04)
Subrion CMS v4.2.1 allows XSS via the panel/phrases/ VALUE parameter.
ngpentest007/CVE-2019-7356
CVE-2019-7357 (2020-11-10)
Subrion CMS 4.2.1 has CSRF in panel/modules/plugins/. The attacker can remotely activate/deactivate the plugins.
ngpentest007/CVE-2019-7357
CVE-2019-7482 (2019-12-18)
Stack-based buffer overflow in SonicWall SMA100 allows an unauthenticated user to execute arbitrary code in function libSys.so. This vulnerability impacted SMA100 version 9.0.0.3 and earlier.
singletrackseeker/CVE-2019-7482
b4bay/CVE-2019-7482
CVE-2019-7609 (2019-03-25)
Kibana versions before 5.6.15 and 6.6.1 contain an arbitrary code execution flaw in the Timelion visualizer. An attacker with access to the Timelion application could send a request that will attempt to execute javascript code. This could possibly lead to an attacker executing arbitrary commands with permissions of the Kibana process on the host system.
jas502n/kibana-RCE
mpgn/CVE-2019-7609
LandGrey/CVE-2019-7609
hekadan/CVE-2019-7609
rhbb/CVE-2019-7609
CVE-2019-7610 (2019-03-25)
Kibana versions before 6.6.1 contain an arbitrary code execution flaw in the security audit logger. If a Kibana instance has the setting xpack.security.audit.enabled set to true, an attacker could send a request that will attempt to execute javascript code. This could possibly lead to an attacker executing arbitrary commands with permissions of the Kibana process on the host system.
whoami0622/CVE-2019-7610
CVE-2019-7616 (2019-07-30)
Kibana versions before 6.8.2 and 7.2.1 contain a server side request forgery (SSRF) flaw in the graphite integration for Timelion visualizer. An attacker with administrative Kibana access could set the timelion:graphite.url configuration option to an arbitrary URL. This could possibly lead to an attacker accessing external URL resources as the Kibana process on the host system.
random-robbie/CVE-2019-7616
CVE-2019-7642 (2019-03-25)
D-Link routers with the mydlink feature have some web interfaces without authentication requirements. An attacker can remotely obtain users' DNS query logs and login logs. Vulnerable targets include but are not limited to the latest firmware versions of DIR-817LW (A1-1.04), DIR-816L (B1-2.06), DIR-816 (B1-2.06?), DIR-850L (A1-1.09), and DIR-868L (A1-1.10).
xw77cve/CVE-2019-7642
CVE-2019-7839 (2019-06-12)
ColdFusion versions Update 3 and earlier, Update 10 and earlier, and Update 18 and earlier have a command injection vulnerability. Successful exploitation could lead to arbitrary code execution.
securifera/CVE-2019-7839
CVE-2019-8389 (2019-02-16)
A file-read vulnerability was identified in the Wi-Fi transfer feature of Musicloud 1.6. By default, the application runs a transfer service on port 8080, accessible by everyone on the same Wi-Fi network. An attacker can send the POST parameters downfiles and cur-folder (with a crafted ../ payload) to the download.script endpoint. This will create a MusicPlayerArchive.zip archive that is publicly accessible and includes the content of any requested file (such as the /etc/passwd file).
shawarkhanethicalhacker/CVE-2019-8389
CVE-2019-8446 (2019-08-23)
The /rest/issueNav/1/issueTable resource in Jira before version 8.3.2 allows remote attackers to enumerate usernames via an incorrect authorisation check.
CyberTrashPanda/CVE-2019-8446
CVE-2019-8449 (2019-09-11)
The /rest/api/latest/groupuserpicker resource in Jira before version 8.4.0 allows remote attackers to enumerate usernames via an information disclosure vulnerability.
mufeedvh/CVE-2019-8449
r0lh/CVE-2019-8449
CVE-2019-8451 (2019-09-11)
The /plugins/servlet/gadgets/makeRequest resource in Jira before version 8.4.0 allows remote attackers to access the content of internal network resources via a Server Side Request Forgery (SSRF) vulnerability due to a logic bug in the JiraWhitelist class.
0xbug/CVE-2019-8451
ianxtianxt/CVE-2019-8451
jas502n/CVE-2019-8451
h0ffayyy/Jira-CVE-2019-8451
CVE-2019-8513 (2019-12-18)
This issue was addressed with improved checks. This issue is fixed in macOS Mojave 10.14.4. A local user may be able to execute arbitrary shell commands.
genknife/cve-2019-8513
CVE-2019-8540 (2019-12-18)
A memory initialization issue was addressed with improved memory handling. This issue is fixed in iOS 12.2, macOS Mojave 10.14.4, tvOS 12.2, watchOS 5.2. A malicious application may be able to determine kernel memory layout.
maldiohead/CVE-2019-8540
CVE-2019-8565 (2019-12-18)
A race condition was addressed with additional validation. This issue is fixed in iOS 12.2, macOS Mojave 10.14.4. A malicious application may be able to gain root privileges.
genknife/cve-2019-8565
CVE-2019-8591 (2019-12-18)
A type confusion issue was addressed with improved memory handling. This issue is fixed in iOS 12.3, macOS Mojave 10.14.5, tvOS 12.3, watchOS 5.2.1. An application may be able to cause unexpected system termination or write kernel memory.
jsherman212/used_sock
CVE-2019-8601 (2019-12-18)
Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS 12.3, macOS Mojave 10.14.5, tvOS 12.3, watchOS 5.2.1, Safari 12.1.1, iTunes for Windows 12.9.5, iCloud for Windows 7.12. Processing maliciously crafted web content may lead to arbitrary code execution.
BadAccess11/CVE-2019-8601
CVE-2019-8605 (2019-12-18)
A use after free issue was addressed with improved memory management. This issue is fixed in iOS 12.3, macOS Mojave 10.14.5, tvOS 12.3, watchOS 5.2.1. A malicious application may be able to execute arbitrary code with system privileges.
1nteger-c/CVE-2019-8605
CVE-2019-8627
maldiohead/CVE-2019-8627
CVE-2019-8641 (2019-12-18)
An out-of-bounds read was addressed with improved input validation.
ire33164/CVE-2019-8641-reproduction
CVE-2019-8656 (2020-10-27)
This was addressed with additional checks by Gatekeeper on files mounted through a network share. This issue is fixed in macOS Mojave 10.14.6, Security Update 2019-004 High Sierra, Security Update 2019-004 Sierra. Extracting a zip file containing a symbolic link to an endpoint in an NFS mount that is attacker controlled may bypass Gatekeeper.
D00MFist/CVE-2019-8656
CVE-2019-8781 (2019-12-18)
A memory corruption issue was addressed with improved state management. This issue is fixed in macOS Catalina 10.15. An application may be able to execute arbitrary code with kernel privileges.
A2nkF/macOS-Kernel-Exploit
TrungNguyen1909/CVE-2019-8781-macOS
CVE-2019-8791 (2019-12-18)
An issue existed in the parsing of URL schemes. This issue was addressed with improved URL validation. This issue is fixed in Shazam Android App Version 9.25.0, Shazam iOS App Version 12.11.0. Processing a maliciously crafted URL may lead to an open redirect.
ashleykinguk/Shazam-CVE-2019-8791-CVE-2019-8792
CVE-2019-8936 (2019-05-15)
NTP through 4.2.8p12 has a NULL Pointer Dereference.
snappyJack/CVE-2019-8936
CVE-2019-8942 (2019-02-19)
WordPress before 4.9.9 and 5.x before 5.0.1 allows remote code execution because an _wp_attached_file Post Meta entry can be changed to an arbitrary string, such as one ending with a .jpg?file.php substring. An attacker with author privileges can execute arbitrary code by uploading a crafted image containing PHP code in the Exif metadata. Exploitation can leverage CVE-2019-8943.
brianwrf/WordPress_4.9.8_RCE_POC
synacktiv/CVE-2019-8942
CVE-2019-8956 (2019-04-01)
In the Linux Kernel before versions 4.20.8 and 4.19.21 a use-after-free error in the "sctp_sendmsg()" function (net/sctp/socket.c) when handling SCTP_SENDALL flag can be exploited to corrupt memory.
butterflyhack/CVE-2019-8956
CVE-2019-8978 (2019-05-14)
An improper authentication vulnerability can be exploited through a race condition that occurs in Ellucian Banner Web Tailor 8.8.3, 8.8.4, and 8.9 and Banner Enterprise Identity Services 8.3, 8.3.1, 8.3.2, and 8.4, in conjunction with SSO Manager. This vulnerability allows remote attackers to steal a victim's session (and cause a denial of service) by repeatedly requesting the initial Banner Web Tailor main page with the IDMSESSID cookie set to the victim's UDCID, which in the case tested is the institutional ID. During a login attempt by a victim, the attacker can leverage the race condition and will be issued the SESSID that was meant for this victim.
JoshuaMulliken/CVE-2019-8978
CVE-2019-8979 (2019-02-21)
Kohana through 3.3.6 has SQL Injection when the order_by() parameter can be controlled.
seb-elttam/ko7demo
CVE-2019-8997 (2019-03-21)
An XML External Entity Injection (XXE) vulnerability in the Management System (console) of BlackBerry AtHoc versions earlier than 7.6 HF-567 could allow an attacker to potentially read arbitrary local files from the application server or make requests on the network by entering maliciously crafted XML in an existing field.
nxkennedy/CVE-2019-8997
CVE-2019-9153 (2019-08-22)
Improper Verification of a Cryptographic Signature in OpenPGP.js <=4.1.2 allows an attacker to forge signed messages by replacing its signatures with a "standalone" or "timestamp" signature.
ZenyWay/opgp-service-cve-2019-9153
CVE-2019-9184 (2019-02-26)
SQL injection vulnerability in the J2Store plugin 3.x before 3.3.7 for Joomla! allows remote attackers to execute arbitrary SQL commands via the product_option[] parameter.
cved-sources/cve-2019-9184
CVE-2019-9193 (2019-04-01)
** DISPUTED ** In PostgreSQL 9.3 through 11.2, the "COPY TO/FROM PROGRAM" function allows superusers and users in the 'pg_execute_server_program' group to execute arbitrary code in the context of the database's operating system user. This functionality is enabled by default and can be abused to run arbitrary operating system commands on Windows, Linux, and macOS. NOTE: Third parties claim/state this is not an issue because PostgreSQL functionality for ‘COPY TO/FROM PROGRAM’ is acting as intended. References state that in PostgreSQL, a superuser can execute commands as the server user without using the ‘COPY FROM PROGRAM’.
skyship36/CVE-2019-9193
Proxysec/CVE-2019-9193
CVE-2019-9194 (2019-02-26)
elFinder before 2.1.48 has a command injection vulnerability in the PHP connector.
cved-sources/cve-2019-9194
CVE-2019-9202 (2019-03-28)
Nagios IM (component of Nagios XI) before 2.2.7 allows authenticated users to execute arbitrary code via API key issues.
polict/CVE-2019-9202
CVE-2019-9465 (2020-01-07)
In the Titan M handling of cryptographic operations, there is a possible information disclosure due to an unusual root cause. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android Versions: Android-10 Android ID: A-133258003
alexbakker/CVE-2019-9465
CVE-2019-9506 (2019-08-14)
The Bluetooth BR/EDR specification up to and including version 5.1 permits sufficiently low encryption key length and does not prevent an attacker from influencing the key length negotiation. This allows practical brute-force attacks (aka "KNOB") that can decrypt traffic and inject arbitrary ciphertext without the victim noticing.
francozappa/knob
CVE-2019-9511 (2019-08-13)
Some HTTP/2 implementations are vulnerable to window size manipulation and stream prioritization manipulation, potentially leading to a denial of service. The attacker requests a large amount of data from a specified resource over multiple streams. They manipulate window size and stream priority to force the server to queue the data in 1-byte chunks. Depending on how efficiently this data is queued, this can consume excess CPU, memory, or both.
flyniu666/ingress-nginx-0.21-1.19.5
CVE-2019-9580 (2019-03-08)
In st2web in StackStorm Web UI before 2.9.3 and 2.10.x before 2.10.3, it is possible to bypass the CORS protection mechanism via a "null" origin value, potentially leading to XSS.
mpgn/CVE-2019-9580
CVE-2019-9596 (2019-10-23)
Darktrace Enterprise Immune System before 3.1 allows CSRF via the /whitelisteddomains endpoint.
gerwout/CVE-2019-9596-and-CVE-2019-9597
CVE-2019-9599 (2019-03-06)
The AirDroid application through 4.2.1.6 for Android allows remote attackers to cause a denial of service (service crash) via many simultaneous sdctl/comm/lite_auth/ requests.
s4vitar/AirDroidPwner
CVE-2019-9621 (2019-04-30)
Zimbra Collaboration Suite before 8.6 patch 13, 8.7.x before 8.7.11 patch 10, and 8.8.x before 8.8.10 patch 7 or 8.8.x before 8.8.11 patch 3 allows SSRF via the ProxyServlet component.
k8gege/ZimbraExploit
CVE-2019-9653 (2019-05-31)
NUUO Network Video Recorder Firmware 1.7.x through 3.3.x allows unauthenticated attackers to execute arbitrary commands via shell metacharacters to handle_load_config.php.
grayoneday/CVE-2019-9653
CVE-2019-9670 (2019-05-29)
mailboxd component in Synacor Zimbra Collaboration Suite 8.7.x before 8.7.11p10 has an XML External Entity injection (XXE) vulnerability.
rek7/Zimbra-RCE
attackgithub/Zimbra-RCE
CVE-2019-9673 (2019-06-05)
Freenet 1483 has a MIME type bypass that allows arbitrary JavaScript execution via a crafted Freenet URI.
mgrube/CVE-2019-9673
CVE-2019-9729 (2019-03-12)
In Shanda MapleStory Online V160, the SdoKeyCrypt.sys driver allows privilege escalation to NT AUTHORITY\SYSTEM because of not validating the IOCtl 0x8000c01c input value, leading to an integer signedness error and a heap-based buffer underflow.
HyperSine/SdoKeyCrypt-sys-local-privilege-elevation
CVE-2019-9730 (2019-06-05)
Incorrect access control in the CxUtilSvc component of the Synaptics Sound Device drivers prior to version 2.29 allows a local attacker to increase access privileges to the Windows Registry via an unpublished API.
jthuraisamy/CVE-2019-9730
CVE-2019-9745 (2019-10-14)
CloudCTI HIP Integrator Recognition Configuration Tool allows privilege escalation via its EXQUISE integration. This tool communicates with a service (Recognition Update Client Service) via an insecure communication channel (Named Pipe). The data (JSON) sent via this channel is used to import data from CRM software using plugins (.dll files). The plugin to import data from the EXQUISE software (DatasourceExquiseExporter.dll) can be persuaded to start arbitrary programs (including batch files) that are executed using the same privileges as Recognition Update Client Service (NT AUTHORITY\SYSTEM), thus elevating privileges. This occurs because a higher-privileged process executes scripts from a directory writable by a lower-privileged user.
KPN-CISO/CVE-2019-9745
CVE-2019-9766 (2019-03-14)
Stack-based buffer overflow in Free MP3 CD Ripper 2.6, when converting a file, allows user-assisted remote attackers to execute arbitrary code via a crafted .mp3 file.
moonheadobj/CVE-2019-9766
CVE-2019-9787 (2019-03-14)
WordPress before 5.1.1 does not properly filter comment content, leading to Remote Code Execution by unauthenticated users in a default configuration. This occurs because CSRF protection is mishandled, and because Search Engine Optimization of A elements is performed incorrectly, leading to XSS. The XSS results in administrative access, which allows arbitrary changes to .php files. This is related to wp-admin/includes/ajax-actions.php and wp-includes/comment.php.
rkatogit/cve-2019-9787_csrf_poc
PalmTreeForest/CodePath_Week_7-8
sijiahi/Wordpress_cve-2019-9787_defense
matinciel/Wordpress_CVE-2019-9787
CVE-2019-9810 (2019-04-26)
Incorrect alias information in IonMonkey JIT compiler for Array.prototype.slice method may lead to missing bounds check and a buffer overflow. This vulnerability affects Firefox < 66.0.1, Firefox ESR < 60.6.1, and Thunderbird < 60.6.1.
xuechiyaobai/CVE-2019-9810-PoC
0vercl0k/CVE-2019-9810
CVE-2019-9896 (2019-03-20)
In PuTTY versions before 0.71 on Windows, local attackers could hijack the application by putting a malicious help file in the same directory as the executable.
yasinyilmaz/vuln-chm-hijack
CVE-2019-9978 (2019-03-24)
The social-warfare plugin before 3.5.3 for WordPress has stored XSS via the wp-admin/admin-post.php?swp_debug=load_options swp_url parameter, as exploited in the wild in March 2019. This affects Social Warfare and Social Warfare Pro.
mpgn/CVE-2019-9978
hash3liZer/CVE-2019-9978
KTN1990/CVE-2019-9978
cved-sources/cve-2019-9978
CVE-2019-10008 (2019-04-24)
Zoho ManageEngine ServiceDesk 9.3 allows session hijacking and privilege escalation because an established guest session is automatically converted into an established administrator session when the guest user enters the administrator username, with an arbitrary incorrect password, in an mc/ login attempt within a different browser tab.
FlameOfIgnis/CVE-2019-10008
CVE-2019-10086 (2019-08-20)
In Apache Commons Beanutils 1.9.2, a special BeanIntrospector class was added which allows suppressing the ability for an attacker to access the classloader via the class property available on all Java objects. We, however were not using this by default characteristic of the PropertyUtilsBean.
evilangelplus/CVE-2019-10086
CVE-2019-10092 (2019-09-26)
In Apache HTTP Server 2.4.0-2.4.39, a limited cross-site scripting issue was reported affecting the mod_proxy error page. An attacker could cause the link on the error page to be malformed and instead point to a page of their choice. This would only be exploitable where a server was set up with proxying enabled but was misconfigured in such a way that the Proxy Error page was displayed.
motikan2010/CVE-2019-10092_Docker
CVE-2019-10149 (2019-06-05)
A flaw was found in Exim versions 4.87 to 4.91 (inclusive). Improper validation of recipient address in deliver_message() function in /src/deliver.c may lead to remote command execution.
bananaphones/exim-rce-quickfix
cowbe0x004/eximrce-CVE-2019-10149
MNEMO-CERT/PoC--CVE-2019-10149_Exim
aishee/CVE-2019-10149-quick
AzizMea/CVE-2019-10149-privilege-escalation
Brets0150/StickyExim
ChrissHack/exim.exp
darsigovrustam/CVE-2019-10149
Diefunction/CVE-2019-10149
Dilshan-Eranda/CVE-2019-10149
area1/exim-cve-2019-10149-data
CVE-2019-10172 (2019-11-18)
A flaw was found in org.codehaus.jackson:jackson-mapper-asl:1.9.x libraries. XML external entity vulnerabilities similar CVE-2016-3720 also affects codehaus jackson-mapper-asl libraries but in different classes.
rusakovichma/CVE-2019-10172
CVE-2019-10207 (2019-11-25)
A flaw was found in the Linux kernel's Bluetooth implementation of UART, all versions kernel 3.x.x before 4.18.0 and kernel 5.x.x. An attacker with local access and write permissions to the Bluetooth hardware could use this flaw to issue a specially crafted ioctl function call and cause the system to crash.
butterflyhack/CVE-2019-10207
CVE-2019-10392 (2019-09-12)
Jenkins Git Client Plugin 2.8.4 and earlier and 3.0.0-rc did not properly restrict values passed as URL argument to an invocation of 'git ls-remote', resulting in OS command injection.
jas502n/CVE-2019-10392
ftk-sostupid/CVE-2019-10392_EXP
CVE-2019-10475 (2019-10-23)
A reflected cross-site scripting vulnerability in Jenkins build-metrics Plugin allows attackers to inject arbitrary HTML and JavaScript into web pages provided by this plugin.
vesche/CVE-2019-10475
CVE-2019-10678 (2019-03-31)
Domoticz before 4.10579 neglects to categorize \n and \r as insecure argument options.
cved-sources/cve-2019-10678
CVE-2019-10685 (2019-05-24)
A Reflected Cross Site Scripting (XSS) Vulnerability was discovered in Heidelberg Prinect Archiver v2013 release 1.0.
alt3kx/CVE-2019-10685
CVE-2019-10708 (2019-04-02)
S-CMS PHP v1.0 has SQL injection via the 4/js/scms.php?action=unlike id parameter.
stavhaygn/CVE-2019-10708
CVE-2019-10758 (2019-12-24)
mongo-express before 0.54.0 is vulnerable to Remote Code Execution via endpoints that uses the `toBSON` method. A misuse of the `vm` dependency to perform `exec` commands in a non-safe environment.
masahiro331/CVE-2019-10758
lp008/CVE-2019-10758
CVE-2019-10779 (2020-01-27)
All versions of stroom:stroom-app before 5.5.12 and all versions of the 6.0.0 branch before 6.0.25 are affected by Cross-site Scripting. An attacker website is able to load the Stroom UI into a hidden iframe. Using that iframe, the attacker site can issue commands to the Stroom UI via an XSS vulnerability to take full control of the Stroom UI on behalf of the logged-in user.
RepublicR0K/CVE-2019-10779
CVE-2019-10869 (2019-05-07)
Path Traversal and Unrestricted File Upload exists in the Ninja Forms plugin before 3.0.23 for WordPress (when the Uploads add-on is activated). This allows an attacker to traverse the file system to access files and execute code via the includes/fields/upload.php (aka upload/submit page) name and tmp_name parameters.
KTN1990/CVE-2019-10869
CVE-2019-10915 (2019-07-11)
A vulnerability has been identified in TIA Administrator (All versions < V1.0 SP1 Upd1). The integrated configuration web application (TIA Administrator) allows to execute certain application commands without proper authentication. The vulnerability could be exploited by an attacker with local access to the affected system. Successful exploitation requires no privileges and no user interaction. An attacker could use the vulnerability to compromise confidentiality and integrity and availability of the affected system. At the time of advisory publication no public exploitation of this security vulnerability was known.
jiansiting/CVE-2019-10915
CVE-2019-10999 (2019-05-06)
The D-Link DCS series of Wi-Fi cameras contains a stack-based buffer overflow in alphapd, the camera's web server. The overflow allows a remotely authenticated attacker to execute arbitrary code by providing a long string in the WEPEncryption parameter when requesting wireless.htm. Vulnerable devices include DCS-5009L (1.08.11 and below), DCS-5010L (1.14.09 and below), DCS-5020L (1.15.12 and below), DCS-5025L (1.03.07 and below), DCS-5030L (1.04.10 and below), DCS-930L (2.16.01 and below), DCS-931L (1.14.11 and below), DCS-932L (2.17.01 and below), DCS-933L (1.14.11 and below), and DCS-934L (1.05.04 and below).
tacnetsol/CVE-2019-10999
CVE-2019-11043 (2019-10-28)
In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below 7.3.11 in certain configurations of FPM setup it is possible to cause FPM module to write past allocated buffers into the space reserved for FCGI protocol data, thus opening the possibility of remote code execution.
neex/phuip-fpizdam
B1gd0g/CVE-2019-11043
tinker-li/CVE-2019-11043
jas502n/CVE-2019-11043
AleWong/PHP-FPM-Remote-Code-Execution-Vulnerability-CVE-2019-11043-
ianxtianxt/CVE-2019-11043
fairyming/CVE-2019-11043
akamajoris/CVE-2019-11043-Docker
theMiddleBlue/CVE-2019-11043
shadow-horse/cve-2019-11043
huowen/CVE-2019-11043
ypereirareis/docker-CVE-2019-11043
MRdoulestar/CVE-2019-11043
0th3rs-Security-Team/CVE-2019-11043
k8gege/CVE-2019-11043
moniik/CVE-2019-11043_env
kriskhub/CVE-2019-11043
alokaranasinghe/cve-2019-11043
corifeo/CVE-2019-11043
lindemer/CVE-2019-11043
CVE-2019-11061 (2019-08-28)
A broken access control vulnerability in HG100 firmware versions up to 4.00.06 allows an attacker in the same local area network to control IoT devices that connect with itself via http://[target]/smarthome/devicecontrol without any authentication. CVSS 3.0 base score 10 (Confidentiality, Integrity and Availability impacts). CVSS vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H).
tim124058/ASUS-SmartHome-Exploit
CVE-2019-11076 (2019-04-23)
Cribl UI 1.5.0 allows remote attackers to run arbitrary commands via an unauthenticated web request.
livehybrid/poc-cribl-rce
CVE-2019-11157 (2019-12-16)
Improper conditions check in voltage settings for some Intel(R) Processors may allow a privileged user to potentially enable escalation of privilege and/or information disclosure via local access.
zkenjar/v0ltpwn
CVE-2019-11223 (2019-04-18)
An Unrestricted File Upload Vulnerability in the SupportCandy plugin through 2.0.0 for WordPress allows remote attackers to execute arbitrary code by uploading a file with an executable extension.
AngelCtulhu/CVE-2019-11223
CVE-2019-11224 (2019-05-15)
HARMAN AMX MVP5150 v2.87.13 devices allow remote OS Command Injection.
Insecurities/CVE-2019-11224
CVE-2019-11358 (2019-04-19)
jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution. If an unsanitized source object contained an enumerable __proto__ property, it could extend the native Object.prototype.
DanielRuf/snyk-js-jquery-174006
bitnesswise/jquery-prototype-pollution-fix
DanielRuf/snyk-js-jquery-565129
CVE-2019-11447 (2019-04-22)
An issue was discovered in CutePHP CuteNews 2.1.2. An attacker can infiltrate the server through the avatar upload process in the profile area via the avatar_file field to index.php?mod=main&opt=personal. There is no effective control of $imgsize in /core/modules/dashboard.php. The header content of a file can be changed and the control can be bypassed for code execution. (An attacker can use the GIF header for this.)
CRFSlick/CVE-2019-11447-POC
mt-code/CVE-2019-11447
khuntor/CVE-2019-11447-EXP
CVE-2019-11477 (2019-06-18)
Jonathan Looney discovered that the TCP_SKB_CB(skb)->tcp_gso_segs value was subject to an integer overflow in the Linux kernel when handling TCP Selective Acknowledgments (SACKs). A remote attacker could use this to cause a denial of service. This has been fixed in stable kernel releases 4.4.182, 4.9.182, 4.14.127, 4.19.52, 5.1.11, and is fixed in commit 3b4929f65b0d8249f19a50245cd88ed1a2f78cff.
sasqwatch/cve-2019-11477-poc
CVE-2019-11510 (2019-05-08)
In Pulse Secure Pulse Connect Secure (PCS) 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 before 9.0R3.4, an unauthenticated remote attacker can send a specially crafted URI to perform an arbitrary file reading vulnerability .
projectzeroindia/CVE-2019-11510
nuc13us/Pulse
imjdl/CVE-2019-11510-poc
es0/CVE-2019-11510_poc
r00tpgp/http-pulse_ssl_vpn.nse
jas502n/CVE-2019-11510-1
jason3e7/CVE-2019-11510
BishopFox/pwn-pulse
aqhmal/pulsexploit
cisagov/check-your-pulse
andripwn/pulse-exploit
pwn3z/CVE-2019-11510-PulseVPN
CVE-2019-11523 (2019-06-06)
Anviz Global M3 Outdoor RFID Access Control executes any command received from any source. No authentication/encryption is done. Attackers can fully interact with the device: for example, send the "open door" command, download the users list (which includes RFID codes and passcodes in cleartext), or update/create users. The same attack can be executed on a local network and over the internet (if the device is exposed on a public IP address).
wizlab-it/anviz-m3-rfid-cve-2019-11523-poc
CVE-2019-11539 (2019-04-25)
In Pulse Secure Pulse Connect Secure version 9.0RX before 9.0R3.4, 8.3RX before 8.3R7.1, 8.2RX before 8.2R12.1, and 8.1RX before 8.1R15.1 and Pulse Policy Secure version 9.0RX before 9.0R3.2, 5.4RX before 5.4R7.1, 5.3RX before 5.3R12.1, 5.2RX before 5.2R12.1, and 5.1RX before 5.1R15.1, the admin web interface allows an authenticated attacker to inject and execute commands.
0xDezzy/CVE-2019-11539
CVE-2019-11580 (2019-06-03)
Atlassian Crowd and Crowd Data Center had the pdkinstall development plugin incorrectly enabled in release builds. Attackers who can send unauthenticated or authenticated requests to a Crowd or Crowd Data Center instance can exploit this vulnerability to install arbitrary plugins, which permits remote code execution on systems running a vulnerable version of Crowd or Crowd Data Center. All versions of Crowd from version 2.1.0 before 3.0.5 (the fixed version for 3.0.x), from version 3.1.0 before 3.1.6 (the fixed version for 3.1.x), from version 3.2.0 before 3.2.8 (the fixed version for 3.2.x), from version 3.3.0 before 3.3.5 (the fixed version for 3.3.x), and from version 3.4.0 before 3.4.4 (the fixed version for 3.4.x) are affected by this vulnerability.
jas502n/CVE-2019-11580
shelld3v/CVE-2019-11580
CVE-2019-11581 (2019-08-09)
There was a server-side template injection vulnerability in Jira Server and Data Center, in the ContactAdministrators and the SendBulkMail actions. An attacker is able to remotely execute code on systems that run a vulnerable version of Jira Server or Data Center. All versions of Jira Server and Data Center from 4.4.0 before 7.6.14, from 7.7.0 before 7.13.5, from 8.0.0 before 8.0.3, from 8.1.0 before 8.1.2, and from 8.2.0 before 8.2.3 are affected by this vulnerability.
jas502n/CVE-2019-11581
kobs0N/CVE-2019-11581
CVE-2019-11687 (2019-05-02)
An issue was discovered in the DICOM Part 10 File Format in the NEMA DICOM Standard 1995 through 2019b. The preamble of a DICOM file that complies with this specification can contain the header for an executable file, such as Portable Executable (PE) malware. This space is left unspecified so that dual-purpose files can be created. (For example, dual-purpose TIFF/DICOM files are used in digital whole slide imaging for applications in medicine.) To exploit this vulnerability, someone must execute a maliciously crafted file that is encoded in the DICOM Part 10 File Format. PE/DICOM files are executable even with the .dcm file extension. Anti-malware configurations at healthcare facilities often ignore medical imagery. Also, anti-malware tools and business processes could violate regulatory frameworks (such as HIPAA) when processing suspicious DICOM files.
kosmokato/bad-dicom
CVE-2019-11707 (2019-07-23)
A type confusion vulnerability can occur when manipulating JavaScript objects due to issues in Array.pop. This can allow for an exploitable crash. We are aware of targeted attacks in the wild abusing this flaw. This vulnerability affects Firefox ESR < 60.7.1, Firefox < 67.0.3, and Thunderbird < 60.7.2.
vigneshsrao/CVE-2019-11707
tunnelshade/cve-2019-11707
CVE-2019-11708 (2019-07-23)
Insufficient vetting of parameters passed with the Prompt:Open IPC message between child and parent processes can result in the non-sandboxed parent process opening web content chosen by a compromised child process. When combined with additional vulnerabilities this could result in executing arbitrary code on the user's computer. This vulnerability affects Firefox ESR < 60.7.2, Firefox < 67.0.4, and Thunderbird < 60.7.2.
0vercl0k/CVE-2019-11708
CVE-2019-11730 (2019-07-23)
A vulnerability exists where if a user opens a locally saved HTML file, this file can use file: URIs to access other files in the same directory or sub-directories if the names are known or guessed. The Fetch API can then be used to read the contents of any files stored in these directories and they may uploaded to a server. It was demonstrated that in combination with a popular Android messaging app, if a malicious HTML attachment is sent to a user and they opened that attachment in Firefox, due to that app's predictable pattern for locally-saved file names, it is possible to read attachments the victim received from other correspondents. This vulnerability affects Firefox ESR < 60.8, Firefox < 68, and Thunderbird < 60.8.
alidnf/CVE-2019-11730
CVE-2019-11881 (2019-06-10)
A vulnerability exists in Rancher 2.1.4 in the login component, where the errorMsg parameter can be tampered to display arbitrary content, filtering tags but not special characters or symbols. There's no other limitation of the message, allowing malicious users to lure legitimate users to visit phishing sites with scare tactics, e.g., displaying a "This version of Rancher is outdated, please visit https://malicious.rancher.site/upgrading" message.
MauroEldritch/VanCleef
CVE-2019-11931 (2019-11-14)
A stack-based buffer overflow could be triggered in WhatsApp by sending a specially crafted MP4 file to a WhatsApp user. The issue was present in parsing the elementary stream metadata of an MP4 file and could result in a DoS or RCE. This affects Android versions prior to 2.19.274, iOS versions prior to 2.19.100, Enterprise Client versions prior to 2.25.3, Business for Android versions prior to 2.19.104 and Business for iOS versions prior to 2.19.100.
kasif-dekel/whatsapp-rce-patched
nop-team/CVE-2019-11931
CVE-2019-11932 (2019-10-03)
A double free vulnerability in the DDGifSlurp function in decoding.c in the android-gif-drawable library before version 1.2.18, as used in WhatsApp for Android before version 2.19.244 and many other Android applications, allows remote attackers to execute arbitrary code or cause a denial of service when the library is used to parse a specially crafted GIF image.
dorkerdevil/CVE-2019-11932
KeepWannabe/WhatsRCE
awakened1712/CVE-2019-11932
TulungagungCyberLink/CVE-2019-11932
infiniteLoopers/CVE-2019-11932
alexanderstonec/CVE-2019-11932
valbrux/CVE-2019-11932-SupportApp
fastmo/CVE-2019-11932
mRanonyMousTZ/CVE-2019-11932-whatsApp-exploit
SmoZy92/CVE-2019-11932
dashtic172/https-github.com-awakened171
Err0r-ICA/WhatsPayloadRCE
starling021/CVE-2019-11932-SupportApp
Hacker-Yadav/CVE-2019-11932
BadAssAiras/hello
CVE-2019-11933 (2019-10-23)
A heap buffer overflow bug in libpl_droidsonroids_gif before 1.2.19, as used in WhatsApp for Android before version 2.19.291 could allow remote attackers to execute arbitrary code or cause a denial of service.
NatleoJ/CVE-2019-11933
CVE-2019-12086 (2019-05-17)
A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.x before 2.9.9. When Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint, the service has the mysql-connector-java jar (8.0.14 or earlier) in the classpath, and an attacker can host a crafted MySQL server reachable by the victim, an attacker can send a crafted JSON message that allows them to read arbitrary local files on the server. This occurs because of missing com.mysql.cj.jdbc.admin.MiniAdmin validation.
codeplutos/CVE-2019-12086-jackson-databind-file-read
Al1ex/CVE-2019-12086
CVE-2019-12169 (2019-06-03)
ATutor 2.2.4 allows Arbitrary File Upload and Directory Traversal, resulting in remote code execution via a ".." pathname in a ZIP archive to the mods/_core/languages/language_import.php (aka Import New Language) or mods/_standard/patcher/index_admin.php (aka Patcher) component.
fuzzlove/ATutor-2.2.4-Language-Exploit
CVE-2019-12170 (2019-05-17)
ATutor through 2.2.4 is vulnerable to arbitrary file uploads via the mods/_core/backups/upload.php (aka backup) component. This may result in remote command execution. An attacker can use the instructor account to fully compromise the system using a crafted backup ZIP archive. This will allow for PHP files to be written to the web root, and for code to execute on the remote server.
fuzzlove/ATutor-Instructor-Backup-Arbitrary-File
CVE-2019-12180 (2020-02-05)
An issue was discovered in SmartBear ReadyAPI through 2.8.2 and 3.0.0 and SoapUI through 5.5. When opening a project, the Groovy "Load Script" is automatically executed. This allows an attacker to execute arbitrary Groovy Language code (Java scripting language) on the victim machine by inducing it to open a malicious Project. The same issue is present in the "Save Script" function, which is executed automatically when saving a project.
0x-nope/CVE-2019-12180
CVE-2019-12181 (2019-06-17)
A privilege escalation vulnerability exists in SolarWinds Serv-U before 15.1.7 for Linux.
guywhataguy/CVE-2019-12181
CVE-2019-12185 (2019-05-19)
eLabFTW 1.8.5 is vulnerable to arbitrary file uploads via the /app/controllers/EntityController.php component. This may result in remote command execution. An attacker can use a user account to fully compromise the system using a POST request. This will allow for PHP files to be written to the web root, and for code to execute on the remote server.
fuzzlove/eLabFTW-1.8.5-EntityController-Arbitrary-File-Upload-RCE
CVE-2019-12189 (2019-05-21)
An issue was discovered in Zoho ManageEngine ServiceDesk Plus 9.3. There is XSS via the SearchN.do search field.
falconz/CVE-2019-12189
tuyenhva/CVE-2019-12189
CVE-2019-12190 (2019-05-21)
XSS was discovered in CentOS-WebPanel.com (aka CWP) CentOS Web Panel through 0.9.8.747 via the testacc/fileManager2.php fm_current_dir or filename parameter.
tuyenhva/CVE-2019-12190
CVE-2019-12252 (2019-05-21)
In Zoho ManageEngine ServiceDesk Plus through 10.5, users with the lowest privileges (guest) can view an arbitrary post by appending its number to the SDNotify.do?notifyModule=Solution&mode=E-Mail&notifyTo=SOLFORWARD&id= substring.
tuyenhva/CVE-2019-12252
CVE-2019-12255 (2019-08-09)
Wind River VxWorks has a Buffer Overflow in the TCP component (issue 1 of 4). This is a IPNET security vulnerability: TCP Urgent Pointer = 0 that leads to an integer underflow.
sud0woodo/Urgent11-Suricata-LUA-scripts
CVE-2019-12272 (2019-05-23)
In OpenWrt LuCI through 0.10, the endpoints admin/status/realtime/bandwidth_status and admin/status/realtime/wireless_status of the web application are affected by a command injection vulnerability.
HACHp1/LuCI_RCE_exp
roguedream/lede-17.01.3
CVE-2019-12314 (2019-05-24)
Deltek Maconomy 2.2.5 is prone to local file inclusion via absolute path traversal in the WS.macx1.W_MCS/ PATH_INFO, as demonstrated by a cgi-bin/Maconomy/MaconomyWS.macx1.W_MCS/etc/passwd URI.
ras313/CVE-2019-12314
CVE-2019-12384 (2019-06-24)
FasterXML jackson-databind 2.x before 2.9.9.1 might allow attackers to have a variety of impacts by leveraging failure to block the logback-core class from polymorphic deserialization. Depending on the classpath content, remote code execution may be possible.
jas502n/CVE-2019-12384
MagicZer0/Jackson_RCE-CVE-2019-12384
CVE-2019-12409 (2019-11-18)
The 8.1.1 and 8.2.0 releases of Apache Solr contain an insecure setting for the ENABLE_REMOTE_JMX_OPTS configuration option in the default solr.in.sh configuration file shipping with Solr. If you use the default solr.in.sh file from the affected releases, then JMX monitoring will be enabled and exposed on RMI_PORT (default=18983), without any authentication. If this port is opened for inbound traffic in your firewall, then anyone with network access to your Solr nodes will be able to access JMX, which may in turn allow them to upload malicious code for execution on the Solr server.
jas502n/CVE-2019-12409
CVE-2019-12453 (2019-07-19)
In MicroStrategy Web before 10.1 patch 10, stored XSS is possible in the FLTB parameter due to missing input validation.
undefinedmode/CVE-2019-12453
CVE-2019-12460 (2019-05-30)
Web Port 1.19.1 allows XSS via the /access/setup type parameter.
EmreOvunc/WebPort-v1.19.1-Reflected-XSS
CVE-2019-12475 (2019-07-17)
In MicroStrategy Web before 10.4.6, there is stored XSS in metric due to insufficient input validation.
undefinedmode/CVE-2019-12475
CVE-2019-12476 (2019-06-17)
An authentication bypass vulnerability in the password reset functionality in Zoho ManageEngine ADSelfService Plus before 5.0.6 allows an attacker with physical access to gain a shell with SYSTEM privileges via the restricted thick client browser. The attack uses a long sequence of crafted keyboard input.
0katz/CVE-2019-12476
CVE-2019-12538 (2019-06-05)
An issue was discovered in Zoho ManageEngine ServiceDesk Plus 9.3. There is XSS via the SiteLookup.do search field.
tarantula-team/CVE-2019-12538
CVE-2019-12541 (2019-06-05)
An issue was discovered in Zoho ManageEngine ServiceDesk Plus 9.3. There is XSS via the SolutionSearch.do searchText parameter.
tarantula-team/CVE-2019-12541
CVE-2019-12542 (2019-06-05)
An issue was discovered in Zoho ManageEngine ServiceDesk Plus 9.3. There is XSS via the SearchN.do userConfigID parameter.
tarantula-team/CVE-2019-12542
CVE-2019-12543 (2019-06-05)
An issue was discovered in Zoho ManageEngine ServiceDesk Plus 9.3. There is XSS via the PurchaseRequest.do serviceRequestId parameter.
tarantula-team/CVE-2019-12543
CVE-2019-12562 (2019-09-26)
Stored Cross-Site Scripting in DotNetNuke (DNN) Version before 9.4.0 allows remote attackers to store and embed the malicious script into the admin notification page. The exploit could be used to perfom any action with admin privileges such as managing content, adding users, uploading backdoors to the server, etc. Successful exploitation occurs when an admin user visits a notification page with stored cross-site scripting.
MAYASEVEN/CVE-2019-12562
CVE-2019-12586 (2019-09-04)
The EAP peer implementation in Espressif ESP-IDF 2.0.0 through 4.0.0 and ESP8266_NONOS_SDK 2.2.0 through 3.1.0 processes EAP Success messages before any EAP method completion or failure, which allows attackers in radio range to cause a denial of service (crash) via a crafted message.
Matheus-Garbelini/esp32_esp8266_attacks
CVE-2019-12594 (2019-07-02)
DOSBox 0.74-2 has Incorrect Access Control.
Alexandre-Bartel/CVE-2019-12594
CVE-2019-12735 (2019-06-05)
getchar.c in Vim before 8.1.1365 and Neovim before 0.3.6 allows remote attackers to execute arbitrary OS commands via the :source! command in a modeline, as demonstrated by execute in Vim, and assert_fails or nvim_input in Neovim.
pcy190/ace-vim-neovim
oldthree3/CVE-2019-12735-VIM-NEOVIM
CVE-2019-12750 (2019-07-31)
Symantec Endpoint Protection, prior to 14.2 RU1 & 12.1 RU6 MP10 and Symantec Endpoint Protection Small Business Edition, prior to 12.1 RU6 MP10c (12.1.7491.7002), may be susceptible to a privilege escalation vulnerability, which is a type of issue whereby an attacker may attempt to compromise the software application to gain elevated access to resources that are normally protected from an application or user.
v-p-b/cve-2019-12750
CVE-2019-12796
PeterUpfold/CVE-2019-12796
CVE-2019-12814 (2019-06-19)
A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.x through 2.9.9. When Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint and the service has JDOM 1.x or 2.x jar in the classpath, an attacker can send a specifically crafted JSON message that allows them to read arbitrary local files on the server.
Al1ex/CVE-2019-12814
CVE-2019-12815 (2019-07-19)
An arbitrary file copy vulnerability in mod_copy in ProFTPD up to 1.3.5b allows for remote code execution and information disclosure without authentication, a related issue to CVE-2015-3306.
KTN1990/CVE-2019-12815
lcartey/proftpd-cve-2019-12815
CVE-2019-12836 (2019-06-21)
The Bobronix JEditor editor before 3.0.6 for Jira allows an attacker to add a URL/Link (to an existing issue) that can cause forgery of a request to an out-of-origin domain. This in turn may allow for a forged request that can be invoked in the context of an authenticated user, leading to stealing of session tokens and account takeover.
9lyph/CVE-2019-12836
CVE-2019-12840 (2019-06-15)
In Webmin through 1.910, any user authorized to the "Package Updates" module can execute arbitrary commands with root privileges via the data parameter to update.cgi.
bkaraceylan/CVE-2019-12840_POC
KrE80r/webmin_cve-2019-12840_poc
anasbousselham/webminscan
CVE-2019-12889 (2019-08-20)
An unauthenticated privilege escalation exists in SailPoint Desktop Password Reset 7.2. A user with local access to only the Windows logon screen can escalate their privileges to NT AUTHORITY\System. An attacker would need local access to the machine for a successful exploit. The attacker must disconnect the computer from the local network / WAN and connect it to an internet facing access point / network. At that point, the attacker can execute the password-reset functionality, which will expose a web browser. Browsing to a site that calls local Windows system functions (e.g., file upload) will expose the local file system. From there an attacker can launch a privileged command shell.
nulsect0r/CVE-2019-12889
CVE-2019-12890 (2019-06-19)
RedwoodHQ 2.5.5 does not require any authentication for database operations, which allows remote attackers to create admin users via a con.automationframework users insert_one call.
EthicalHCOP/CVE-2019-12890_RedxploitHQ
CVE-2019-12949 (2019-06-25)
In pfSense 2.4.4-p2 and 2.4.4-p3, if it is possible to trick an authenticated administrator into clicking on a button on a phishing page, an attacker can leverage XSS to upload arbitrary executable code, via diag_command.php and rrd_fetch_json.php (timePeriod parameter), to a server. Then, the remote attacker can run any command with root privileges on that server.
tarantula-team/CVE-2019-12949
CVE-2019-12999 (2020-01-31)
Lightning Network Daemon (lnd) before 0.7 allows attackers to trigger loss of funds because of Incorrect Access Control.
lightninglabs/chanleakcheck
CVE-2019-13000 (2020-01-31)
Eclair through 0.3 allows attackers to trigger loss of funds because of Incorrect Access Control. NOTE: README.md states "it is beta-quality software and don't put too much money in it."
ACINQ/detection-tool-cve-2019-13000
CVE-2019-13024 (2019-07-01)
Centreon 18.x before 18.10.6, 19.x before 19.04.3, and Centreon web before 2.8.29 allows the attacker to execute arbitrary system commands by using the value "init_script"-"Monitoring Engine Binary" in main.get.php to insert a arbitrary command into the database, and execute it by calling the vulnerable page www/include/configuration/configGenerate/xml/generateFiles.php (which passes the inserted value to the database to shell_exec without sanitizing it, allowing one to execute system arbitrary commands).
mhaskar/CVE-2019-13024
get-get-get-get/Centreon-RCE
CVE-2019-13025 (2019-10-02)
Compal CH7465LG CH7465LG-NCIP-6.12.18.24-5p8-NOSH devices have Incorrect Access Control because of Improper Input Validation. The attacker can send a maliciously modified POST (HTTP) request containing shell commands, which will be executed on the device, to an backend API endpoint of the cable modem.
x1tan/CVE-2019-13025
CVE-2019-13027 (2019-07-12)
Realization Concerto Critical Chain Planner (aka CCPM) 5.10.8071 has SQL Injection in at least in the taskupdt/taskdetails.aspx webpage via the projectname parameter.
IckoGZ/CVE-2019-13027
CVE-2019-13051 (2019-10-09)
Pi-Hole 4.3 allows Command Injection.
pr0tean/CVE-2019-13051
CVE-2019-13063 (2019-09-23)
Within Sahi Pro 8.0.0, an attacker can send a specially crafted URL to include any victim files on the system via the script parameter on the Script_view page. This will result in file disclosure (i.e., being able to pull any file from the remote victim application). This can be used to steal and obtain sensitive config and other files. This can result in complete compromise of the application. The script parameter is vulnerable to directory traversal and both local and remote file inclusion.
0x6b7966/CVE-2019-13063-POC
CVE-2019-13086 (2019-06-30)
core/MY_Security.php in CSZ CMS 1.2.2 before 2019-06-20 has member/login/check SQL injection by sending a crafted HTTP User-Agent header and omitting the csrf_csz parameter.
lingchuL/CVE_POC_test
CVE-2019-13101 (2019-08-08)
An issue was discovered on D-Link DIR-600M 3.02, 3.03, 3.04, and 3.06 devices. wan.htm can be accessed directly without authentication, which can lead to disclosure of information about the WAN, and can also be leveraged by an attacker to modify the data fields of the page.
halencarjunior/dlkploit600
CVE-2019-13115 (2019-07-16)
In libssh2 before 1.9.0, kex_method_diffie_hellman_group_exchange_sha256_key_exchange in kex.c has an integer overflow that could lead to an out-of-bounds read in the way packets are read from the server. A remote attacker who compromises a SSH server may be able to disclose sensitive information or cause a denial of service condition on the client system when a user connects to the server. This is related to an _libssh2_check_length mistake, and is different from the various issues fixed in 1.8.1, such as CVE-2019-3855.
viz27/Libssh2-Exploit
CSSProject/libssh2-Exploit
CVE-2019-13143 (2019-08-06)
An HTTP parameter pollution issue was discovered on Shenzhen Dragon Brothers Fingerprint Bluetooth Round Padlock FB50 2.3. With the user ID, user name, and the lock's MAC address, anyone can unbind the existing owner of the lock, and bind themselves instead. This leads to complete takeover of the lock. The user ID, name, and MAC address are trivially obtained from APIs found within the Android or iOS application. With only the MAC address of the lock, any attacker can transfer ownership of the lock from the current user, over to the attacker's account. Thus rendering the lock completely inaccessible to the current user.
securelayer7/pwnfb50
CVE-2019-13272 (2019-07-17)
In the Linux kernel before 5.1.17, ptrace_link in kernel/ptrace.c mishandles the recording of the credentials of a process that wants to create a ptrace relationship, which allows local users to obtain root access by leveraging certain scenarios with a parent-child process relationship, where a parent drops privileges and calls execve (potentially allowing control by an attacker). One contributing factor is an object lifetime issue (which can also cause a panic). Another contributing factor is incorrect marking of a ptrace relationship as privileged, which is exploitable through (for example) Polkit's pkexec helper with PTRACE_TRACEME. NOTE: SELinux deny_ptrace might be a usable workaround in some environments.
jas502n/CVE-2019-13272
Cyc1eC/CVE-2019-13272
bigbigliang-malwarebenchmark/cve-2019-13272
oneoy/CVE-2019-13272
Huandtx/CVE-2019-13272
polosec/CVE-2019-13272
sumedhaDharmasena/-Kernel-ptrace-c-mishandles-vulnerability-CVE-2019-13272
Tharana/Exploiting-a-Linux-kernel-vulnerability
RashmikaEkanayake/Privilege-Escalation-CVE-2019-13272-
Tharana/vulnerability-exploitation
teddy47/CVE-2019-13272---Documentation
CVE-2019-13361 (2019-09-05)
Smanos W100 1.0.0 devices have Insecure Permissions, exploitable by an attacker on the same Wi-Fi network.
lodi-g/CVE-2019-13361
CVE-2019-13403 (2019-07-17)
Temenos CWX version 8.9 has an Broken Access Control vulnerability in the module /CWX/Employee/EmployeeEdit2.aspx, leading to the viewing of user information.
B3Bo1d/CVE-2019-13403
CVE-2019-13404 (2019-07-07)
** DISPUTED ** The MSI installer for Python through 2.7.16 on Windows defaults to the C:\Python27 directory, which makes it easier for local users to deploy Trojan horse code. (This also affects old 3.x releases before 3.5.) NOTE: the vendor's position is that it is the user's responsibility to ensure C:\Python27 access control or choose a different directory, because backwards compatibility requires that C:\Python27 remain the default for 2.7.x.
alidnf/CVE-2019-13404
CVE-2019-13496 (2019-11-04)
One Identity Cloud Access Manager before 8.1.4 Hotfix 1 allows OTP bypass via vectors involving a man in the middle, the One Identity Defender product, and replacing a failed SAML response with a successful SAML response.
FurqanKhan1/CVE-2019-13496
CVE-2019-13497 (2019-11-04)
One Identity Cloud Access Manager before 8.1.4 Hotfix 1 allows CSRF for logout requests.
FurqanKhan1/CVE-2019-13497
CVE-2019-13498 (2019-07-29)
One Identity Cloud Access Manager 8.1.3 does not use HTTP Strict Transport Security (HSTS), which may allow man-in-the-middle (MITM) attacks. This issue is fixed in version 8.1.4.
FurqanKhan1/CVE-2019-13498
CVE-2019-13504 (2019-07-10)
There is an out-of-bounds read in Exiv2::MrwImage::readMetadata in mrwimage.cpp in Exiv2 through 0.27.2.
hazedic/fuzzenv-exiv2
CVE-2019-13574 (2019-07-11)
In lib/mini_magick/image.rb in MiniMagick before 4.9.4, a fetched remote image filename could cause remote command execution because Image.open input is directly passed to Kernel#open, which accepts a '|' character followed by a command.
masahiro331/CVE-2019-13574
CVE-2019-13600
Crystalware/CVE-2019-13600
CVE-2019-13633 (2020-10-19)
Blinger.io v.1.0.2519 is vulnerable to Blind/Persistent XSS. An attacker can send arbitrary JavaScript code via a built-in communication channel, such as Telegram, WhatsApp, Viber, Skype, Facebook, Vkontakte, or Odnoklassniki. This is mishandled within the administration panel for conversations/all, conversations/inbox, conversations/unassigned, and conversations/closed.
Security-AVS/CVE-2019-13633
CVE-2019-13720 (2019-11-25)
Use after free in WebAudio in Google Chrome prior to 78.0.3904.87 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.
cve-2019-13720/cve-2019-13720
ChoKyuWon/CVE-2019-13720
CVE-2019-13956 (2019-07-18)
Discuz!ML 3.2 through 3.4 allows remote attackers to execute arbitrary PHP code via a modified language cookie, as demonstrated by changing 4gH4_0df5_language=en to 4gH4_0df5_language=en'.phpinfo().'; (if the random prefix 4gH4_0df5_ were used).
rhbb/CVE-2019-13956
CVE-2019-14040 (2020-02-07)
Using memory after being freed in qsee due to wrong implementation can lead to unexpected behavior such as execution of unknown code in Snapdragon Auto, Snapdragon Compute, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon IoT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon Wearables in APQ8009, APQ8017, APQ8053, APQ8096AU, APQ8098, MDM9150, MDM9206, MDM9207C, MDM9607, MDM9640, MDM9650, MSM8905, MSM8909W, MSM8917, MSM8920, MSM8937, MSM8940, MSM8953, MSM8996AU, MSM8998, QCS605, QM215, SDA660, SDA845, SDM429, SDM429W, SDM439, SDM450, SDM630, SDM632, SDM636, SDM660, SDM845, SDX20, SDX24, SM8150, SXR1130
tamirzb/CVE-2019-14040
CVE-2019-14041 (2020-02-07)
During listener modified response processing, a buffer overrun occurs due to lack of buffer size verification when updating message buffer with physical address information in Snapdragon Auto, Snapdragon Compute, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon IoT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon Wearables in APQ8009, APQ8017, APQ8053, APQ8096AU, APQ8098, MDM9206, MDM9207C, MDM9607, MDM9640, MDM9650, MSM8905, MSM8909W, MSM8917, MSM8953, MSM8996AU, Nicobar, QCM2150, QCS405, QCS605, QM215, Rennell, SA6155P, Saipan, SC8180X, SDA660, SDA845, SDM429, SDM429W, SDM439, SDM450, SDM632, SDM670, SDM710, SDM845, SDX20, SDX24, SDX55, SM6150, SM7150, SM8150, SM8250, SXR1130, SXR2130
tamirzb/CVE-2019-14041
CVE-2019-14079 (2020-03-05)
Access to the uninitialized variable when the driver tries to unmap the dma buffer of a request which was never mapped in the first place leading to kernel failure in Snapdragon Auto, Snapdragon Compute, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Wearables in APQ8009, APQ8053, MDM9607, MDM9640, MSM8909W, MSM8953, QCA6574AU, QCS605, SDA845, SDM429, SDM429W, SDM439, SDM450, SDM632, SDM670, SDM710, SDM845, SDX24, SM8150, SXR1130
parallelbeings/CVE-2019-14079
CVE-2019-14205 (2019-07-21)
A Local File Inclusion vulnerability in the Nevma Adaptive Images plugin before 0.6.67 for WordPress allows remote attackers to retrieve arbitrary files via the $REQUEST['adaptive-images-settings']['source_file'] parameter in adaptive-images-script.php.
security-kma/EXPLOITING-CVE-2019-14205
CVE-2019-14220 (2019-09-24)
An issue was discovered in BlueStacks 4.110 and below on macOS and on 4.120 and below on Windows. BlueStacks employs Android running in a virtual machine (VM) to enable Android apps to run on Windows or MacOS. Bug is in a local arbitrary file read through a system service call. The impacted method runs with System admin privilege and if given the file name as parameter returns you the content of file. A malicious app using the affected method can then read the content of any system file which it is not authorized to read
seqred-s-a/cve-2019-14220
CVE-2019-14267 (2019-07-29)
PDFResurrect 0.15 has a buffer overflow via a crafted PDF file because data associated with startxref and %%EOF is mishandled.
snappyJack/pdfresurrect_CVE-2019-14267
CVE-2019-14287 (2019-10-17)
In Sudo before 1.8.28, an attacker with access to a Runas ALL sudoer account can bypass certain policy blacklists and session PAM modules, and can cause incorrect logging, by invoking sudo with a crafted user ID. For example, this allows bypass of !root configuration, and USER= logging, for a "sudo -u \#$((0xffffffff))" command.
FauxFaux/sudo-cve-2019-14287
CashWilliams/CVE-2019-14287-demo
n0w4n/CVE-2019-14287
gurneesh/CVE-2019-14287-write-up
shallvhack/Sudo-Security-Bypass-CVE-2019-14287
Janette88/cve-2019-14287sudoexp
huang919/cve-2019-14287-PPT
wenyu1999/sudo-
Sindadziy/cve-2019-14287
Sindayifu/CVE-2019-14287-CVE-2014-6271
Unam3dd/sudo-vulnerability-CVE-2019-14287
CMNatic/Dockerized-CVE-2019-14287
SachinthaDeSilva-cmd/Exploit-CVE-2019-14287
HussyCool/CVE-2019-14287-IT18030372-
ShianTrish/sudo-Security-Bypass-vulnerability-CVE-2019-14287
ejlevin99/Sudo-Security-Bypass-Vulnerability
thinuri99/Sudo-Security-Bypass-Vulnerability-CVE-2019-14287-
janod313/-CVE-2019-14287-SUDO-bypass-vulnerability
DewmiApsara/CVE-2019-14287
M108Falcon/Sudo-CVE-2019-14287
CVE-2019-14314 (2019-08-27)
A SQL injection vulnerability exists in the Imagely NextGEN Gallery plugin before 3.2.11 for WordPress. Successful exploitation of this vulnerability would allow a remote attacker to execute arbitrary SQL commands on the affected system via modules/nextgen_gallery_display/package.module.nextgen_gallery_display.php.
imthoe/CVE-2019-14314
CVE-2019-14319 (2019-09-04)
The TikTok (formerly Musical.ly) application 12.2.0 for Android and iOS performs unencrypted transmission of images, videos, and likes. This allows an attacker to extract private sensitive information by sniffing network traffic.
MelroyB/CVE-2019-14319
CVE-2019-14326 (2020-04-14)
An issue was discovered in AndyOS Andy versions up to 46.11.113. By default, it starts telnet and ssh (ports 22 and 23) with root privileges in the emulated Android system. This can be exploited by remote attackers to gain full access to the device, or by malicious apps installed inside the emulator to perform privilege escalation from a normal user to root (unlike with standard methods of getting root privileges on Android - e.g., the SuperSu program - the user is not asked for consent). There is no authentication performed - access to a root shell is given upon a successful connection. NOTE: although this was originally published with a slightly different CVE ID number, the correct ID for this Andy vulnerability has always been CVE-2019-14326.
seqred-s-a/cve-2019-14326
CVE-2019-14339 (2019-09-05)
The ContentProvider in the Canon PRINT jp.co.canon.bsd.ad.pixmaprint 2.5.5 application for Android does not properly restrict canon.ij.printer.capability.data data access. This allows an attacker's malicious application to obtain sensitive information including factory passwords for the administrator web interface and WPA2-PSK key.
0x48piraj/CVE-2019-14339
CVE-2019-14439 (2019-07-30)
A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.x before 2.9.9.2. This occurs when Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint and the service has the logback jar in the classpath.
jas502n/CVE-2019-14439
CVE-2019-14450 (2019-10-28)
A directory traversal vulnerability was discovered in RepetierServer.exe in Repetier-Server 0.8 through 0.91 that allows for the creation of a user controlled XML file at an unintended location. When this is combined with CVE-2019-14451, an attacker can upload an "external command" configuration as a printer configuration, and achieve remote code execution. After exploitation, loading of the external command configuration is dependent on a system reboot or service restart.
securifera/CVE-2019-14450
CVE-2019-14514 (2020-02-10)
An issue was discovered in Microvirt MEmu all versions prior to 7.0.2. A guest Android operating system inside the MEmu emulator contains a /system/bin/systemd binary that is run with root privileges on startup (this is unrelated to Red Hat's systemd init program, and is a closed-source proprietary tool that seems to be developed by Microvirt). This program opens TCP port 21509, presumably to receive installation-related commands from the host OS. Because everything after the installer:uninstall command is concatenated directly into a system() call, it is possible to execute arbitrary commands by supplying shell metacharacters.
seqred-s-a/cve-2019-14514
CVE-2019-14529 (2019-08-02)
OpenEMR before 5.0.2 allows SQL Injection in interface/forms/eye_mag/save.php.
Wezery/CVE-2019-14529
CVE-2019-14530 (2019-08-13)
An issue was discovered in custom/ajax_download.php in OpenEMR before 5.0.2 via the fileName parameter. An attacker can download any file (that is readable by the user www-data) from server storage. If the requested file is writable for the www-data user and the directory /var/www/openemr/sites/default/documents/cqm_qrda/ exists, it will be deleted from server.
Wezery/CVE-2019-14530
CVE-2019-14537 (2019-08-07)
YOURLS through 1.7.3 is affected by a type juggling vulnerability in the api component that can result in login bypass.
Wocanilo/CVE-2019-14537
CVE-2019-14540 (2019-09-15)
A Polymorphic Typing issue was discovered in FasterXML jackson-databind before 2.9.10. It is related to com.zaxxer.hikari.HikariConfig.
LeadroyaL/cve-2019-14540-exploit
CVE-2019-14615 (2020-01-17)
Insufficient control flow in certain data structures for some Intel(R) Processors with Intel(R) Processor Graphics may allow an unauthenticated user to potentially enable information disclosure via local access.
HE-Wenjian/iGPU-Leak
CVE-2019-14745 (2019-08-07)
In radare2 before 3.7.0, a command injection vulnerability exists in bin_symbols() in libr/core/cbin.c. By using a crafted executable file, it's possible to execute arbitrary shell commands with the permissions of the victim. This vulnerability is due to improper handling of symbol names embedded in executables.
xooxo/CVE-2019-14745
CVE-2019-14751 (2019-08-22)
NLTK Downloader before 3.4.5 is vulnerable to a directory traversal, allowing attackers to write arbitrary files via a ../ (dot dot slash) in an NLTK package (ZIP archive) that is mishandled during extraction.
mssalvatore/CVE-2019-14751_PoC
CVE-2019-14830
Fr3d-/moodle-token-stealer
CVE-2019-14899 (2019-12-11)
A vulnerability was discovered in Linux, FreeBSD, OpenBSD, MacOS, iOS, and Android that allows a malicious access point, or an adjacent user, to determine if a connected user is using a VPN, make positive inferences about the websites they are visiting, and determine the correct sequence and acknowledgement numbers in use, allowing the bad actor to inject data into the TCP stream. This provides everything that is needed for an attacker to hijack active connections inside the VPN tunnel.
stryngs/hysteria
CVE-2019-14900 (2020-07-06)
A flaw was found in Hibernate ORM in versions before 5.3.18, 5.4.18 and 5.5.0.Beta1. A SQL injection in the implementation of the JPA Criteria API can permit unsanitized literals when a literal is used in the SELECT or GROUP BY parts of the query. This flaw could allow an attacker to access unauthorized information or possibly conduct further attacks.
shanika04/hibernate-orm
CVE-2019-14912 (2019-09-20)
An issue was discovered in PRiSE adAS 1.7.0. The OPENSSO module does not properly check the goto parameter, leading to an open redirect that leaks the session cookie.
Wocanilo/adaPwn
CVE-2019-15029 (2019-09-05)
FusionPBX 4.4.8 allows an attacker to execute arbitrary system commands by submitting a malicious command to the service_edit.php file (which will insert the malicious command into the database). To trigger the command, one needs to call the services.php file via a GET request with the service id followed by the parameter a=start to execute the stored command.
mhaskar/CVE-2019-15029
CVE-2019-15043 (2019-09-03)
In Grafana 2.x through 6.x before 6.3.4, parts of the HTTP API allow unauthenticated use. This makes it possible to run a denial of service attack against the server running Grafana.
h0ffayyy/CVE-2019-15043
CVE-2019-15053 (2019-08-14)
The "HTML Include and replace macro" plugin before 1.5.0 for Confluence Server allows a bypass of the includeScripts=false XSS protection mechanism via vectors involving an IFRAME element.
l0nax/CVE-2019-15053
CVE-2019-15107 (2019-08-15)
An issue was discovered in Webmin <=1.920. The parameter old in password_change.cgi contains a command injection vulnerability.
jas502n/CVE-2019-15107
HACHp1/webmin_docker_and_exp
ketlerd/CVE-2019-15107
AdministratorGithub/CVE-2019-15107
Pichuuuuu/CVE-2019-15107
Rayferrufino/Make-and-Break
AleWong/WebminRCE-EXP-CVE-2019-15107-
ianxtianxt/CVE-2019-15107
hannob/webminex
ChakoMoonFish/webmin_CVE-2019-15107
cdedmondson/CVE-2019-15107
ruthvikvegunta/CVE-2019-15107
n0obit4/Webmin_1.890-POC
squid22/Webmin_CVE-2019-15107
MuirlandOracle/CVE-2019-15107
diegojuan/CVE-2019-15107
CVE-2019-15120 (2019-08-16)
The Kunena extension before 5.1.14 for Joomla! allows XSS via BBCode.
h3llraiser/CVE-2019-15120
CVE-2019-15126 (2020-02-05)
An issue was discovered on Broadcom Wi-Fi client devices. Specifically timed and handcrafted traffic can cause internal errors (related to state transitions) in a WLAN device that lead to improper layer 2 Wi-Fi encryption with a consequent possibility of information disclosure over the air for a discrete set of traffic, a different vulnerability than CVE-2019-9500, CVE-2019-9501, CVE-2019-9502, and CVE-2019-9503.
0x13enny/kr00k
hexway/r00kie-kr00kie
akabe1/kr00ker
mustafasevim/kr00k-vulnerability
CVE-2019-15224 (2019-08-19)
The rest-client gem 1.6.10 through 1.6.13 for Ruby, as distributed on RubyGems.org, included a code-execution backdoor inserted by a third party. Versions <=1.6.9 and >=1.6.14 are unaffected.
chef-cft/inspec_cve_2019_15224
CVE-2019-15233 (2019-08-20)
The Live:Text Box macro in the Old Street Live Input Macros app before 2.11 for Confluence has XSS, leading to theft of the Administrator Session Cookie.
l0nax/CVE-2019-15233
CVE-2019-15511 (2019-11-21)
An exploitable local privilege escalation vulnerability exists in the GalaxyClientService installed by GOG Galaxy. Due to Improper Access Control, an attacker can send unauthenticated local TCP packets to the service to gain SYSTEM privileges in Windows system where GOG Galaxy software is installed. All GOG Galaxy versions before 1.2.60 and all corresponding versions of GOG Galaxy 2.0 Beta are affected.
adenkiewicz/CVE-2019-15511
CVE-2019-15588 (2019-11-01)
There is an OS Command Injection in Nexus Repository Manager <= 2.14.14 (bypass CVE-2019-5475) that could allow an attacker a Remote Code Execution (RCE). All instances using CommandLineExecutor.java with user-supplied data is vulnerable, such as the Yum Configuration Capability.
lyy289065406/CVE-2019-15588
CVE-2019-15605 (2020-02-07)
HTTP request smuggling in Node.js 10, 12, and 13 causes malicious payload delivery when transfer-encoding is malformed
jlcarruda/node-poc-http-smuggling
CVE-2019-15642 (2019-08-26)
rpc.cgi in Webmin through 1.920 allows authenticated Remote Code Execution via a crafted object name because unserialise_variable makes an eval call. NOTE: the Webmin_Servers_Index documentation states "RPC can be used to run any command or modify any file on a server, which is why access to it must not be granted to un-trusted Webmin users."
jas502n/CVE-2019-15642
CVE-2019-15802 (2019-11-14)
An issue was discovered on Zyxel GS1900 devices with firmware before 2.50(AAHH.0)C0. The firmware hashes and encrypts passwords using a hardcoded cryptographic key in sal_util_str_encrypt() in libsal.so.0.0. The parameters (salt, IV, and key data) are used to encrypt and decrypt all passwords using AES256 in CBC mode. With the parameters known, all previously encrypted passwords can be decrypted. This includes the passwords that are part of configuration backups or otherwise embedded as part of the firmware.
jasperla/CVE-2019-15802
CVE-2019-15813 (2019-09-04)
Multiple file upload restriction bypass vulnerabilities in Sentrifugo 3.2 could allow authenticated users to execute arbitrary code via a webshell.
iamhrishikeshpadhye/CVE-2019-15813-Exploitation
wolf1892/CVE-2019-15813
CVE-2019-15846 (2019-09-06)
Exim before 4.92.2 allows remote attackers to execute arbitrary code as root via a trailing backslash.
synacktiv/Exim-CVE-2019-15846
CVE-2019-15858 (2019-09-03)
admin/includes/class.import.snippet.php in the "Woody ad snippets" plugin before 2.2.5 for WordPress allows unauthenticated options import, as demonstrated by storing an XSS payload for remote code execution.
GeneralEG/CVE-2019-15858
CVE-2019-15972 (2019-11-25)
A vulnerability in the web-based management interface of Cisco Unified Communications Manager could allow an authenticated, remote attacker to conduct SQL injection attacks on an affected system. The vulnerability exists because the web-based management interface improperly validates SQL values. An attacker could exploit this vulnerability by authenticating to the application and sending malicious requests to an affected system. A successful exploit could allow the attacker to modify values on or return values from the underlying database.
FSecureLABS/Cisco-UCM-SQLi-Scripts
CVE-2019-16097 (2019-09-08)
core/api/user.go in Harbor 1.7.0 through 1.8.2 allows non-admin users to create admin accounts via the POST /api/users API, when Harbor is setup with DB as authentication backend and allow user to do self-registration. Fixed version: v1.7.6 v1.8.3. v.1.9.0. Workaround without applying the fix: configure Harbor to use non-DB authentication backend such as LDAP.
evilAdan0s/CVE-2019-16097
rockmelodies/CVE-2019-16097-batch
ianxtianxt/CVE-2019-16097
dacade/cve-2019-16097
theLSA/harbor-give-me-admin
luckybool1020/CVE-2019-16097
CVE-2019-16098 (2019-09-11)
The driver in Micro-Star MSI Afterburner 4.6.2.15658 (aka RTCore64.sys and RTCore32.sys) allows any authenticated user to read and write to arbitrary memory, I/O ports, and MSRs. This can be exploited for privilege escalation, code execution under high privileges, and information disclosure. These signed drivers can also be used to bypass the Microsoft driver-signing policy to deploy malicious code.
Barakat/CVE-2019-16098
CVE-2019-16113 (2019-09-08)
Bludit 3.9.2 allows remote code execution via bl-kernel/ajax/upload-images.php because PHP code can be entered with a .jpg file name, and then this PHP code can write other PHP code to a ../ pathname.
ynots0ups/CVE-2019-16113
cybervaca/CVE-2019-16113
hg8/CVE-2019-16113-PoC
Kenun99/CVE-2019-16113-Dockerfile
itsjeffersonli/CVE-2019-16113
west-tek/CVE-2019-16113-PoC
Noroh4xy/CVE-2019-16113
CVE-2019-16278 (2019-10-14)
Directory Traversal in the function http_verify in nostromo nhttpd through 1.9.6 allows an attacker to achieve remote code execution via a crafted HTTP request.
jas502n/CVE-2019-16278
imjdl/CVE-2019-16278-PoC
ianxtianxt/CVE-2019-16278
darkerego/Nostromo_Python3
AnubisSec/CVE-2019-16278
theRealFr13nd/CVE-2019-16278-Nostromo_1.9.6-RCE
Kr0ff/cve-2019-16278
NHPT/CVE-2019-16278
Unam3dd/nostromo_1_9_6_rce
keshiba/cve-2019-16278
CVE-2019-16279 (2019-10-14)
A memory error in the function SSL_accept in nostromo nhttpd through 1.9.6 allows an attacker to trigger a denial of service via a crafted HTTP request.
ianxtianxt/CVE-2019-16279
CVE-2019-16374 (2020-08-13)
Pega Platform 8.2.1 allows LDAP injection because a username can contain a * character and can be of unlimited length. An attacker can specify four characters of a username, followed by the * character, to bypass access control.
IAG0110/CVE-2019-16374
CVE-2019-16394 (2019-09-17)
SPIP before 3.1.11 and 3.2 before 3.2.5 provides different error messages from the password-reminder page depending on whether an e-mail address exists, which might help attackers to enumerate subscribers.
SilentVoid13/Silent_CVE_2019_16394
CVE-2019-16405 (2019-11-21)
Centreon Web before 2.8.30, 18.10.x before 18.10.8, 19.04.x before 19.04.5 and 19.10.x before 19.10.2 allows Remote Code Execution by an administrator who can modify Macro Expression location settings. CVE-2019-16405 and CVE-2019-17501 are similar to one another and may be the same.
TheCyberGeek/CVE-2019-16405.rb
CVE-2019-16662 (2019-10-28)
An issue was discovered in rConfig 3.9.2. An attacker can directly execute system commands by sending a GET request to ajaxServerSettingsChk.php because the rootUname parameter is passed to the exec function without filtering, which can lead to command execution.
mhaskar/CVE-2019-16662
CVE-2019-16663 (2019-10-28)
An issue was discovered in rConfig 3.9.2. An attacker can directly execute system commands by sending a GET request to search.crud.php because the catCommand parameter is passed to the exec function without filtering, which can lead to command execution.
mhaskar/CVE-2019-16663
CVE-2019-16692 (2019-09-22)
phpIPAM 1.4 allows SQL injection via the app/admin/custom-fields/filter-result.php table parameter when action=add is used.
kkirsche/CVE-2019-16692
CVE-2019-16759 (2019-09-24)
vBulletin 5.x through 5.5.4 allows remote command execution via the widgetConfig[code] parameter in an ajax/render/widget_php routestring request.
M0sterHxck/CVE-2019-16759-Vbulletin-rce-exploit
r00tpgp/http-vuln-CVE-2019-16759
jas502n/CVE-2019-16759
theLSA/vbulletin5-rce
FarjaalAhmad/CVE-2019-16759
andripwn/pwn-vbulletin
psychoxploit/vbull
jd-961/CVE-2019-16759-bypass
nako48/CVE-2019-16759
mas1337/CVE-2019-16759
sunian19/CVE-2019-16759
ludy-dev/vBulletin_Routestring-RCE
apidotmy/CVE-2019-16759
CVE-2019-16784 (2020-01-14)
In PyInstaller before version 3.6, only on Windows, a local privilege escalation vulnerability is present in this particular case: If a software using PyInstaller in "onefile" mode is launched by a privileged user (at least more than the current one) which have his "TempPath" resolving to a world writable directory. This is the case for example if the software is launched as a service or as a scheduled task using a system account (TempPath will be C:\Windows\Temp). In order to be exploitable the software has to be (re)started after the attacker launch the exploit program, so for a service launched at startup, a service restart is needed (e.g. after a crash or an upgrade).
AlterSolutions/PyInstallerPrivEsc
CVE-2019-16889 (2019-09-25)
Ubiquiti EdgeMAX devices before 2.0.3 allow remote attackers to cause a denial of service (disk consumption) because *.cache files in /var/run/beaker/container_file/ are created when providing a valid length payload of 249 characters or fewer to the beaker.session.id cookie in a GET header. The attacker can use a long series of unique session IDs.
grampae/meep
CVE-2019-16920 (2019-09-27)
Unauthenticated remote code execution occurs in D-Link products such as DIR-655C, DIR-866L, DIR-652, and DHP-1565. The issue occurs when the attacker sends an arbitrary input to a "PingTest" device common gateway interface that could lead to common injection. An attacker who successfully triggers the command injection could achieve full system compromise. Later, it was independently found that these are also affected: DIR-855L, DAP-1533, DIR-862L, DIR-615, DIR-835, and DIR-825.
pwnhacker0x18/CVE-2019-16920-MassPwn3r
CVE-2019-16941 (2019-09-28)
NSA Ghidra through 9.0.4, when experimental mode is enabled, allows arbitrary code execution if the Read XML Files feature of Bit Patterns Explorer is used with a modified XML document. This occurs in Features/BytePatterns/src/main/java/ghidra/bitpatterns/info/FileBitPatternInfoReader.java. An attack could start with an XML document that was originally created by DumpFunctionPatternInfoScript but then directly modified by an attacker (for example, to make a java.lang.Runtime.exec call).
purpleracc00n/CVE-2019-16941
CVE-2019-17026 (2020-03-01)
Incorrect alias information in IonMonkey JIT compiler for setting array elements could lead to a type confusion. We are aware of targeted attacks in the wild abusing this flaw. This vulnerability affects Firefox ESR < 68.4.1, Thunderbird < 68.4.1, and Firefox < 72.0.1.
maxpl0it/CVE-2019-17026-Exploit
CVE-2019-17041 (2019-10-07)
An issue was discovered in Rsyslog v8.1908.0. contrib/pmaixforwardedfrom/pmaixforwardedfrom.c has a heap overflow in the parser for AIX log messages. The parser tries to locate a log message delimiter (in this case, a space or a colon) but fails to account for strings that do not satisfy this constraint. If the string does not match, then the variable lenMsg will reach the value zero and will skip the sanity check that detects invalid log messages. The message will then be considered valid, and the parser will eat up the nonexistent colon delimiter. In doing so, it will decrement lenMsg, a signed integer, whose value was zero and now becomes minus one. The following step in the parser is to shift left the contents of the message. To do this, it will call memmove with the right pointers to the target and destination strings, but the lenMsg will now be interpreted as a huge value, causing a heap overflow.
Resery/CVE-2019-17041
CVE-2019-17080 (2019-10-02)
mintinstall (aka Software Manager) 7.9.9 for Linux Mint allows code execution if a REVIEWS_CACHE file is controlled by an attacker, because an unpickle occurs. This is resolved in 8.0.0 and backports.
Andhrimnirr/Mintinstall-object-injection
materaj2/Mintinstall-object-injection
CVE-2019-17124 (2019-10-09)
Kramer VIAware 2.5.0719.1034 has Incorrect Access Control.
hessandrew/CVE-2019-17124
CVE-2019-17221 (2019-11-05)
PhantomJS through 2.1.1 has an arbitrary file read vulnerability, as demonstrated by an XMLHttpRequest for a file:// URI. The vulnerability exists in the page.open() function of the webpage module, which loads a specified URL and calls a given callback. An attacker can supply a specially crafted HTML file, as user input, that allows reading arbitrary files on the filesystem. For example, if page.render() is the function callback, this generates a PDF or an image of the targeted file. NOTE: this product is no longer developed.
h4ckologic/CVE-2019-17221
CVE-2019-17234 (2019-11-12)
includes/class-coming-soon-creator.php in the igniteup plugin through 3.4 for WordPress allows unauthenticated arbitrary file deletion.
administra1tor/CVE-2019-17234b-Exploit
CVE-2019-17240 (2019-10-06)
bl-kernel/security.class.php in Bludit 3.9.2 allows attackers to bypass a brute-force protection mechanism by using many different forged X-Forwarded-For or Client-IP HTTP headers.
pingport80/CVE-2019-17240
LucaReggiannini/Bludit-3-9-2-bb
tripleoctopus/Bludit-CVE-2019-17240-Fork
Noroh4xy/CVE-2019-17240
ColdFusionX/CVE-2019-17240_Bludit-BF-Bypass
CVE-2019-17424 (2019-10-22)
A stack-based buffer overflow in the processPrivilage() function in IOS/process-general.c in nipper-ng 0.11.10 allows remote attackers (serving firewall configuration files) to achieve Remote Code Execution or Denial Of Service via a crafted file.
guywhataguy/CVE-2019-17424
CVE-2019-17427 (2019-10-09)
In Redmine before 3.4.11 and 4.0.x before 4.0.4, persistent XSS exists due to textile formatting errors.
RealLinkers/CVE-2019-17427
CVE-2019-17495 (2019-10-10)
A Cascading Style Sheets (CSS) injection vulnerability in Swagger UI before 3.23.11 allows attackers to use the Relative Path Overwrite (RPO) technique to perform CSS-based input field value exfiltration, such as exfiltration of a CSRF token value. In other words, this product intentionally allows the embedding of untrusted JSON data from remote servers, but it was not previously known that <style>@import within the JSON data was a functional attack method.
SecT0uch/CVE-2019-17495-test
CVE-2019-17525 (2020-04-21)
The login page on D-Link DIR-615 T1 20.10 devices allows remote attackers to bypass the CAPTCHA protection mechanism and conduct brute-force attacks.
huzaifahussain98/CVE-2019-17525
CVE-2019-17558 (2019-12-30)
Apache Solr 5.0.0 to Apache Solr 8.3.1 are vulnerable to a Remote Code Execution through the VelocityResponseWriter. A Velocity template can be provided through Velocity templates in a configset `velocity/` directory or as a parameter. A user defined configset could contain renderable, potentially malicious, templates. Parameter provided templates are disabled by default, but can be enabled by setting `params.resource.loader.enabled` by defining a response writer with that setting set to `true`. Defining a response writer requires configuration API access. Solr 8.4 removed the params resource loader entirely, and only enables the configset-provided template rendering when the configset is `trusted` (has been uploaded by an authenticated user).
SDNDTeam/CVE-2019-17558_Solr_Vul_Tool
zhzyker/exphub
gsheller/Solr_CVE-2019-17558
pan3a/Solr-CVE-2019-17558
xkyrage/Exploit_CVE-2019-17558-RCE
CVE-2019-17564 (2020-04-01)
Unsafe deserialization occurs within a Dubbo application which has HTTP remoting enabled. An attacker may submit a POST request with a Java object in it to completely compromise a Provider instance of Apache Dubbo, if this instance enables HTTP. This issue affected Apache Dubbo 2.7.0 to 2.7.4, 2.6.0 to 2.6.7, and all 2.5.x versions.
r00t4dm/CVE-2019-17564
Jaky5155/CVE-2019-17564
Hu3sky/CVE-2019-17564
Exploit-3389/CVE-2019-17564
Dor-Tumarkin/CVE-2019-17564-FastJson-Gadget
fairyming/CVE-2019-17564
CVE-2019-17570 (2020-01-23)
An untrusted deserialization was found in the org.apache.xmlrpc.parser.XmlRpcResponseParser:addResult method of Apache XML-RPC (aka ws-xmlrpc) library. A malicious XML-RPC server could target a XML-RPC client causing it to execute arbitrary code. Apache XML-RPC is no longer maintained and this issue will not be fixed.
r00t4dm/CVE-2019-17570
orangecertcc/xmlrpc-common-deserialization
CVE-2019-17571 (2019-12-20)
Included in Log4j 1.2 is a SocketServer class that is vulnerable to deserialization of untrusted data which can be exploited to remotely execute arbitrary code when combined with a deserialization gadget when listening to untrusted network traffic for log data. This affects Log4j versions up to 1.2 up to 1.2.17.
shadow-horse/CVE-2019-17571
CVE-2019-17596 (2019-10-24)
Go before 1.12.11 and 1.3.x before 1.13.2 can panic upon an attempt to process network traffic containing an invalid DSA public key. There are several attack scenarios, such as traffic from a client to a server that verifies client certificates.
pquerna/poc-dsa-verify-CVE-2019-17596
CVE-2019-17625 (2019-10-16)
There is a stored XSS in Rambox 0.6.9 that can lead to code execution. The XSS is in the name field while adding/editing a service. The problem occurs due to incorrect sanitization of the name field when being processed and stored. This allows a user to craft a payload for Node.js and Electron, such as an exec of OS commands within the onerror attribute of an IMG element.
Ekultek/CVE-2019-17625
CVE-2019-17633 (2019-12-19)
For Eclipse Che versions 6.16 to 7.3.0, with both authentication and TLS disabled, visiting a malicious web site could trigger the start of an arbitrary Che workspace. Che with no authentication and no TLS is not usually deployed on a public network but is often used for local installations (e.g. on personal laptops). In that case, even if the Che API is not exposed externally, some javascript running in the local browser is able to send requests to it.
mgrube/CVE-2019-17633
CVE-2019-17658 (2020-03-12)
An unquoted service path vulnerability in the FortiClient FortiTray component of FortiClientWindows v6.2.2 and prior allow an attacker to gain elevated privileges via the FortiClientConsole executable service path.
Ibonok/CVE-2019-17658
CVE-2019-17671 (2019-10-17)
In WordPress before 5.2.4, unauthenticated viewing of certain content is possible because the static query property is mishandled.
rhbb/CVE-2019-17671
CVE-2019-18371 (2019-10-23)
An issue was discovered on Xiaomi Mi WiFi R3G devices before 2.28.23-stable. There is a directory traversal vulnerability to read arbitrary files via a misconfigured NGINX alias, as demonstrated by api-third-party/download/extdisks../etc/config/account. With this vulnerability, the attacker can bypass authentication.
UltramanGaia/Xiaomi_Mi_WiFi_R3G_Vulnerability_POC
CVE-2019-18418 (2019-10-24)
clonos.php in ClonOS WEB control panel 19.09 allows remote attackers to gain full access via change password requests because there is no session management.
Andhrimnirr/ClonOS-WEB-control-panel-multi-vulnerability
CVE-2019-18426 (2020-01-21)
A vulnerability in WhatsApp Desktop versions prior to 0.3.9309 when paired with WhatsApp for iPhone versions prior to 2.20.10 allows cross-site scripting and local file reading. Exploiting the vulnerability requires the victim to click a link preview from a specially crafted text message.
PerimeterX/CVE-2019-18426
CVE-2019-18634 (2020-01-29)
In Sudo before 1.8.26, if pwfeedback is enabled in /etc/sudoers, users can trigger a stack-based buffer overflow in the privileged sudo process. (pwfeedback is a default setting in Linux Mint and elementary OS; however, it is NOT the default for upstream and many other packages, and would exist only if enabled by an administrator.) The attacker needs to deliver a long string to the stdin of getln() in tgetpass.c.
Plazmaz/CVE-2019-18634
saleemrashid/sudo-cve-2019-18634
N1et/CVE-2019-18634
ptef/CVE-2019-18634
CVE-2019-18655 (2019-11-12)
File Sharing Wizard version 1.5.0 build 2008 is affected by a Structured Exception Handler based buffer overflow vulnerability. An unauthenticated attacker is able to perform remote command execution and obtain a command shell by sending a HTTP GET request including the malicious payload in the URL. A similar issue to CVE-2019-17415, CVE-2019-16724, and CVE-2010-2331.
0xhuesca/CVE-2019-18655
CVE-2019-18683 (2019-11-04)
An issue was discovered in drivers/media/platform/vivid in the Linux kernel through 5.3.8. It is exploitable for privilege escalation on some Linux distributions where local users have /dev/video0 access, but only if the driver happens to be loaded. There are multiple race conditions during streaming stopping in this driver (part of the V4L2 subsystem). These issues are caused by wrong mutex locking in vivid_stop_generating_vid_cap(), vivid_stop_generating_vid_out(), sdr_cap_stop_streaming(), and the corresponding kthreads. At least one of these race conditions leads to a use-after-free.
sanjana123-cloud/CVE-2019-18683
Limesss/cve-2019-18683
CVE-2019-18873 (2019-11-11)
FUDForum 3.0.9 is vulnerable to Stored XSS via the User-Agent HTTP header. This may result in remote code execution. An attacker can use a user account to fully compromise the system via a GET request. When the admin visits user information under "User Manager" in the control panel, the payload will execute. This will allow for PHP files to be written to the web root, and for code to execute on the remote server. The problem is in admsession.php and admuser.php.
fuzzlove/FUDforum-XSS-RCE
CVE-2019-18885 (2019-11-14)
fs/btrfs/volumes.c in the Linux kernel before 5.1 allows a btrfs_verify_dev_extents NULL pointer dereference via a crafted btrfs image because fs_devices->devices is mishandled within find_device, aka CID-09ba3bc9dd15.
bobfuzzer/CVE-2019-18885
CVE-2019-18890 (2019-11-21)
A SQL injection vulnerability in Redmine through 3.2.9 and 3.3.x before 3.3.10 allows Redmine users to access protected information via a crafted object query.
RealLinkers/CVE-2019-18890
CVE-2019-18935 (2019-12-11)
Progress Telerik UI for ASP.NET AJAX through 2019.3.1023 contains a .NET deserialization vulnerability in the RadAsyncUpload function. This is exploitable when the encryption keys are known due to the presence of CVE-2017-11317 or CVE-2017-11357, or other means. Exploitation can result in remote code execution. (As of 2020.1.114, a default setting prevents the exploit. In 2019.3.1023, but not earlier versions, a non-default setting can prevent exploitation.)
bao7uo/RAU_crypto
noperator/CVE-2019-18935
becrevex/Telerik_CVE-2019-18935
ThanHuuTuan/Telerik_CVE-2019-18935
ThanHuuTuan/CVE_2019_18935
murataydemir/CVE-2019-18935
random-robbie/CVE-2019-18935
CVE-2019-18988 (2020-02-07)
TeamViewer Desktop through 14.7.1965 allows a bypass of remote-login access control because the same key is used for different customers' installations. It used a shared AES key for all installations since at least as far back as v7.0.43148, and used it for at least OptionsPasswordAES in the current version of the product. If an attacker were to know this key, they could decrypt protect information stored in the registry or configuration files of TeamViewer. With versions before v9.x , this allowed for attackers to decrypt the Unattended Access password to the system (which allows for remote login to the system as well as headless file browsing). The latest version still uses the same key for OptionPasswordAES but appears to have changed how the Unattended Access password is stored. While in most cases an attacker requires an existing session on a system, if the registry/configuration keys were stored off of the machine (such as in a file share or online), an attacker could then decrypt the required password to login to the system.
ReverseBrain/CVE-2019-18988
mr-r3b00t/CVE-2019-18988
CVE-2019-19012 (2019-11-16)
An integer overflow in the search_in_range function in regexec.c in Oniguruma 6.x before 6.9.4_rc2 leads to an out-of-bounds read, in which the offset of this read is under the control of an attacker. (This only affects the 32-bit compiled version). Remote attackers can cause a denial-of-service or information disclosure, or possibly have unspecified other impact, via a crafted regular expression.
ManhNDd/CVE-2019-19012
tarantula-team/CVE-2019-19012
CVE-2019-19033 (2019-11-21)
Jalios JCMS 10 allows attackers to access any part of the website and the WebDAV server with administrative privileges via a backdoor account, by using any username and the hardcoded dev password.
ricardojoserf/CVE-2019-19033
CVE-2019-19203 (2019-11-21)
An issue was discovered in Oniguruma 6.x before 6.9.4_rc2. In the function gb18030_mbc_enc_len in file gb18030.c, a UChar pointer is dereferenced without checking if it passed the end of the matched string. This leads to a heap-based buffer over-read.
ManhNDd/CVE-2019-19203
tarantula-team/CVE-2019-19203
CVE-2019-19204 (2019-11-21)
An issue was discovered in Oniguruma 6.x before 6.9.4_rc2. In the function fetch_interval_quantifier (formerly known as fetch_range_quantifier) in regparse.c, PFETCH is called without checking PEND. This leads to a heap-based buffer over-read.
ManhNDd/CVE-2019-19204
tarantula-team/CVE-2019-19204
CVE-2019-19231 (2019-12-20)
An insecure file access vulnerability exists in CA Client Automation 14.0, 14.1, 14.2, and 14.3 Agent for Windows that can allow a local attacker to gain escalated privileges.
hessandrew/CVE-2019-19231
CVE-2019-19268
TheCyberGeek/CVE-2019-19268
CVE-2019-19315 (2019-12-17)
NLSSRV32.EXE in Nalpeiron Licensing Service 7.3.4.0, as used with Nitro PDF and other products, allows Elevation of Privilege via the \\.\mailslot\nlsX86ccMailslot mailslot.
monoxgas/mailorder
CVE-2019-19356 (2020-02-07)
Netis WF2419 is vulnerable to authenticated Remote Code Execution (RCE) as root through the router Web management page. The vulnerability has been found in firmware version V1.2.31805 and V2.2.36123. After one is connected to this page, it is possible to execute system commands as root through the tracert diagnostic tool because of lack of user input sanitizing.
shadowgatt/CVE-2019-19356
qq1515406085/CVE-2019-19356
CVE-2019-19369
TheCyberGeek/CVE-2019-19369
CVE-2019-19383 (2019-12-03)
freeFTPd 1.0.8 has a Post-Authentication Buffer Overflow via a crafted SIZE command (this is exploitable even if logging is disabled).
cwinfosec/CVE-2019-19383
CVE-2019-19393 (2020-10-01)
The Web application on Rittal CMC PU III 7030.000 V3.00 V3.11.00_2 to V3.15.70_4 devices fails to sanitize user input on the system configurations page. This allows an attacker to backdoor the device with HTML and browser-interpreted content (such as JavaScript or other client-side scripts) as the content is always displayed after and before login. Persistent XSS allows an attacker to modify displayed content or to change the victim's information. Successful exploitation requires access to the web management interface, either with valid credentials or a hijacked session.
miguelhamal/CVE-2019-19393
CVE-2019-19511
jra89/CVE-2019-19511
CVE-2019-19520 (2019-12-04)
xlock in OpenBSD 6.6 allows local users to gain the privileges of the auth group by providing a LIBGL_DRIVERS_PATH environment variable, because xenocara/lib/mesa/src/loader/loader.c mishandles dlopen.
retrymp3/Openbsd-Privilege-Escalation
CVE-2019-19550 (2020-01-31)
Remote Authentication Bypass in Senior Rubiweb 6.2.34.28 and 6.2.34.37 allows admin access to sensitive information of affected users using vulnerable versions. The attacker only needs to provide the correct URL.
underprotection/CVE-2019-19550
CVE-2019-19576 (2019-12-04)
class.upload.php in verot.net class.upload before 1.0.3 and 2.x before 2.0.4, as used in the K2 extension for Joomla! and other products, omits .phar from the set of dangerous file extensions.
jra89/CVE-2019-19576
CVE-2019-19633
jra89/CVE-2019-19633
CVE-2019-19634 (2019-12-17)
class.upload.php in verot.net class.upload through 1.0.3 and 2.x through 2.0.4, as used in the K2 extension for Joomla! and other products, omits .pht from the set of dangerous file extensions, a similar issue to CVE-2019-19576.
jra89/CVE-2019-19634
CVE-2019-19651
jra89/CVE-2019-19651
CVE-2019-19652
jra89/CVE-2019-19652
CVE-2019-19653
jra89/CVE-2019-19653
CVE-2019-19654
jra89/CVE-2019-19654
CVE-2019-19658
jra89/CVE-2019-19658
CVE-2019-19699 (2020-04-06)
There is Authenticated remote code execution in Centreon Infrastructure Monitoring Software through 19.10 via Pollers misconfiguration, leading to system compromise via apache crontab misconfiguration, This allows the apache user to modify an executable file executed by root at 22:30 every day. To exploit the vulnerability, someone must have Admin access to the Centreon Web Interface and create a custom main.php?p=60803&type=3 command. The user must then set the Pollers Post-Restart Command to this previously created command via the main.php?p=60901&o=c&server_id=1 URI. This is triggered via an export of the Poller Configuration.
SpengeSec/CVE-2019-19699
CVE-2019-19732 (2019-12-30)
translation_manage_text.ajax.php and various *_manage.ajax.php in MFScripts YetiShare 3.5.2 through 4.5.3 directly insert values from the aSortDir_0 and/or sSortDir_0 parameter into a SQL string. This allows an attacker to inject their own SQL and manipulate the query, typically extracting data from the database, aka SQL Injection.
jra89/CVE-2019-19732
CVE-2019-19733 (2019-12-30)
_get_all_file_server_paths.ajax.php (aka get_all_file_server_paths.ajax.php) in MFScripts YetiShare 3.5.2 through 4.5.3 does not sanitize or encode the output from the fileIds parameter on the page, which would allow an attacker to input HTML or execute scripts on the site, aka XSS.
jra89/CVE-2019-19733
CVE-2019-19734 (2019-12-30)
_account_move_file_in_folder.ajax.php in MFScripts YetiShare 3.5.2 directly inserts values from the fileIds parameter into a SQL string. This allows an attacker to inject their own SQL and manipulate the query, typically extracting data from the database, aka SQL Injection.
jra89/CVE-2019-19734
CVE-2019-19735 (2019-12-30)
class.userpeer.php in MFScripts YetiShare 3.5.2 through 4.5.3 uses an insecure method of creating password reset hashes (based only on microtime), which allows an attacker to guess the hash and set the password within a few hours by bruteforcing.
jra89/CVE-2019-19735
CVE-2019-19738 (2019-12-30)
log_file_viewer.php in MFScripts YetiShare 3.5.2 through 4.5.3 does not sanitize or encode the output from the lFile parameter on the page, which would allow an attacker to input HTML or execute scripts on the site, aka XSS.
jra89/CVE-2019-19738
CVE-2019-19781 (2019-12-27)
An issue was discovered in Citrix Application Delivery Controller (ADC) and Gateway 10.5, 11.1, 12.0, 12.1, and 13.0. They allow Directory Traversal.
mekoko/CVE-2019-19781
projectzeroindia/CVE-2019-19781
trustedsec/cve-2019-19781
cisagov/check-cve-2019-19781
jas502n/CVE-2019-19781
ianxtianxt/CVE-2019-19781
mpgn/CVE-2019-19781
oways/CVE-2019-19781
becrevex/Citrix_CVE-2019-19781
unknowndevice64/Exploits_CVE-2019-19781
bufsnake/CVE-2019-19781
x1sec/citrixmash_scanner
Jabo-SCO/Shitrix-CVE-2019-19781
x1sec/CVE-2019-19781
hollerith/CVE-2019-19781
aqhmal/CVE-2019-19781
MalwareTech/CitrixHoneypot
mekhalleh/citrix_dir_traversal_rce
zenturacp/cve-2019-19781-web
zgelici/CVE-2019-19781-Checker
digitalshadows/CVE-2019-19781_IOCs
onSec-fr/CVE-2019-19781-Forensic
DanielWep/CVE-NetScalerFileSystemCheck
Castaldio86/Detect-CVE-2019-19781
j81blog/ADC-19781
b510/CVE-2019-19781
redscan/CVE-2019-19781
DIVD-NL/Citrix-CVE-2019-19781
ynsmroztas/citrix.sh
digitalgangst/massCitrix
fireeye/ioc-scanner-CVE-2019-19781
citrix/ioc-scanner-CVE-2019-19781
x1sec/citrix-honeypot
L4r1k/CitrixNetscalerAnalysis
Azeemering/CVE-2019-19781-DFIR-Notes
0xams/citrixvulncheck
RaulCalvoLaorden/CVE-2019-19781
nmanzi/webcvescanner
darren646/CVE-2019-19781POC
5l1v3r1/Citrix_CVE-2019-19781
Jerry-Swift/CVE-2019-19781-scanner
Roshi99/Remote-Code-Execution-Exploit-for-Citrix-Application-Delivery-Controller-and-Citrix-Gateway-CVE-201
yukar1z0e/CVE-2019-19781
SharpHack/CVE-2019-19781
qiong-qi/CVE-2019-19781-poc
w4fz5uck5/CVE-2019-19781-CitrixRCE
andripwn/CVE-2019-19781
VladRico/CVE-2019-19781
CVE-2019-19844 (2019-12-18)
Django before 1.11.27, 2.x before 2.2.9, and 3.x before 3.0.1 allows account takeover. A suitably crafted email address (that is equal to an existing user's email address after case transformation of Unicode characters) would allow an attacker to be sent a password reset token for the matched user account. (One mitigation in the new releases is to send password reset tokens only to the registered user email address.)
ryu22e/django_cve_2019_19844_poc
andripwn/django_cve201919844
0xsha/CVE_2019_19844
CVE-2019-19871
VDISEC/CVE-2019-19871-AuditGuide
CVE-2019-19905 (2019-12-19)
NetHack 3.6.x before 3.6.4 is prone to a buffer overflow vulnerability when reading very long lines from configuration files. This affects systems that have NetHack installed suid/sgid, and shared systems that allow users to upload their own configuration files.
dpmdpm2/CVE-2019-19905
CVE-2019-19943 (2020-02-28)
The HTTP service in quickweb.exe in Pablo Quick 'n Easy Web Server 3.3.8 allows Remote Unauthenticated Heap Memory Corruption via a large host or domain parameter. It may be possible to achieve remote code execution because of a double free.
cwinfosec/CVE-2019-19943
CVE-2019-20059 (2020-02-10)
payment_manage.ajax.php and various *_manage.ajax.php in MFScripts YetiShare 3.5.2 through 4.5.4 directly insert values from the sSortDir_0 parameter into a SQL string. This allows an attacker to inject their own SQL and manipulate the query, typically extracting data from the database, aka SQL Injection. NOTE: this issue exists because of an incomplete fix for CVE-2019-19732.
jra89/CVE-2019-20059
CVE-2019-20085 (2019-12-29)
TVT NVMS-1000 devices allow GET /.. Directory Traversal
AleDiBen/NVMS1000-Exploit
CVE-2019-20197 (2019-12-31)
In Nagios XI 5.6.9, an authenticated user is able to execute arbitrary OS commands via shell metacharacters in the id parameter to schedulereport.php, in the context of the web-server user account.
lp008/CVE-2019-20197
jas502n/CVE-2019-20197
CVE-2019-20224 (2020-01-09)
netflow_get_stats in functions_netflow.php in Pandora FMS 7.0NG allows remote authenticated users to execute arbitrary OS commands via shell metacharacters in the ip_src parameter in an index.php?operation/netflow/nf_live_view request. This issue has been fixed in Pandora FMS 7.0 NG 742.
mhaskar/CVE-2019-20224
CVE-2019-20326 (2020-03-16)
A heap-based buffer overflow in _cairo_image_surface_create_from_jpeg() in extensions/cairo_io/cairo-image-surface-jpeg.c in GNOME gThumb before 3.8.3 and Linux Mint Pix before 2.4.5 allows attackers to cause a crash and potentially execute arbitrary code via a crafted JPEG file.
Fysac/CVE-2019-20326
CVE-2019-48814
wucj001/cve-2019-48814
CVE-2019-1002101 (2019-04-01)
The kubectl cp command allows copying files between containers and the user machine. To copy files from a container, Kubernetes creates a tar inside the container, copies it over the network, and kubectl unpacks it on the user’s machine. If the tar binary in the container is malicious, it could run any code and output unexpected, malicious results. An attacker could use this to write files to any path on the user’s machine when kubectl cp is called, limited only by the system permissions of the local user. The untar function can both create and follow symbolic links. The issue is resolved in kubectl v1.11.9, v1.12.7, v1.13.5, and v1.14.0.
brompwnie/CVE-2019-1002101-Helpers
CVE-2019-1003000 (2019-01-22)
A sandbox bypass vulnerability exists in Script Security Plugin 1.49 and earlier in src/main/java/org/jenkinsci/plugins/scriptsecurity/sandbox/groovy/GroovySandbox.java that allows attackers with the ability to provide sandboxed scripts to execute arbitrary code on the Jenkins master JVM.
wetw0rk/Exploit-Development
adamyordan/cve-2019-1003000-jenkins-rce-poc
0xtavian/CVE-2019-1003000-and-CVE-2018-1999002-Pre-Auth-RCE-Jenkins
1NTheKut/CVE-2019-1003000_RCE-DETECTION
CVE-2019-1010054 (2019-07-18)
Dolibarr 7.0.0 is affected by: Cross Site Request Forgery (CSRF). The impact is: allow malitious html to change user password, disable users and disable password encryptation. The component is: Function User password change, user disable and password encryptation. The attack vector is: admin access malitious urls.
chaizeg/CSRF-breach
CVE-2019-1010298 (2019-07-15)
Linaro/OP-TEE OP-TEE 3.3.0 and earlier is affected by: Buffer Overflow. The impact is: Code execution in the context of TEE core (kernel). The component is: optee_os. The fixed version is: 3.4.0 and later.
RKX1209/CVE-2019-1010298
2018
CVE-2018-0101 (2018-01-29)
A vulnerability in the Secure Sockets Layer (SSL) VPN functionality of the Cisco Adaptive Security Appliance (ASA) Software could allow an unauthenticated, remote attacker to cause a reload of the affected system or to remotely execute code. The vulnerability is due to an attempt to double free a region of memory when the webvpn feature is enabled on the Cisco ASA device. An attacker could exploit this vulnerability by sending multiple, crafted XML packets to a webvpn-configured interface on the affected system. An exploit could allow the attacker to execute arbitrary code and obtain full control of the system, or cause a reload of the affected device. This vulnerability affects Cisco ASA Software that is running on the following Cisco products: 3000 Series Industrial Security Appliance (ISA), ASA 5500 Series Adaptive Security Appliances, ASA 5500-X Series Next-Generation Firewalls, ASA Services Module for Cisco Catalyst 6500 Series Switches and Cisco 7600 Series Routers, ASA 1000V Cloud Firewall, Adaptive Security Virtual Appliance (ASAv), Firepower 2100 Series Security Appliance, Firepower 4110 Security Appliance, Firepower 9300 ASA Security Module, Firepower Threat Defense Software (FTD). Cisco Bug IDs: CSCvg35618.
1337g/CVE-2018-0101-DOS-POC
Cymmetria/ciscoasa_honeypot
CVE-2018-0114 (2018-01-04)
A vulnerability in the Cisco node-jose open source library before 0.11.0 could allow an unauthenticated, remote attacker to re-sign tokens using a key that is embedded within the token. The vulnerability is due to node-jose following the JSON Web Signature (JWS) standard for JSON Web Tokens (JWTs). This standard specifies that a JSON Web Key (JWK) representing a public key can be embedded within the header of a JWS. This public key is then trusted for verification. An attacker could exploit this by forging valid JWS objects by removing the original signature, adding a new public key to the header, and then signing the object using the (attacker-owned) private key associated with the public key embedded in that JWS header.
zi0Black/POC-CVE-2018-0114
Logeirs/CVE-2018-0114
adityathebe/POC-CVE-2018-0114
Eremiel/CVE-2018-0114
Starry-lord/CVE-2018-0114
CVE-2018-0202 (2018-03-27)
clamscan in ClamAV before 0.99.4 contains a vulnerability that could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. The vulnerability is due to improper input validation checking mechanisms when handling Portable Document Format (.pdf) files sent to an affected device. An unauthenticated, remote attacker could exploit this vulnerability by sending a crafted .pdf file to an affected device. This action could cause an out-of-bounds read when ClamAV scans the malicious file, allowing the attacker to cause a DoS condition. This concerns pdf_parse_array and pdf_parse_string in libclamav/pdfng.c. Cisco Bug IDs: CSCvh91380, CSCvh91400.
jaychowjingjie/CVE-2018-0202
CVE-2018-0208 (2018-03-08)
A vulnerability in the web-based management interface of the (cloud based) Cisco Registered Envelope Service could allow an authenticated, remote attacker to conduct a cross-site scripting (XSS) attack against a user of the web-based management interface of the affected service. The vulnerability is due to insufficient validation of user-supplied input that is processed by the web-based management interface of the affected service. An attacker could exploit this vulnerability by persuading a user of the interface to click a malicious link. A successful exploit could allow the attacker to execute arbitrary script code in the context of the interface or access sensitive browser-based information. Cisco Bug IDs: CSCvg74126.
dima5455/Cve-2018-0208
CVE-2018-0296 (2018-06-07)
A vulnerability in the web interface of the Cisco Adaptive Security Appliance (ASA) could allow an unauthenticated, remote attacker to cause an affected device to reload unexpectedly, resulting in a denial of service (DoS) condition. It is also possible on certain software releases that the ASA will not reload, but an attacker could view sensitive system information without authentication by using directory traversal techniques. The vulnerability is due to lack of proper input validation of the HTTP URL. An attacker could exploit this vulnerability by sending a crafted HTTP request to an affected device. An exploit could allow the attacker to cause a DoS condition or unauthenticated disclosure of information. This vulnerability applies to IPv4 and IPv6 HTTP traffic. This vulnerability affects Cisco ASA Software and Cisco Firepower Threat Defense (FTD) Software that is running on the following Cisco products: 3000 Series Industrial Security Appliance (ISA), ASA 1000V Cloud Firewall, ASA 5500 Series Adaptive Security Appliances, ASA 5500-X Series Next-Generation Firewalls, ASA Services Module for Cisco Catalyst 6500 Series Switches and Cisco 7600 Series Routers, Adaptive Security Virtual Appliance (ASAv), Firepower 2100 Series Security Appliance, Firepower 4100 Series Security Appliance, Firepower 9300 ASA Security Module, FTD Virtual (FTDv). Cisco Bug IDs: CSCvi16029.
milo2012/CVE-2018-0296
yassineaboukir/CVE-2018-0296
bhenner1/CVE-2018-0296
qiantu88/CVE-2018-0296
CVE-2018-0708 (2018-07-16)
Command injection vulnerability in networking of QNAP Q'center Virtual Appliance version 1.7.1063 and earlier could allow authenticated users to run arbitrary commands.
ntkernel0/CVE-2019-0708
CVE-2018-0802 (2018-01-09)
Equation Editor in Microsoft Office 2007, Microsoft Office 2010, Microsoft Office 2013, and Microsoft Office 2016 allow a remote code execution vulnerability due to the way objects are handled in memory, aka "Microsoft Office Memory Corruption Vulnerability". This CVE is unique from CVE-2018-0797 and CVE-2018-0812.
zldww2011/CVE-2018-0802_POC
rxwx/CVE-2018-0802
Ridter/RTF_11882_0802
likescam/CVE-2018-0802_CVE-2017-11882
dcsync/rtfkit
CVE-2018-0824 (2018-05-09)
A remote code execution vulnerability exists in "Microsoft COM for Windows" when it fails to properly handle serialized objects, aka "Microsoft COM for Windows Remote Code Execution Vulnerability." This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers.
codewhitesec/UnmarshalPwn
CVE-2018-0886 (2018-03-14)
The Credential Security Support Provider protocol (CredSSP) in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1 and RT 8.1, Windows Server 2012 and R2, Windows 10 Gold, 1511, 1607, 1703, and 1709 Windows Server 2016 and Windows Server, version 1709 allows a remote code execution vulnerability due to how CredSSP validates request during the authentication process, aka "CredSSP Remote Code Execution Vulnerability".
preempt/credssp
CVE-2018-0952 (2018-08-15)
An Elevation of Privilege vulnerability exists when Diagnostics Hub Standard Collector allows file creation in arbitrary locations, aka "Diagnostic Hub Standard Collector Elevation Of Privilege Vulnerability." This affects Windows Server 2016, Windows 10, Microsoft Visual Studio, Windows 10 Servers.
atredispartners/CVE-2018-0952-SystemCollector
CVE-2018-14
lckJack/legacySymfony
CVE-2018-1010 (2018-04-11)
A remote code execution vulnerability exists when the Windows font library improperly handles specially crafted embedded fonts, aka "Microsoft Graphics Remote Code Execution Vulnerability." This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers. This CVE ID is unique from CVE-2018-1012, CVE-2018-1013, CVE-2018-1015, CVE-2018-1016.
ymgh96/Detecting-the-patch-of-CVE-2018-1010
CVE-2018-1026 (2018-04-11)
A remote code execution vulnerability exists in Microsoft Office software when the software fails to properly handle objects in memory, aka "Microsoft Office Remote Code Execution Vulnerability." This affects Microsoft Office. This CVE ID is unique from CVE-2018-1030.
ymgh96/Detecting-the-CVE-2018-1026-and-its-patch
CVE-2018-1056 (2018-07-27)
An out-of-bounds heap buffer read flaw was found in the way advancecomp before 2.1-2018/02 handled processing of ZIP files. An attacker could potentially use this flaw to crash the advzip utility by tricking it into processing crafted ZIP files.
rotemkama/Gpon-Routers
CVE-2018-1088 (2018-04-18)
A privilege escalation flaw was found in gluster 3.x snapshot scheduler. Any gluster client allowed to mount gluster volumes could also mount shared gluster storage volume and escalate privileges by scheduling malicious cronjob via symlink.
MauroEldritch/GEVAUDAN
CVE-2018-1111 (2018-05-17)
DHCP packages in Red Hat Enterprise Linux 6 and 7, Fedora 28, and earlier are vulnerable to a command injection flaw in the NetworkManager integration script included in the DHCP client. A malicious DHCP server, or an attacker on the local network able to spoof DHCP responses, could use this flaw to execute arbitrary commands with root privileges on systems using NetworkManager and configured to obtain network configuration using the DHCP protocol.
knqyf263/CVE-2018-1111
kkirsche/CVE-2018-1111
baldassarreFe/FEP3370-advanced-ethical-hacking
CVE-2018-1133 (2018-05-25)
An issue was discovered in Moodle 3.x. A Teacher creating a Calculated question can intentionally cause remote code execution on the server, aka eval injection.
darrynten/MoodleExploit
M4LV0/MOODLE-3.X-Remote-Code-Execution
CVE-2018-1160 (2018-12-20)
Netatalk before 3.1.12 is vulnerable to an out of bounds write in dsi_opensess.c. This is due to lack of bounds checking on attacker controlled data. A remote unauthenticated attacker can leverage this vulnerability to achieve arbitrary code execution.
SachinThanushka/CVE-2018-1160
CVE-2018-1235 (2018-05-29)
Dell EMC RecoverPoint versions prior to 5.1.2 and RecoverPoint for VMs versions prior to 5.1.1.3, contain a command injection vulnerability. An unauthenticated remote attacker may potentially exploit this vulnerability to execute arbitrary commands on the affected system with root privilege.
AbsoZed/CVE-2018-1235
CVE-2018-1259 (2018-05-11)
Spring Data Commons, versions 1.13 prior to 1.13.12 and 2.0 prior to 2.0.7, used in combination with XMLBeam 1.4.14 or earlier versions, contains a property binder vulnerability caused by improper restriction of XML external entity references as underlying library XMLBeam does not restrict external reference expansion. An unauthenticated remote malicious user can supply specially crafted request parameters against Spring Data's projection-based request payload binding to access arbitrary files on the system.
tafamace/CVE-2018-1259
CVE-2018-1270 (2018-04-06)
Spring Framework, versions 5.0 prior to 5.0.5 and versions 4.3 prior to 4.3.15 and older unsupported versions, allow applications to expose STOMP over WebSocket endpoints with a simple, in-memory STOMP broker through the spring-messaging module. A malicious user (or attacker) can craft a message to the broker that can lead to a remote code execution attack.
CaledoniaProject/CVE-2018-1270
genxor/CVE-2018-1270_EXP
tafamace/CVE-2018-1270
Venscor/CVE-2018-1270
mprunet/owasp-formation-cve-2018-1270
CVE-2018-1273 (2018-04-11)
Spring Data Commons, versions prior to 1.13 to 1.13.10, 2.0 to 2.0.5, and older unsupported versions, contain a property binder vulnerability caused by improper neutralization of special elements. An unauthenticated remote malicious user (or attacker) can supply specially crafted request parameters against Spring Data REST backed HTTP resources or using Spring Data's projection-based request payload binding hat can lead to a remote code execution attack.
knqyf263/CVE-2018-1273
wearearima/poc-cve-2018-1273
webr0ck/poc-cve-2018-1273
cved-sources/cve-2018-1273
jas502n/cve-2018-1273
CVE-2018-1288 (2018-07-26)
In Apache Kafka 0.9.0.0 to 0.9.0.1, 0.10.0.0 to 0.10.2.1, 0.11.0.0 to 0.11.0.2, and 1.0.0, authenticated Kafka users may perform action reserved for the Broker via a manually created fetch request interfering with data replication, resulting in data loss.
joegallagher4/CVE-2018-1288-
CVE-2018-1297 (2018-02-13)
When using Distributed Test only (RMI based), Apache JMeter 2.x and 3.x uses an unsecured RMI connection. This could allow an attacker to get Access to JMeterEngine and send unauthorized code.
xDro1d/CVE-2018-1297
Al1ex/CVE-2018-1297
CVE-2018-1304 (2018-02-28)
The URL pattern of "" (the empty string) which exactly maps to the context root was not correctly handled in Apache Tomcat 9.0.0.M1 to 9.0.4, 8.5.0 to 8.5.27, 8.0.0.RC1 to 8.0.49 and 7.0.0 to 7.0.84 when used as part of a security constraint definition. This caused the constraint to be ignored. It was, therefore, possible for unauthorised users to gain access to web application resources that should have been protected. Only security constraints with a URL pattern of the empty string were affected.
knqyf263/CVE-2018-1304
thariyarox/tomcat_CVE-2018-1304_testing
CVE-2018-1305 (2018-02-23)
Security constraints defined by annotations of Servlets in Apache Tomcat 9.0.0.M1 to 9.0.4, 8.5.0 to 8.5.27, 8.0.0.RC1 to 8.0.49 and 7.0.0 to 7.0.84 were only applied once a Servlet had been loaded. Because security constraints defined in this way apply to the URL pattern and any URLs below that point, it was possible - depending on the order Servlets were loaded - for some security constraints not to be applied. This could have exposed resources to users who were not authorised to access them.
Pa55w0rd/CVE-2018-1305
CVE-2018-1306 (2018-06-27)
The PortletV3AnnotatedDemo Multipart Portlet war file code provided in Apache Pluto version 3.0.0 could allow a remote attacker to obtain sensitive information, caused by the failure to restrict path information provided during a file upload. An attacker could exploit this vulnerability to obtain configuration data and other sensitive information.
JJSO12/Apache-Pluto-3.0.0--CVE-2018-1306
CVE-2018-1313 (2018-05-07)
In Apache Derby 10.3.1.4 to 10.14.1.0, a specially-crafted network packet can be used to request the Derby Network Server to boot a database whose location and contents are under the user's control. If the Derby Network Server is not running with a Java Security Manager policy file, the attack is successful. If the server is using a policy file, the policy file must permit the database location to be read for the attack to work. The default Derby Network Server policy file distributed with the affected releases includes a permissive policy as the default Network Server policy, which allows the attack to work.
tafamace/CVE-2018-1313
CVE-2018-1324 (2018-03-16)
A specially crafted ZIP archive can be used to cause an infinite loop inside of Apache Commons Compress' extra field parser used by the ZipFile and ZipArchiveInputStream classes in versions 1.11 to 1.15. This can be used to mount a denial of service attack against services that use Compress' zip package.
tafamace/CVE-2018-1324
CVE-2018-1335 (2018-04-25)
From Apache Tika versions 1.7 to 1.17, clients could send carefully crafted headers to tika-server that could be used to inject commands into the command line of the server running tika-server. This vulnerability only affects those running tika-server on a server that is open to untrusted clients. The mitigation is to upgrade to Tika 1.18.
SkyBlueEternal/CVE-2018-1335-EXP-GUI
N0b1e6/CVE-2018-1335-Python3
canumay/cve-2018-1335
CVE-2018-2019 (2019-01-18)
IBM Security Identity Manager 6.0.0 Virtual Appliance is vulnerable to a XML External Entity Injection (XXE) attack when processing XML data. A remote attacker could exploit this vulnerability to expose sensitive information or consume memory resources. IBM X-Force ID: 155265.
attakercyebr/hack4lx_CVE-2018-2019
CVE-2018-2380 (2018-03-01)
SAP CRM, 7.01, 7.02,7.30, 7.31, 7.33, 7.54, allows an attacker to exploit insufficient validation of path information provided by users, thus characters representing "traverse to parent directory" are passed through to the file APIs.
erpscanteam/CVE-2018-2380
CVE-2018-2392 (2018-02-14)
Under certain conditions SAP Internet Graphics Server (IGS) 7.20, 7.20EXT, 7.45, 7.49, 7.53, fails to validate XML External Entity appropriately causing the SAP Internet Graphics Server (IGS) to become unavailable.
Vladimir-Ivanov-Git/sap_igs_xxe
CVE-2018-2628 (2018-04-18)
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
forlin/CVE-2018-2628
shengqi158/CVE-2018-2628
skydarker/CVE-2018-2628
jiansiting/weblogic-cve-2018-2628
zjxzjx/CVE-2018-2628-detect
aedoo/CVE-2018-2628-MultiThreading
hawk-520/CVE-2018-2628
9uest/CVE-2018-2628
Shadowshusky/CVE-2018-2628all
shaoshore/CVE-2018-2628
tdy218/ysoserial-cve-2018-2628
s0wr0b1ndef/CVE-2018-2628
wrysunny/cve-2018-2628
jas502n/CVE-2018-2628
stevenlinfeng/CVE-2018-2628
likescam/CVE-2018-2628
Nervous/WebLogic-RCE-exploit
Lighird/CVE-2018-2628
0xMJ/CVE-2018-2628
0xn0ne/weblogicScanner
seethen/cve-2018-2628
CVE-2018-2636 (2018-01-17)
Vulnerability in the Oracle Hospitality Simphony component of Oracle Hospitality Applications (subcomponent: Security). Supported versions that are affected are 2.7, 2.8 and 2.9. Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Hospitality Simphony. Successful attacks of this vulnerability can result in takeover of Oracle Hospitality Simphony. CVSS 3.0 Base Score 8.1 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).
erpscanteam/CVE-2018-2636
Cymmetria/micros_honeypot
CVE-2018-2844 (2018-04-18)
Vulnerability in the Oracle VM VirtualBox component of Oracle Virtualization (subcomponent: Core). Supported versions that are affected are Prior to 5.1.36 and Prior to 5.2.10. Easily exploitable vulnerability allows low privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Oracle VM VirtualBox. CVSS 3.0 Base Score 8.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H).
renorobert/virtualbox-cve-2018-2844
CVE-2018-2879 (2018-04-18)
Vulnerability in the Oracle Access Manager component of Oracle Fusion Middleware (subcomponent: Authentication Engine). Supported versions that are affected are 11.1.2.3.0 and 12.2.1.3.0. Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Access Manager. While the vulnerability is in Oracle Access Manager, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Oracle Access Manager. Note: Please refer to Doc ID <a href="http://support.oracle.com/CSP/main/article?cmd=show&type=NOT&id=2386496.1">My Oracle Support Note 2386496.1 for instructions on how to address this issue. CVSS 3.0 Base Score 9.0 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H).
MostafaSoliman/Oracle-OAM-Padding-Oracle-CVE-2018-2879-Exploit
AymanElSherif/oracle-oam-authentication-bypas-exploit
redtimmy/OAMBuster
CVE-2018-2893 (2018-07-18)
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
sry309/CVE-2018-2893
ryanInf/CVE-2018-2893
bigsizeme/CVE-2018-2893
pyn3rd/CVE-2018-2893
qianl0ng/CVE-2018-2893
jas502n/CVE-2018-2893
ianxtianxt/CVE-2018-2893
CVE-2018-2894 (2018-07-18)
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS - Web Services). Supported versions that are affected are 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
111ddea/cve-2018-2894
LandGrey/CVE-2018-2894
jas502n/CVE-2018-2894
k8gege/PyLadon
changpin666com/CVE-2018-2894-Weblogic-
CVE-2018-3191 (2018-10-16)
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
arongmh/CVE-2018-3191
pyn3rd/CVE-2018-3191
Libraggbond/CVE-2018-3191
jas502n/CVE-2018-3191
mackleadmire/CVE-2018-3191-Rce-Exploit
CVE-2018-3245 (2018-10-16)
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
pyn3rd/CVE-2018-3245
jas502n/CVE-2018-3245
ianxtianxt/CVE-2018-3245
CVE-2018-3252 (2018-10-16)
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
jas502n/CVE-2018-3252
b1ueb0y/CVE-2018-3252
pyn3rd/CVE-2018-3252
CVE-2018-3260
ionescu007/SpecuCheck
CVE-2018-3295 (2018-10-16)
Vulnerability in the Oracle VM VirtualBox component of Oracle Virtualization (subcomponent: Core). The supported version that is affected is Prior to 5.2.20. Easily exploitable vulnerability allows unauthenticated attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Oracle VM VirtualBox. CVSS 3.0 Base Score 8.6 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H).
ndureiss/e1000_vulnerability_exploit
CVE-2018-3608 (2018-07-06)
A vulnerability in Trend Micro Maximum Security's (Consumer) 2018 (versions 12.0.1191 and below) User-Mode Hooking (UMH) driver could allow an attacker to create a specially crafted packet that could alter a vulnerable system in such a way that malicious code could be injected into other processes.
ZhiyuanWang-Chengdu-Qihoo360/Trend_Micro_POC
CVE-2018-3639 (2018-05-22)
Systems with microprocessors utilizing speculative execution and speculative execution of memory reads before the addresses of all prior memory writes are known may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis, aka Speculative Store Bypass (SSB), Variant 4.
tyhicks/ssbd-tools
malindarathnayake/Intel-CVE-2018-3639-Mitigation_RegistryUpdate
mmxsrup/CVE-2018-3639
Shuiliusheng/CVE-2018-3639-specter-v4-
CVE-2018-3760 (2018-06-26)
There is an information leak vulnerability in Sprockets. Versions Affected: 4.0.0.beta7 and lower, 3.7.1 and lower, 2.12.4 and lower. Specially crafted requests can be used to access files that exists on the filesystem that is outside an application's root directory, when the Sprockets server is used in production. All users running an affected release should either upgrade or use one of the work arounds immediately.
mpgn/CVE-2018-3760
cyberharsh/Ruby-On-Rails-Path-Traversal-Vulnerability-CVE-2018-3760-
CVE-2018-3783 (2018-08-17)
A privilege escalation detected in flintcms versions <= 1.1.9 allows account takeover due to blind MongoDB injection in password reset.
nisaruj/nosqli-flintcms
CVE-2018-3786 (2018-08-24)
A command injection vulnerability in egg-scripts <v2.8.1 allows arbitrary shell command execution through a maliciously crafted command line argument.
erik-krogh/egg-scripts-CVE-2018-3786
CVE-2018-3810 (2018-01-01)
Authentication Bypass vulnerability in the Oturia Smart Google Code Inserter plugin before 3.5 for WordPress allows unauthenticated attackers to insert arbitrary JavaScript or HTML code (via the sgcgoogleanalytic parameter) that runs on all pages served by WordPress. The saveGoogleCode() function in smartgooglecode.php does not check if the current request is made by an authorized user, thus allowing any unauthenticated user to successfully update the inserted code.
lucad93/CVE-2018-3810
cved-sources/cve-2018-3810
CVE-2018-3811 (2018-01-01)
SQL Injection vulnerability in the Oturia Smart Google Code Inserter plugin before 3.5 for WordPress allows unauthenticated attackers to execute SQL queries in the context of the web server. The saveGoogleAdWords() function in smartgooglecode.php did not use prepared statements and did not sanitize the $_POST["oId"] variable before passing it as input into the SQL query.
cved-sources/cve-2018-3811
CVE-2018-4013 (2018-10-19)
An exploitable code execution vulnerability exists in the HTTP packet-parsing functionality of the LIVE555 RTSP server library version 0.92. A specially crafted packet can cause a stack-based buffer overflow, resulting in code execution. An attacker can send a packet to trigger this vulnerability.
DoubleMice/cve-2018-4013
r3dxpl0it/RTSPServer-Code-Execution-Vulnerability
CVE-2018-4087 (2018-04-03)
An issue was discovered in certain Apple products. iOS before 11.2.5 is affected. tvOS before 11.2.5 is affected. watchOS before 4.2.2 is affected. The issue involves the "Core Bluetooth" component. It allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app.
rani-i/bluetoothdPoC
MTJailed/UnjailMe
joedaguy/Exploit11.2
CVE-2018-4110 (2018-04-03)
An issue was discovered in certain Apple products. iOS before 11.3 is affected. The issue involves the "Web App" component. It allows remote attackers to bypass intended restrictions on cookie persistence.
bencompton/ios11-cookie-set-expire-issue
CVE-2018-4121 (2018-04-03)
An issue was discovered in certain Apple products. iOS before 11.3 is affected. Safari before 11.1 is affected. iCloud before 7.4 on Windows is affected. iTunes before 12.7.4 on Windows is affected. tvOS before 11.3 is affected. watchOS before 4.3 is affected. The issue involves the "WebKit" component. It allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted web site.
FSecureLABS/CVE-2018-4121
likescam/CVE-2018-4121
jezzus/CVE-2018-4121
CVE-2018-4124 (2018-04-03)
An issue was discovered in certain Apple products. iOS before 11.2.6 is affected. macOS before 10.13.3 Supplemental Update is affected. tvOS before 11.2.6 is affected. watchOS before 4.2.3 is affected. The issue involves the "CoreText" component. It allows remote attackers to cause a denial of service (memory corruption and system crash) or possibly have unspecified other impact via a crafted string containing a certain Telugu character.
ZecOps/TELUGU_CVE-2018-4124_POC
CVE-2018-4150 (2018-04-03)
An issue was discovered in certain Apple products. iOS before 11.3 is affected. macOS before 10.13.4 is affected. tvOS before 11.3 is affected. watchOS before 4.3 is affected. The issue involves the "Kernel" component. It allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app.
Jailbreaks/CVE-2018-4150
RPwnage/LovelySn0w
littlelailo/incomplete-exploit-for-CVE-2018-4150-bpf-filter-poc-
CVE-2018-4185 (2019-01-11)
In iOS before 11.3, tvOS before 11.3, watchOS before 4.3, and macOS before High Sierra 10.13.4, an information disclosure issue existed in the transition of program state. This issue was addressed with improved state handling.
bazad/x18-leak
CVE-2018-4193 (2018-06-08)
An issue was discovered in certain Apple products. macOS before 10.13.5 is affected. The issue involves the "Windows Server" component. It allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app.
Synacktiv-contrib/CVE-2018-4193
CVE-2018-4233 (2018-06-08)
An issue was discovered in certain Apple products. iOS before 11.4 is affected. Safari before 11.1.1 is affected. iCloud before 7.5 on Windows is affected. iTunes before 12.7.5 on Windows is affected. tvOS before 11.4 is affected. watchOS before 4.3.1 is affected. The issue involves the "WebKit" component. It allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted web site.
saelo/cve-2018-4233
CVE-2018-4241 (2018-06-08)
An issue was discovered in certain Apple products. iOS before 11.4 is affected. macOS before 10.13.5 is affected. tvOS before 11.4 is affected. watchOS before 4.3.1 is affected. The issue involves the "Kernel" component. A buffer overflow in mptcp_usr_connectx allows attackers to execute arbitrary code in a privileged context via a crafted app.
0neday/multi_path
CVE-2018-4242 (2018-06-08)
An issue was discovered in certain Apple products. macOS before 10.13.5 is affected. The issue involves the "Hypervisor" component. It allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app.
yeonnic/Look-at-The-XNU-Through-A-Tube-CVE-2018-4242-Write-up-Translation-
CVE-2018-4243 (2018-06-08)
An issue was discovered in certain Apple products. iOS before 11.4 is affected. macOS before 10.13.5 is affected. tvOS before 11.4 is affected. watchOS before 4.3.1 is affected. The issue involves the "Kernel" component. A buffer overflow in getvolattrlist allows attackers to execute arbitrary code in a privileged context via a crafted app.
Jailbreaks/empty_list
CVE-2018-4248 (2019-04-03)
An out-of-bounds read was addressed with improved input validation. This issue affected versions prior to iOS 11.4.1, macOS High Sierra 10.13.6, tvOS 11.4.1, watchOS 4.3.2.
bazad/xpc-string-leak
CVE-2018-4280 (2019-04-03)
A memory corruption issue was addressed with improved memory handling. This issue affected versions prior to iOS 11.4.1, macOS High Sierra 10.13.6, tvOS 11.4.1, watchOS 4.3.2.
bazad/launchd-portrep
bazad/blanket
CVE-2018-4327 (2019-04-03)
A memory corruption issue was addressed with improved memory handling. This issue affected versions prior to iOS 11.4.1.
omerporze/brokentooth
harryanon/POC-CVE-2018-4327-and-CVE-2018-4330
CVE-2018-4330 (2019-01-11)
In iOS before 11.4, a memory corruption issue exists and was addressed with improved memory handling.
omerporze/toothfairy
CVE-2018-4331 (2019-04-03)
A memory corruption issue was addressed with improved memory handling. This issue affected versions prior to iOS 12, macOS Mojave 10.14, tvOS 12, watchOS 5.
bazad/gsscred-race
CVE-2018-4343 (2019-04-03)
A memory corruption issue was addressed with improved memory handling. This issue affected versions prior to iOS 12, macOS Mojave 10.14, tvOS 12, watchOS 5.
bazad/gsscred-move-uaf
CVE-2018-4407 (2019-04-03)
A memory corruption issue was addressed with improved validation. This issue affected versions prior to iOS 12, macOS Mojave 10.14, tvOS 12, watchOS 5.
Pa55w0rd/check_icmp_dos
unixpickle/cve-2018-4407
s2339956/check_icmp_dos-CVE-2018-4407-
farisv/AppleDOS
WyAtu/CVE-2018-4407
zteeed/CVE-2018-4407-IOS
SamDecrock/node-cve-2018-4407
r3dxpl0it/CVE-2018-4407
lucagiovagnoli/CVE-2018-4407
anonymouz4/Apple-Remote-Crash-Tool-CVE-2018-4407
soccercab/wifi
zeng9t/CVE-2018-4407-iOS-exploit
5431/CVE-2018-4407
pwnhacker0x18/iOS-Kernel-Crash
Fans0n-Fan/CVE-2018-4407
CVE-2018-4411 (2019-04-03)
A memory corruption issue was addressed with improved input validation. This issue affected versions prior to macOS Mojave 10.14.
lilang-wu/POC-CVE-2018-4411
CVE-2018-4415 (2019-04-03)
A memory corruption issue was addressed with improved memory handling. This issue affected versions prior to macOS Mojave 10.14.1.
T1V0h/CVE-2018-4415
CVE-2018-4431 (2019-04-03)
A memory initialization issue was addressed with improved memory handling. This issue affected versions prior to iOS 12.1.1, macOS Mojave 10.14.2, tvOS 12.1.1, watchOS 5.1.2.
ktiOSz/PoC_iOS12
CVE-2018-4441 (2019-04-03)
A memory corruption issue was addressed with improved memory handling. This issue affected versions prior to iOS 12.1.1, tvOS 12.1.1, watchOS 5.1.2, Safari 12.0.2, iTunes 12.9.2 for Windows, iCloud for Windows 7.9.
Cryptogenic/PS4-6.20-WebKit-Code-Execution-Exploit
CVE-2018-4878 (2018-02-06)
A use-after-free vulnerability was discovered in Adobe Flash Player before 28.0.0.161. This vulnerability occurs due to a dangling pointer in the Primetime SDK related to media player handling of listener objects. A successful attack can lead to arbitrary code execution. This was exploited in the wild in January and February 2018.
ydl555/CVE-2018-4878-
mdsecactivebreach/CVE-2018-4878
hybridious/CVE-2018-4878
vysecurity/CVE-2018-4878
KathodeN/CVE-2018-4878
SyFi/CVE-2018-4878
ydl555/CVE-2018-4878
B0fH/CVE-2018-4878
Yable/CVE-2018-4878
HuanWoWeiLan/SoftwareSystemSecurity-2019
CVE-2018-4879 (2018-02-27)
An issue was discovered in Adobe Acrobat Reader 2018.009.20050 and earlier versions, 2017.011.30070 and earlier versions, 2015.006.30394 and earlier versions. The vulnerability is caused by the computation that writes data past the end of the intended buffer; the computation is part of the image conversion module that processes Enhanced Metafile Format Plus (EMF+) data. An attacker can potentially leverage the vulnerability to corrupt sensitive data or execute arbitrary code.
H3llozy/CVE-2018-4879
CVE-2018-4901 (2018-02-27)
An issue was discovered in Adobe Acrobat Reader 2018.009.20050 and earlier versions, 2017.011.30070 and earlier versions, 2015.006.30394 and earlier versions. The vulnerability is caused by the computation that writes data past the end of the intended buffer; the computation is part of the document identity representation. An attacker can potentially leverage the vulnerability to corrupt sensitive data or execute arbitrary code.
bigric3/CVE-2018-4901
CVE-2018-5234 (2018-04-30)
The Norton Core router prior to v237 may be susceptible to a command injection exploit. This is a type of attack in which the goal is execution of arbitrary commands on the host system via vulnerable software.
embedi/ble_norton_core
CVE-2018-5353 (2020-09-29)
The custom GINA/CP module in Zoho ManageEngine ADSelfService Plus before 5.5 build 5517 allows remote attackers to execute code and escalate privileges via spoofing. It does not authenticate the intended server before opening a browser window. An unauthenticated attacker capable of conducting a spoofing attack can redirect the browser to gain execution in the context of the WinLogon.exe process. If Network Level Authentication is not enforced, the vulnerability can be exploited via RDP. Additionally, if the web server has a misconfigured certificate then no spoofing attack is required
missing0x00/CVE-2018-5353
CVE-2018-5354 (2020-09-29)
The custom GINA/CP module in ANIXIS Password Reset Client before version 3.22 allows remote attackers to execute code and escalate privileges via spoofing. When the client is configured to use HTTP, it does not authenticate the intended server before opening a browser window. An unauthenticated attacker capable of conducting a spoofing attack can redirect the browser to gain execution in the context of the WinLogon.exe process. If Network Level Authentication is not enforced, the vulnerability can be exploited via RDP.
missing0x00/CVE-2018-5354
CVE-2018-5711 (2018-01-16)
gd_gif_in.c in the GD Graphics Library (aka libgd), as used in PHP before 5.6.33, 7.0.x before 7.0.27, 7.1.x before 7.1.13, and 7.2.x before 7.2.1, has an integer signedness error that leads to an infinite loop via a crafted GIF file, as demonstrated by a call to the imagecreatefromgif or imagecreatefromstring PHP function. This is related to GetCode_ and gdImageCreateFromGifCtx.
huzhenghui/Test-7-2-0-PHP-CVE-2018-5711
huzhenghui/Test-7-2-1-PHP-CVE-2018-5711
CVE-2018-5724 (2018-01-16)
MASTER IPCAMERA01 3.3.4.2103 devices allow Unauthenticated Configuration Download and Upload, as demonstrated by restore.cgi.
gusrmsdlrh/Python-CVE-Code
CVE-2018-5728 (2018-01-16)
Cobham Sea Tel 121 build 222701 devices allow remote attackers to obtain potentially sensitive information via a /cgi-bin/getSysStatus request, as demonstrated by the Latitude/Longitude of the ship, or satellite details.
ezelf/seatel_terminals
CVE-2018-5740 (2019-01-16)
"deny-answer-aliases" is a little-used feature intended to help recursive server operators protect end users against DNS rebinding attacks, a potential method of circumventing the security model used by client browsers. However, a defect in this feature makes it easy, when the feature is in use, to experience an assertion failure in name.c. Affects BIND 9.7.0->9.8.8, 9.9.0->9.9.13, 9.10.0->9.10.8, 9.11.0->9.11.4, 9.12.0->9.12.2, 9.13.0->9.13.2.
sischkg/cve-2018-5740
CVE-2018-5951 (2020-03-02)
An issue was discovered in Mikrotik RouterOS. Crafting a packet that has a size of 1 byte and sending it to an IPv6 address of a RouterOS box with IP Protocol 97 will cause RouterOS to reboot imminently. All versions of RouterOS that supports EoIPv6 are vulnerable to this attack.
Nat-Lab/CVE-2018-5951
CVE-2018-5955 (2018-01-21)
An issue was discovered in GitStack through 2.3.10. User controlled input is not sufficiently filtered, allowing an unauthenticated attacker to add a user to the server via the username and password fields to the rest/user/ URI.
cisp/GitStackRCE
YagamiiLight/Cerberus
CVE-2018-6242 (2018-05-01)
Some NVIDIA Tegra mobile processors released prior to 2016 contain a buffer overflow vulnerability in BootROM Recovery Mode (RCM). An attacker with physical access to the device's USB and the ability to force the device to reboot into RCM could exploit the vulnerability to execute unverified code.
DavidBuchanan314/NXLoader
reswitched/rcm-modchips
switchjs/fusho
ChrisFigura/react-tegra-payload-launcher
austinhartzheim/fusee-gelee
CVE-2018-6376 (2018-01-30)
In Joomla! before 3.8.4, the lack of type casting of a variable in a SQL statement leads to a SQL injection vulnerability in the Hathor postinstall message.
knqyf263/CVE-2018-6376
CVE-2018-6389 (2018-02-06)
In WordPress through 4.9.2, unauthenticated attackers can cause a denial of service (resource consumption) by using the large list of registered .js files (from wp-includes/script-loader.php) to construct a series of requests to load every file many times.
yolabingo/wordpress-fix-cve-2018-6389
WazeHell/CVE-2018-6389
rastating/modsecurity-cve-2018-6389
knqyf263/CVE-2018-6389
JulienGadanho/cve-2018-6389-php-patcher
dsfau/wordpress-CVE-2018-6389
Jetserver/CVE-2018-6389-FIX
thechrono13/PoC---CVE-2018-6389
BlackRouter/cve-2018-6389
alessiogilardi/PoC---CVE-2018-6389
JavierOlmedo/wordpress-cve-2018-6389
m3ssap0/wordpress_cve-2018-6389
s0md3v/Shiva
mudhappy/Wordpress-Hack-CVE-2018-6389
armaanpathan12345/WP-DOS-Exploit-CVE-2018-6389
ItinerisLtd/trellis-cve-2018-6389
Zazzzles/Wordpress-DOS
fakedob/tvsz
heisenberg-official/Wordpress-DOS-Attack-CVE-2018-6389
ianxtianxt/CVE-2018-6389
Elsfa7-110/CVE-2018-6389
CVE-2018-6396 (2018-02-17)
SQL Injection exists in the Google Map Landkarten through 4.2.3 component for Joomla! via the cid or id parameter in a layout=form_markers action, or the map parameter in a layout=default action.
JavierOlmedo/joomla-cve-2018-6396
CVE-2018-6407 (2018-01-30)
An issue was discovered on Conceptronic CIPCAMPTIWL V3 0.61.30.21 devices. An unauthenticated attacker can crash a device by sending a POST request with a huge body size to /hy-cgi/devices.cgi?cmd=searchlandevice. The crash completely freezes the device.
dreadlocked/ConceptronicIPCam_MultipleVulnerabilities
CVE-2018-6479 (2018-01-31)
An issue was discovered on Netwave IP Camera devices. An unauthenticated attacker can crash a device by sending a POST request with a huge body size to the / URI.
dreadlocked/netwave-dosvulnerability
CVE-2018-6518 (2018-04-26)
Composr CMS 10.0.13 has XSS via the site_name parameter in a page=admin-setupwizard&type=step3 request to /adminzone/index.php.
faizzaidi/Composr-CMS-10.0.13-Cross-Site-Scripting-XSS
CVE-2018-6546 (2018-04-13)
plays_service.exe in the plays.tv service before 1.27.7.0, as distributed in AMD driver-installation packages and Gaming Evolved products, executes code at a user-defined (local or SMB) path as SYSTEM when the execute_installer parameter is used in an HTTP message. This occurs without properly authenticating the user.
securifera/CVE-2018-6546-Exploit
YanZiShuang/CVE-2018-6546
CVE-2018-6574 (2018-02-07)
Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow "go get" remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.
acole76/cve-2018-6574
neargle/CVE-2018-6574-POC
willbo4r/go-get-rce
ahmetmanga/go-get-rce
ahmetmanga/cve-2018-6574
kenprice/cve-2018-6574
redirected/cve-2018-6574
20matan/CVE-2018-6574-POC
zur250/Zur-Go-GET-RCE-Solution
mekhalleh/cve-2018-6574
veter069/go-get-rce
duckzsc2/CVE-2018-6574-POC
ivnnn1/CVE-2018-6574
dollyptm/cve-2018-6574
qweraqq/CVE-2018-6574
d4rkshell/go-get-rce
chaosura/CVE-2018-6574
french560/ptl6574
InfoSecJack/CVE-2018-6574
asavior2/CVE-2018-6574
drset/golang
frozenkp/CVE-2018-6574
kev-ho/cve-2018-6574-payload
sdosis/cve-2018-6574
No1zy/CVE-2018-6574-PoC
nthuong95/CVE-2018-6574
AdriVillaB/CVE-2018-6574
yitingfan/CVE-2018-6574_demo
mhamed366/CVE-2018-6574
Eugene24/CVE-2018-6574
coblax/CVE-2018-6574
darthvader-htb/CVE-2018-6574
it3x55/CVE-2018-6574
Malone5923/CVE-2018-6574-go-get-RCE
shivam18u/CVE-2018-6574
illnino/CVE-2018-6574
TakuCoder/CVE-2018-6574
kawkab101/cve-2018-6574
lsnakazone/cve-2018-6574
pswalia2u/CVE-2018-6574
jongmartinez/CVE-2018-6574-POC
Yashrk078/Test_CVE-2018-6574
azzzzzzzzzzzzzzzzz/CVE-2018-6574
FilipeFraqueiro/CVE-2018-6574
shadofren/CVE-2018-6574
NikolaT3sla/cve-2018-6574
vishack/CVE-2018-6574
PLP-Orange/cve-2018-6574-exercise
purgedemo/CVE-2018-6574
purgedemo/CVE-2018-6574_2
CVE-2018-6622 (2018-08-17)
An issue was discovered that affects all producers of BIOS firmware who make a certain realistic interpretation of an obscure portion of the Trusted Computing Group (TCG) Trusted Platform Module (TPM) 2.0 specification. An abnormal case is not handled properly by this firmware while S3 sleep and can clear TPM 2.0. It allows local users to overwrite static PCRs of TPM and neutralize the security features of it, such as seal/unseal and remote attestation.
kkamagui/napper-for-tpm
CVE-2018-6643 (2018-08-28)
Infoblox NetMRI 7.1.1 has Reflected Cross-Site Scripting via the /api/docs/index.php query parameter.
undefinedmode/CVE-2018-6643
CVE-2018-6789 (2018-02-08)
An issue was discovered in the base64d function in the SMTP listener in Exim before 4.90.1. By sending a handcrafted message, a buffer overflow may happen. This can be used to execute code remotely.
c0llision/exim-vuln-poc
beraphin/CVE-2018-6789
synacktiv/Exim-CVE-2018-6789
martinclauss/exim-rce-cve-2018-6789
CVE-2018-6791 (2018-02-06)
An issue was discovered in soliduiserver/deviceserviceaction.cpp in KDE Plasma Workspace before 5.12.0. When a vfat thumbdrive that contains `` or $() in its volume label is plugged in and mounted through the device notifier, it's interpreted as a shell command, leading to a possibility of arbitrary command execution. An example of an offending volume label is "$(touch b)" -- this will create a file called b in the home folder.
rarar0/KDE_Vuln
CVE-2018-6890 (2018-02-22)
Cross-site scripting (XSS) vulnerability in Wolf CMS 0.8.3.1 via the page editing feature, as demonstrated by /?/admin/page/edit/3.
pradeepjairamani/WolfCMS-XSS-POC
CVE-2018-6892 (2018-02-11)
An issue was discovered in CloudMe before 1.11.0. An unauthenticated remote attacker that can connect to the "CloudMe Sync" client application listening on port 8888 can send a malicious payload causing a buffer overflow condition. This will result in an attacker controlling the program's execution flow and allowing arbitrary code execution.
manojcode/CloudMe-Sync-1.10.9---Buffer-Overflow-SEH-DEP-Bypass
manojcode/-Win10-x64-CloudMe-Sync-1.10.9-Buffer-Overflow-SEH-DEP-Bypass
latortuga71/CVE-2018-6892-Golang
CVE-2018-6905 (2018-04-08)
The page module in TYPO3 before 8.7.11, and 9.1.0, has XSS via $GLOBALS['TYPO3_CONF_VARS']['SYS']['sitename'], as demonstrated by an admin entering a crafted site name during the installation process.
pradeepjairamani/TYPO3-XSS-POC
CVE-2018-6961 (2018-06-11)
VMware NSX SD-WAN Edge by VeloCloud prior to version 3.1.0 contains a command injection vulnerability in the local web UI component. This component is disabled by default and should not be enabled on untrusted networks. VeloCloud by VMware will be removing this service from the product in future releases. Successful exploitation of this issue could result in remote code execution.
bokanrb/CVE-2018-6961
r3dxpl0it/CVE-2018-6961
CVE-2018-6981 (2018-12-04)
VMware ESXi 6.7 without ESXi670-201811401-BG and VMware ESXi 6.5 without ESXi650-201811301-BG, VMware ESXi 6.0 without ESXi600-201811401-BG, VMware Workstation 15, VMware Workstation 14.1.3 or below, VMware Fusion 11, VMware Fusion 10.1.3 or below contain uninitialized stack memory usage in the vmxnet3 virtual network adapter which may allow a guest to execute code on the host.
heaphopopotamus/vmxnet3Hunter
CVE-2018-7171 (2018-03-30)
Directory traversal vulnerability in Twonky Server 7.0.11 through 8.5 allows remote attackers to share the contents of arbitrary directories via a .. (dot dot) in the contentbase parameter to rpc/set_all.
mechanico/sharingIsCaring
CVE-2018-7197 (2018-02-17)
An issue was discovered in Pluck through 4.7.4. A stored cross-site scripting (XSS) vulnerability allows remote unauthenticated users to inject arbitrary web script or HTML into admin/blog Reaction Comments via a crafted URL.
Alyssa-o-Herrera/CVE-2018-7197
CVE-2018-7211 (2018-02-17)
An issue was discovered in iDashboards 9.6b. The SSO implementation is affected by a weak obfuscation library, allowing man-in-the-middle attackers to discover credentials.
c3r34lk1ll3r/CVE-2018-7211-PoC
CVE-2018-7249 (2018-02-26)
An issue was discovered in secdrv.sys as shipped in Microsoft Windows Vista, Windows 7, Windows 8, and Windows 8.1 before KB3086255, and as shipped in Macrovision SafeDisc. Two carefully timed calls to IOCTL 0xCA002813 can cause a race condition that leads to a use-after-free. When exploited, an unprivileged attacker can run arbitrary code in the kernel.
Elvin9/NotSecDrv
CVE-2018-7250 (2018-02-26)
An issue was discovered in secdrv.sys as shipped in Microsoft Windows Vista, Windows 7, Windows 8, and Windows 8.1 before KB3086255, and as shipped in Macrovision SafeDisc. An uninitialized kernel pool allocation in IOCTL 0xCA002813 allows a local unprivileged attacker to leak 16 bits of uninitialized kernel PagedPool data.
Elvin9/SecDrvPoolLeak
CVE-2018-7284 (2018-02-21)
A Buffer Overflow issue was discovered in Asterisk through 13.19.1, 14.x through 14.7.5, and 15.x through 15.2.1, and Certified Asterisk through 13.18-cert2. When processing a SUBSCRIBE request, the res_pjsip_pubsub module stores the accepted formats present in the Accept headers of the request. This code did not limit the number of headers it processed, despite having a fixed limit of 32. If more than 32 Accept headers were present, the code would write outside of its memory and cause a crash.
Rodrigo-D/astDoS
CVE-2018-7422 (2018-03-19)
A Local File Inclusion vulnerability in the Site Editor plugin through 1.1.1 for WordPress allows remote attackers to retrieve arbitrary files via the ajax_path parameter to editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php, aka absolute path traversal.
0x00-0x00/CVE-2018-7422
CVE-2018-7489 (2018-02-26)
FasterXML jackson-databind before 2.7.9.3, 2.8.x before 2.8.11.1 and 2.9.x before 2.9.5 allows unauthenticated remote code execution because of an incomplete fix for the CVE-2017-7525 deserialization flaw. This is exploitable by sending maliciously crafted JSON input to the readValue method of the ObjectMapper, bypassing a blacklist that is ineffective if the c3p0 libraries are available in the classpath.
tafamace/CVE-2018-7489
CVE-2018-7600 (2018-03-29)
Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.
g0rx/CVE-2018-7600-Drupal-RCE
a2u/CVE-2018-7600
dreadlocked/Drupalgeddon2
knqyf263/CVE-2018-7600
dr-iman/CVE-2018-7600-Drupal-0day-RCE
jirojo2/drupalgeddon2
dwisiswant0/CVE-2018-7600
thehappydinoa/CVE-2018-7600
sl4cky/CVE-2018-7600
sl4cky/CVE-2018-7600-Masschecker
FireFart/CVE-2018-7600
pimps/CVE-2018-7600
lorddemon/drupalgeddon2
Hestat/drupal-check
fyraiga/CVE-2018-7600-drupalgeddon2-scanner
Damian972/drupalgeddon-2
Jyozi/CVE-2018-7600
happynote3966/CVE-2018-7600
shellord/CVE-2018-7600-Drupal-RCE
r3dxpl0it/CVE-2018-7600
cved-sources/cve-2018-7600
madneal/drupalgeddon2
drugeddon/drupal-exploit
shellord/Drupalgeddon-Mass-Exploiter
zhzyker/CVE-2018-7600-Drupal-POC-EXP
rabbitmask/CVE-2018-7600-Drupal7
ynsmroztas/drupalhunter
ruthvikvegunta/Drupalgeddon2
ludy-dev/drupal8-REST-RCE
CVE-2018-7602 (2018-07-19)
A remote code execution vulnerability exists within multiple subsystems of Drupal 7.x and 8.x. This potentially allows attackers to exploit multiple attack vectors on a Drupal site, which could result in the site being compromised. This vulnerability is related to Drupal core - Highly critical - Remote Code Execution - SA-CORE-2018-002. Both SA-CORE-2018-002 and this vulnerability are being exploited in the wild.
1337g/Drupalgedon3
happynote3966/CVE-2018-7602
kastellanos/CVE-2018-7602
cyberharsh/DrupalCVE-2018-7602
CVE-2018-7690 (2018-12-13)
A potential Remote Unauthorized Access in Micro Focus Fortify Software Security Center (SSC), versions 17.10, 17.20, 18.10 this exploitation could allow Remote Unauthorized Access
alt3kx/CVE-2018-7690
CVE-2018-7691 (2018-12-13)
A potential Remote Unauthorized Access in Micro Focus Fortify Software Security Center (SSC), versions 17.10, 17.20, 18.10 this exploitation could allow Remote Unauthorized Access
alt3kx/CVE-2018-7691
CVE-2018-7747 (2018-04-20)
Multiple cross-site scripting (XSS) vulnerabilities in the Caldera Forms plugin before 1.6.0-rc.1 for WordPress allow remote attackers to inject arbitrary web script or HTML via vectors involving (1) a greeting message, (2) the email transaction log, or (3) an imported form.
mindpr00f/CVE-2018-7747
CVE-2018-7750 (2018-03-13)
transport.py in the SSH server implementation of Paramiko before 1.17.6, 1.18.x before 1.18.5, 2.0.x before 2.0.8, 2.1.x before 2.1.5, 2.2.x before 2.2.3, 2.3.x before 2.3.2, and 2.4.x before 2.4.1 does not properly check whether authentication is completed before processing other requests, as demonstrated by channel-open. A customized SSH client can simply skip the authentication step.
jm33-m0/CVE-2018-7750
CVE-2018-7935
lawrenceamer/CVE-2018-7935
CVE-2018-8004 (2018-08-29)
There are multiple HTTP smuggling and cache poisoning issues when clients making malicious requests interact with Apache Traffic Server (ATS). This affects versions 6.0.0 to 6.2.2 and 7.0.0 to 7.1.3. To resolve this issue users running 6.x should upgrade to 6.2.3 or later versions and 7.x users should upgrade to 7.1.4 or later versions.
mosesrenegade/CVE-2018-8004
CVE-2018-8021 (2018-11-07)
Versions of Superset prior to 0.23 used an unsafe load method from the pickle library to deserialize data leading to possible remote code execution. Note Superset 0.23 was released prior to any Superset release under the Apache Software Foundation.
r3dxpl0it/Apache-Superset-Remote-Code-Execution-PoC-CVE-2018-8021
CVE-2018-8032 (2018-08-02)
Apache Axis 1.x up to and including 1.4 is vulnerable to a cross-site scripting (XSS) attack in the default servlet/services.
cairuojin/CVE-2018-8032
CVE-2018-8038 (2018-07-05)
Versions of Apache CXF Fediz prior to 1.4.4 do not fully disable Document Type Declarations (DTDs) when either parsing the Identity Provider response in the application plugins, or in the Identity Provider itself when parsing certain XML-based parameters.
tafamace/CVE-2018-8038
CVE-2018-8039 (2018-07-02)
It is possible to configure Apache CXF to use the com.sun.net.ssl implementation via 'System.setProperty("java.protocol.handler.pkgs", "com.sun.net.ssl.internal.www.protocol");'. When this system property is set, CXF uses some reflection to try to make the HostnameVerifier work with the old com.sun.net.ssl.HostnameVerifier interface. However, the default HostnameVerifier implementation in CXF does not implement the method in this interface, and an exception is thrown. However, in Apache CXF prior to 3.2.5 and 3.1.16 the exception is caught in the reflection code and not properly propagated. What this means is that if you are using the com.sun.net.ssl stack with CXF, an error with TLS hostname verification will not be thrown, leaving a CXF client subject to man-in-the-middle attacks.
tafamace/CVE-2018-8039
CVE-2018-8045 (2018-03-14)
In Joomla! 3.5.0 through 3.8.5, the lack of type casting of a variable in a SQL statement leads to a SQL injection vulnerability in the User Notes list view.
luckybool1020/CVE-2018-8045
CVE-2018-8060 (2018-05-09)
HWiNFO AMD64 Kernel driver version 8.98 and lower allows an unprivileged user to send an IOCTL to the device driver. If input and/or output buffer pointers are NULL or if these buffers' data are invalid, a NULL/invalid pointer access occurs, resulting in a Windows kernel panic aka Blue Screen. This affects IOCTLs higher than 0x85FE2600 with the HWiNFO32 symbolic device name.
otavioarj/SIOCtl
CVE-2018-8065 (2018-03-12)
An issue was discovered in the web server in Flexense SyncBreeze Enterprise 10.6.24. There is a user mode write access violation on the syncbrs.exe memory region that can be triggered by rapidly sending a variety of HTTP requests with long HTTP header values or long URIs.
EgeBalci/CVE-2018-8065
CVE-2018-8078 (2018-03-13)
YzmCMS 3.7 has Stored XSS via the title parameter to advertisement/adver/edit.html.
AlwaysHereFight/YZMCMSxss
CVE-2018-8090 (2018-07-25)
Quick Heal Total Security 64 bit 17.00 (QHTS64.exe), (QHTSFT64.exe) - Version 10.0.1.38; Quick Heal Total Security 32 bit 17.00 (QHTS32.exe), (QHTSFT32.exe) - Version 10.0.1.38; Quick Heal Internet Security 64 bit 17.00 (QHIS64.exe), (QHISFT64.exe) - Version 10.0.0.37; Quick Heal Internet Security 32 bit 17.00 (QHIS32.exe), (QHISFT32.exe) - Version 10.0.0.37; Quick Heal AntiVirus Pro 64 bit 17.00 (QHAV64.exe), (QHAVFT64.exe) - Version 10.0.0.37; and Quick Heal AntiVirus Pro 32 bit 17.00 (QHAV32.exe), (QHAVFT32.exe) - Version 10.0.0.37 allow DLL Hijacking because of Insecure Library Loading.
kernelm0de/CVE-2018-8090
CVE-2018-8108 (2018-03-14)
The select component in bui through 2018-03-13 has XSS because it performs an escape operation on already-escaped text, as demonstrated by workGroupList text.
zlgxzswjy/BUI-select-xss
CVE-2018-8115 (2018-05-02)
A remote code execution vulnerability exists when the Windows Host Compute Service Shim (hcsshim) library fails to properly validate input while importing a container image, aka "Windows Host Compute Service Shim Remote Code Execution Vulnerability." This affects Windows Host Compute.
aquasecurity/scan-cve-2018-8115
CVE-2018-8120 (2018-05-09)
An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka "Win32k Elevation of Privilege Vulnerability." This affects Windows Server 2008, Windows 7, Windows Server 2008 R2. This CVE ID is unique from CVE-2018-8124, CVE-2018-8164, CVE-2018-8166.
bigric3/cve-2018-8120
unamer/CVE-2018-8120
ne1llee/cve-2018-8120
alpha1ab/CVE-2018-8120
areuu/CVE-2018-8120
EVOL4/CVE-2018-8120
ozkanbilge/CVE-2018-8120
qiantu88/CVE-2018-8120
Y0n0Y/cve-2018-8120-exp
DreamoneOnly/CVE-2018-8120
StartZYP/CVE-2018-8120
wikiZ/cve-2018-8120
CVE-2018-8172 (2018-07-10)
A remote code execution vulnerability exists in Visual Studio software when the software does not check the source markup of a file for an unbuilt project, aka "Visual Studio Remote Code Execution Vulnerability." This affects Microsoft Visual Studio, Expression Blend 4.
SyFi/CVE-2018-8172
CVE-2018-8174 (2018-05-09)
A remote code execution vulnerability exists in the way that the VBScript engine handles objects in memory, aka "Windows VBScript Engine Remote Code Execution Vulnerability." This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers.
0x09AL/CVE-2018-8174-msf
Yt1g3r/CVE-2018-8174_EXP
SyFi/CVE-2018-8174
orf53975/Rig-Exploit-for-CVE-2018-8174
piotrflorczyk/cve-2018-8174_analysis
likescam/CVE-2018-8174-msf
ruthlezs/ie11_vbscript_exploit
ericisnotrealname/CVE-2018-8174_EXP
www201001/https-github.com-iBearcat-CVE-2018-8174_EXP
www201001/https-github.com-iBearcat-CVE-2018-8174_EXP.git-
CVE-2018-8208 (2018-06-14)
An elevation of privilege vulnerability exists in Windows when Desktop Bridge does not properly manage the virtual registry, aka "Windows Desktop Bridge Elevation of Privilege Vulnerability." This affects Windows Server 2016, Windows 10, Windows 10 Servers. This CVE ID is unique from CVE-2018-8214.
kaisaryousuf/CVE-2018-8208
CVE-2018-8214 (2018-06-14)
An elevation of privilege vulnerability exists in Windows when Desktop Bridge does not properly manage the virtual registry, aka "Windows Desktop Bridge Elevation of Privilege Vulnerability." This affects Windows Server 2016, Windows 10, Windows 10 Servers. This CVE ID is unique from CVE-2018-8208.
guwudoor/CVE-2018-8214
CVE-2018-8284 (2018-07-10)
A remote code execution vulnerability exists when the Microsoft .NET Framework fails to validate input properly, aka ".NET Framework Remote Code Injection Vulnerability." This affects Microsoft .NET Framework 2.0, Microsoft .NET Framework 3.0, Microsoft .NET Framework 4.6.2/4.7/4.7.1/4.7.2, Microsoft .NET Framework 4.5.2, Microsoft .NET Framework 4.6, Microsoft .NET Framework 4.7/4.7.1/4.7.2, Microsoft .NET Framework 4.7.1/4.7.2, Microsoft .NET Framework 3.5, Microsoft .NET Framework 3.5.1, Microsoft .NET Framework 4.6/4.6.1/4.6.2, Microsoft .NET Framework 4.6/4.6.1/4.6.2/4.7/4.7.1/4.7.1/4.7.2, Microsoft .NET Framework 4.7.2.
quantiti/CVE-2018-8284-Sharepoint-RCE
CVE-2018-8353 (2018-08-15)
A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Internet Explorer, aka "Scripting Engine Memory Corruption Vulnerability." This affects Internet Explorer 9, Internet Explorer 11, Internet Explorer 10. This CVE ID is unique from CVE-2018-8355, CVE-2018-8359, CVE-2018-8371, CVE-2018-8372, CVE-2018-8373, CVE-2018-8385, CVE-2018-8389, CVE-2018-8390.
whereisr0da/CVE-2018-8353-POC
CVE-2018-8389 (2018-08-15)
A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Internet Explorer, aka "Scripting Engine Memory Corruption Vulnerability." This affects Internet Explorer 9, Internet Explorer 11, Internet Explorer 10. This CVE ID is unique from CVE-2018-8353, CVE-2018-8355, CVE-2018-8359, CVE-2018-8371, CVE-2018-8372, CVE-2018-8373, CVE-2018-8385, CVE-2018-8390.
sharmasandeepkr/cve-2018-8389
CVE-2018-8414 (2018-08-15)
A remote code execution vulnerability exists when the Windows Shell does not properly validate file paths, aka "Windows Shell Remote Code Execution Vulnerability." This affects Windows 10 Servers, Windows 10.
whereisr0da/CVE-2018-8414-POC
CVE-2018-8420 (2018-09-12)
A remote code execution vulnerability exists when the Microsoft XML Core Services MSXML parser processes user input, aka "MS XML Remote Code Execution Vulnerability." This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers.
idkwim/CVE-2018-8420
CVE-2018-8440 (2018-09-12)
An elevation of privilege vulnerability exists when Windows improperly handles calls to Advanced Local Procedure Call (ALPC), aka "Windows ALPC Elevation of Privilege Vulnerability." This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers.
sourceincite/CVE-2018-8440
CVE-2018-8453 (2018-10-10)
An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka "Win32k Elevation of Privilege Vulnerability." This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2019, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers.
Mkv4/cve-2018-8453-exp
ze0r/cve-2018-8453-exp
thepwnrip/leHACK-Analysis-of-CVE-2018-8453
CVE-2018-8495 (2018-10-10)
A remote code execution vulnerability exists when Windows Shell improperly handles URIs, aka "Windows Shell Remote Code Execution Vulnerability." This affects Windows Server 2016, Windows 10, Windows 10 Servers.
whereisr0da/CVE-2018-8495-POC
CVE-2018-8581 (2018-11-13)
An elevation of privilege vulnerability exists in Microsoft Exchange Server, aka "Microsoft Exchange Server Elevation of Privilege Vulnerability." This affects Microsoft Exchange Server.
WyAtu/CVE-2018-8581
qiantu88/CVE-2018-8581
Ridter/Exchange2domain
CVE-2018-8639 (2018-12-11)
An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka "Win32k Elevation of Privilege Vulnerability." This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2019, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers. This CVE ID is unique from CVE-2018-8641.
ze0r/CVE-2018-8639-exp
timwhitez/CVE-2018-8639-EXP
CVE-2018-8718 (2018-03-27)
Cross-site request forgery (CSRF) vulnerability in the Mailer Plugin 1.20 for Jenkins 2.111 allows remote authenticated users to send unauthorized mail as an arbitrary user via a /descriptorByName/hudson.tasks.Mailer/sendTestMail request.
GeunSam2/CVE-2018-8718
CVE-2018-8733 (2018-04-17)
Authentication bypass vulnerability in the core config manager in Nagios XI 5.2.x through 5.4.x before 5.4.13 allows an unauthenticated attacker to make configuration changes and leverage an authenticated SQL injection vulnerability.
xfer0/Nagios-XI-5.2.6-9-5.3-5.4-Chained-Remote-Root-Exploit-Fixed
CVE-2018-8820 (2018-03-28)
An issue was discovered in Square 9 GlobalForms 6.2.x. A Time Based SQL injection vulnerability in the "match" parameter allows remote authenticated attackers to execute arbitrary SQL commands. It is possible to upgrade access to full server compromise via xp_cmdshell. In some cases, the authentication requirement for the attack can be met by sending the default admin credentials.
hateshape/frevvomapexec
CVE-2018-8897 (2018-05-08)
A statement in the System Programming Guide of the Intel 64 and IA-32 Architectures Software Developer's Manual (SDM) was mishandled in the development of some or all operating-system kernels, resulting in unexpected behavior for #DB exceptions that are deferred by MOV SS or POP SS, as demonstrated by (for example) privilege escalation in Windows, macOS, some Xen configurations, or FreeBSD, or a Linux kernel crash. The MOV to SS and POP SS instructions inhibit interrupts (including NMIs), data breakpoints, and single step trap exceptions until the instruction boundary following the next instruction (SDM Vol. 3A; section 6.8.3). (The inhibited data breakpoints are those on memory accessed by the MOV to SS or POP to SS instruction itself.) Note that debug exceptions are not inhibited by the interrupt enable (EFLAGS.IF) system flag (SDM Vol. 3A; section 2.3). If the instruction following the MOV to SS or POP to SS instruction is an instruction like SYSCALL, SYSENTER, INT 3, etc. that transfers control to the operating system at CPL < 3, the debug exception is delivered after the transfer to CPL < 3 is complete. OS kernels may not expect this order of events and may therefore experience unexpected behavior when it occurs.
nmulasmajic/CVE-2018-8897
jiazhang0/pop-mov-ss-exploit
can1357/CVE-2018-8897
nmulasmajic/syscall_exploit_CVE-2018-8897
CVE-2018-8941 (2018-04-03)
Diagnostics functionality on D-Link DSL-3782 devices with firmware EU v. 1.01 has a buffer overflow, allowing authenticated remote attackers to execute arbitrary code via a long Addr value to the 'set Diagnostics_Entry' function in an HTTP request, related to /userfs/bin/tcapi.
SECFORCE/CVE-2018-8941
CVE-2018-8943 (2018-03-22)
There is a SQL injection in the PHPSHE 1.6 userbank parameter.
coolboy0816/CVE-2018-8943
CVE-2018-8970 (2018-03-24)
The int_x509_param_set_hosts function in lib/libcrypto/x509/x509_vpm.c in LibreSSL 2.7.0 before 2.7.1 does not support a certain special case of a zero name length, which causes silent omission of hostname verification, and consequently allows man-in-the-middle attackers to spoof servers and obtain sensitive information via a crafted certificate. NOTE: the LibreSSL documentation indicates that this special case is supported, but the BoringSSL documentation does not.
tiran/CVE-2018-8970
CVE-2018-9059 (2018-04-20)
Stack-based buffer overflow in Easy File Sharing (EFS) Web Server 7.2 allows remote attackers to execute arbitrary code via a malicious login request to forum.ghp. NOTE: this may overlap CVE-2014-3791.
manojcode/easy-file-share-7.2-exploit-CVE-2018-9059
CVE-2018-9075 (2018-09-28)
For some Iomega, Lenovo, LenovoEMC NAS devices versions 4.1.402.34662 and earlier, when joining a PersonalCloud setup, an attacker can craft a command injection payload using backtick "``" characters in the client:password parameter. As a result, arbitrary commands may be executed as the root user. The attack requires a value __c and iomega parameter.
beverlymiller818/cve-2018-9075
CVE-2018-9160 (2018-03-31)
SickRage before v2018.03.09-1 includes cleartext credentials in HTTP responses.
mechanico/sickrageWTF
CVE-2018-9206 (2018-10-11)
Unauthenticated arbitrary file upload vulnerability in Blueimp jQuery-File-Upload <= v9.22.0
Den1al/CVE-2018-9206
Stahlz/JQShell
cved-sources/cve-2018-9206
CVE-2018-9207 (2018-11-19)
Arbitrary file upload in jQuery Upload File <= 4.0.2
cved-sources/cve-2018-9207
CVE-2018-9208 (2018-11-05)
Unauthenticated arbitrary file upload vulnerability in jQuery Picture Cut <= v1.1Beta
cved-sources/cve-2018-9208
CVE-2018-9276 (2018-07-02)
An issue was discovered in PRTG Network Monitor before 18.2.39. An attacker who has access to the PRTG System Administrator web console with administrative privileges can exploit an OS command injection vulnerability (both on the server and on devices) by sending malformed parameters in sensor or notification management scenarios.
wildkindcc/CVE-2018-9276
AndyFeiLi/CVE-2018-9276
CVE-2018-9375
IOActive/AOSP-ExploitUserDictionary
CVE-2018-9411
tamirzb/CVE-2018-9411
CVE-2018-9468
IOActive/AOSP-DownloadProviderHijacker
CVE-2018-9493 (2018-10-02)
In the content provider of the download manager, there is a possible SQL injection due to improper input validation. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android Versions: Android-7.0 Android-7.1.1 Android-7.1.2 Android-8.0 Android-8.1 Android-9.0 Android ID: A-111085900
IOActive/AOSP-DownloadProviderDbDumper
CVE-2018-9539 (2018-11-14)
In the ClearKey CAS descrambler, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android. Versions: Android-8.0 Android-8.1 Android-9. Android ID: A-113027383
tamirzb/CVE-2018-9539
CVE-2018-9546
IOActive/AOSP-DownloadProviderHeadersDumper
CVE-2018-9948 (2018-05-17)
This vulnerability allows remote attackers to disclose sensitive information on vulnerable installations of Foxit Reader 9.0.0.29935. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the handling of typed arrays. The issue results from the lack of proper initialization of a pointer prior to accessing it. An attacker can leverage this in conjunction with other vulnerabilities to execute code in the context of the current process. Was ZDI-CAN-5380.
manojcode/Foxit-Reader-RCE-with-virualalloc-and-shellcode-for-CVE-2018-9948-and-CVE-2018-9958
orangepirate/cve-2018-9948-9958-exp
CVE-2018-9950 (2018-05-17)
This vulnerability allows remote attackers to disclose sensitive information on vulnerable installations of Foxit Reader 9.0.0.29935. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of PDF documents. The issue results from the lack of proper validation of user-supplied data, which can result in a read past the end of an allocated object. An attacker can leverage this in conjunction with other vulnerabilities to execute code in the context of the current process. Was ZDI-CAN-5413.
sharmasandeepkr/PS-2017-13---CVE-2018-9950
CVE-2018-9951 (2018-05-17)
This vulnerability allows remote attackers to execute arbitrary code on vulnerable installations of Foxit Reader 9.0.0.29935. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the handling of CPDF_Object objects. The issue results from the lack of validating the existence of an object prior to performing operations on the object. An attacker can leverage this vulnerability to execute code under the context of the current process. Was ZDI-CAN-5414.
sharmasandeepkr/cve-2018-9951
CVE-2018-9958 (2018-05-17)
This vulnerability allows remote attackers to execute arbitrary code on vulnerable installations of Foxit Reader 9.0.1.1049. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the handling of Text Annotations. When setting the point attribute, the process does not properly validate the existence of an object prior to performing operations on the object. An attacker can leverage this vulnerability to execute code under the context of the current process. Was ZDI-CAN-5620.
t3rabyt3-zz/CVE-2018-9958--Exploit
CVE-2018-9995 (2018-04-10)
TBK DVR4104 and DVR4216 devices, as well as Novo, CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Login, HVR Login, and MDVR Login, which run re-branded versions of the original TBK DVR4104 and DVR4216 series, allow remote attackers to bypass authentication via a "Cookie: uid=admin" header, as demonstrated by a device.rsp?opt=user&cmd=list request that provides credentials within JSON data in a response.
ezelf/CVE-2018-9995_dvr_credentials
zzh217/CVE-2018-9995_Batch_scanning_exp
Huangkey/CVE-2018-9995_check
gwolfs/CVE-2018-9995-ModifiedByGwolfs
shacojx/cve-2018-9995
Cyb0r9/DVR-Exploiter
codeholic2k18/CVE-2018-9995
TateYdq/CVE-2018-9995-ModifiedByGwolfs
ABIZCHI/CVE-2018-9995_dvr_credentials
IHA114/CVE-2018-9995_dvr_credentials
likaifeng0/CVE-2018-9995_dvr_credentials-dev_tool
b510/CVE-2018-9995-POC
akuhidayat/HTC
g5q2/cve-2018-9995
HACKGM/CVE-2018-9995
CVE-2018-10118 (2018-04-15)
Monstra CMS 3.0.4 has Stored XSS via the Name field on the Create New Page screen under the admin/index.php?id=pages URI, related to plugins/box/pages/pages.admin.php.
GeunSam2/CVE-2018-10118
CVE-2018-10299 (2018-04-23)
An integer overflow in the batchTransfer function of a smart contract implementation for Beauty Ecosystem Coin (BEC), the Ethereum ERC20 token used in the Beauty Chain economic system, allows attackers to accomplish an unauthorized increase of digital assets by providing two _receivers arguments in conjunction with a large _value argument, as exploited in the wild in April 2018, aka the "batchOverflow" issue.
phzietsman/batchOverflow
CVE-2018-10388 (2019-12-23)
Format string vulnerability in the logMess function in TFTP Server SP 1.66 and earlier allows remote attackers to perform a denial of service or execute arbitrary code via format string sequences in a TFTP error packet.
0xddaa/CVE-2018-10388
CVE-2018-10467
alt3kx/CVE-2018-10467
CVE-2018-10517 (2018-04-27)
In CMS Made Simple (CMSMS) through 2.2.7, the "module import" operation in the admin dashboard contains a remote code execution vulnerability, exploitable by an admin user, because an XML Package can contain base64-encoded PHP code in a data element.
0x00-0x00/CVE-2018-10517
CVE-2018-10546 (2018-04-29)
An issue was discovered in PHP before 5.6.36, 7.0.x before 7.0.30, 7.1.x before 7.1.17, and 7.2.x before 7.2.5. An infinite loop exists in ext/iconv/iconv.c because the iconv stream filter does not reject invalid multibyte sequences.
dsfau/CVE-2018-10546
CVE-2018-10561 (2018-05-03)
An issue was discovered on Dasan GPON home routers. It is possible to bypass authentication simply by appending "?images" to any URL of the device that requires authentication, as demonstrated by the /menu.html?images/ or /GponForm/diag_FORM?images/ URI. One can then manage the device.
vhackor/GPON-home-routers-Exploit
CVE-2018-10562 (2018-05-03)
An issue was discovered on Dasan GPON home routers. Command Injection can occur via the dest_host parameter in a diag_action=ping request to a GponForm/diag_Form URI. Because the router saves ping results in /tmp and transmits them to the user when the user revisits /diag.html, it's quite simple to execute commands and retrieve their output.
f3d0x0/GPON
649/Pingpon-Exploit
Choudai/GPON-LOADER
c0ld1/GPON_RCE
ATpiu/CVE-2018-10562
CVE-2018-10583 (2018-05-01)
An information disclosure vulnerability occurs when LibreOffice 6.0.3 and Apache OpenOffice Writer 4.1.5 automatically process and initiate an SMB connection embedded in a malicious file, as demonstrated by xlink:href=file://192.168.0.2/test.jpg within an office:document-content element in a .odt XML document.
TaharAmine/CVE-2018-10583
CVE-2018-10678 (2018-05-13)
MyBB 1.8.15, when accessed with Microsoft Edge, mishandles 'target="_blank" rel="noopener"' in A elements, which makes it easier for remote attackers to conduct redirection attacks.
hbranco/CVE-2018-10678
CVE-2018-10715
alt3kx/CVE-2018-10715
CVE-2018-10732 (2018-05-28)
The REST API in Dataiku DSS before 4.2.3 allows remote attackers to obtain sensitive information (i.e., determine if a username is valid) because of profile pictures visibility.
alt3kx/CVE-2018-10732
CVE-2018-10821 (2018-06-14)
Cross-site scripting (XSS) vulnerability in backend/pages/modify.php in BlackCatCMS 1.3 allows remote authenticated users with the Admin role to inject arbitrary web script or HTML via the search panel.
BalvinderSingh23/Cross-Site-Scripting-Reflected-XSS-Vulnerability-in-blackcatcms_v1.3
CVE-2018-10920 (2018-08-02)
Improper input validation bug in DNS resolver component of Knot Resolver before 2.4.1 allows remote attacker to poison cache.
shutingrz/CVE-2018-10920_PoC
CVE-2018-10933 (2018-10-17)
A vulnerability was found in libssh's server-side state machine before versions 0.7.6 and 0.8.4. A malicious client could create channels without first performing authentication, resulting in unauthorized access.
SoledaD208/CVE-2018-10933
blacknbunny/CVE-2018-10933
hook-s3c/CVE-2018-10933
kn6869610/CVE-2018-10933
leapsecurity/libssh-scanner
likescam/CVE-2018-10933_ssh
trbpnd/bpnd-libssh
likescam/CVE-2018-10933-libSSH-Authentication-Bypass
marco-lancini/hunt-for-cve-2018-10933
hackerhouse-opensource/cve-2018-10933
cve-2018/cve-2018-10933
jas502n/CVE-2018-10933
ninp0/cve-2018-10933_poc
pghook/CVE-2018-10933_Scanner
Virgula0/POC-CVE-2018-10933
shifa123/pythonprojects-CVE-2018-10933
xFreed0m/CVE-2018-10933
Bifrozt/CVE-2018-10933
r3dxpl0it/CVE-2018-10933
ivanacostarubio/libssh-scanner
throwawayaccount12312312/precompiled-CVE-2018-10933
ensimag-security/CVE-2018-10933
Ad1bDaw/libSSH-bypass
sambiyal/CVE-2018-10933-POC
nikhil1232/LibSSH-Authentication-Bypass
Kurlee/LibSSH-exploit
crispy-peppers/Libssh-server-CVE-2018-10933
youkergav/CVE-2018-10933
kristyna-mlcakova/CVE-2018-10933
lalishasanduwara/CVE-2018-10933
JoSecMx/CVE-2018-10933_Scanner
cyberharsh/Libssh-server-CVE-2018-10933
CVE-2018-10936 (2018-08-30)
A weakness was found in postgresql-jdbc before version 42.2.5. It was possible to provide an SSL Factory and not check the host name if a host name verifier was not provided to the driver. This could lead to a condition where a man-in-the-middle attacker could masquerade as a trusted server by providing a certificate for the wrong host, as long as it was signed by a trusted CA.
tafamace/CVE-2018-10936
CVE-2018-10949 (2018-05-09)
mailboxd in Zimbra Collaboration Suite 8.8 before 8.8.8; 8.7 before 8.7.11.Patch3; and 8.6 allows Account Enumeration by leveraging a Discrepancy between the "HTTP 404 - account is not active" and "HTTP 401 - must authenticate" errors.
0x00-0x00/CVE-2018-10949
CVE-2018-11235 (2018-05-30)
In Git before 2.13.7, 2.14.x before 2.14.4, 2.15.x before 2.15.2, 2.16.x before 2.16.4, and 2.17.x before 2.17.1, remote code execution can occur. With a crafted .gitmodules file, a malicious project can execute an arbitrary script on a machine that runs "git clone --recurse-submodules" because submodule "names" are obtained from this file, and then appended to $GIT_DIR/modules, leading to directory traversal with "../" in a name. Finally, post-checkout hooks from a submodule are executed, bypassing the intended design in which hooks are not obtained from a remote server.
Rogdham/CVE-2018-11235
vmotos/CVE-2018-11235
Choihosu/cve-2018-11235
CHYbeta/CVE-2018-11235-DEMO
Kiss-sh0t/CVE-2018-11235-poc
H0K5/clone_and_pwn
knqyf263/CVE-2018-11235
ygouzerh/CVE-2018-11235
qweraqq/CVE-2018-11235-Git-Submodule-CE
jhswartz/CVE-2018-11235
AnonymKing/CVE-2018-11235
morhax/CVE-2018-11235
cchang27/CVE-2018-11235-test
nthuong95/CVE-2018-11235
xElkomy/CVE-2018-11235
makeross/CVE-2018-11235
makeross/CVE-2018-11235_pub
jongmartinez/CVE-2018-11235-PoC
CVE-2018-11236 (2018-05-18)
stdlib/canonicalize.c in the GNU C Library (aka glibc or libc6) 2.27 and earlier, when processing very long pathname arguments to the realpath function, could encounter an integer overflow on 32-bit architectures, leading to a stack-based buffer overflow and, potentially, arbitrary code execution.
evilmiracle/CVE-2018-11236
rockysec/CVE-2018-11236
CVE-2018-11311 (2018-05-20)
A hardcoded FTP username of myscada and password of Vikuk63 in 'myscadagate.exe' in mySCADA myPRO 7 allows remote attackers to access the FTP server on port 2121, and upload files or list directories, by entering these credentials.
EmreOvunc/mySCADA-myPRO-7-Hardcoded-FTP-Username-and-Password
CVE-2018-11450 (2018-07-09)
A reflected Cross-Site-Scripting (XSS) vulnerability has been identified in Siemens PLM Software TEAMCENTER (V9.1.2.5). If a user visits the login portal through the URL crafted by the attacker, the attacker can insert html/javascript and thus alter/rewrite the login portal page. Siemens PLM Software TEAMCENTER V9.1.3 and newer are not affected.
LucvanDonk/Siemens-Siemens-PLM-Software-TEAMCENTER-Reflected-Cross-Site-Scripting-XSS-vulnerability
CVE-2018-11510 (2018-06-28)
The ASUSTOR ADM 3.1.0.RFQ3 NAS portal suffers from an unauthenticated remote code execution vulnerability in the portal/apis/aggrecate_js.cgi file by embedding OS commands in the 'script' parameter.
mefulton/CVE-2018-11510
CVE-2018-11517 (2018-05-28)
mySCADA myPRO 7 allows remote attackers to discover all ProjectIDs in a project by sending all of the prj parameter values from 870000 to 875000 in t=0&rq=0 requests to TCP port 11010.
EmreOvunc/mySCADA-myPRO-7-projectID-Disclosure
CVE-2018-11564 (2018-06-01)
Stored XSS in YOOtheme Pagekit 1.0.13 and earlier allows a user to upload malicious code via the picture upload feature. A user with elevated privileges could upload a photo to the system in an SVG format. This file will be uploaded to the system and it will not be stripped or filtered. The user can create a link on the website pointing to "/storage/poc.svg" that will point to http://localhost/pagekit/storage/poc.svg. When a user comes along to click that link, it will trigger a XSS attack.
GeunSam2/CVE-2018-11564
CVE-2018-11631 (2018-05-31)
Rondaful M1 Wristband Smart Band 1 devices allow remote attackers to send an arbitrary number of call or SMS notifications via crafted Bluetooth Low Energy (BLE) traffic.
xMagass/bandexploit
CVE-2018-11686 (2019-07-03)
The Publish Service in FlexPaper (later renamed FlowPaper) 2.3.6 allows remote code execution via setup.php and change_config.php.
mpgn/CVE-2018-11686
CVE-2018-11759 (2018-10-31)
The Apache Web Server (httpd) specific code that normalised the requested path before matching it to the URI-worker map in Apache Tomcat JK (mod_jk) Connector 1.2.0 to 1.2.44 did not handle some edge cases correctly. If only a sub-set of the URLs supported by Tomcat were exposed via httpd, then it was possible for a specially constructed request to expose application functionality through the reverse proxy that was not intended for clients accessing the application via the reverse proxy. It was also possible in some configurations for a specially constructed request to bypass the access controls configured in httpd. While there is some overlap between this issue and CVE-2018-1323, they are not identical.
immunIT/CVE-2018-11759
Jul10l1r4/Identificador-CVE-2018-11759
CVE-2018-11761 (2018-09-19)
In Apache Tika 0.1 to 1.18, the XML parsers were not configured to limit entity expansion. They were therefore vulnerable to an entity expansion vulnerability which can lead to a denial of service attack.
brianwrf/CVE-2018-11761
CVE-2018-11770 (2018-08-13)
From version 1.3.0 onward, Apache Spark's standalone master exposes a REST API for job submission, in addition to the submission mechanism used by spark-submit. In standalone, the config property 'spark.authenticate.secret' establishes a shared secret for authenticating requests to submit jobs via spark-submit. However, the REST API does not use this or any other authentication mechanism, and this is not adequately documented. In this case, a user would be able to run a driver program without authenticating, but not launch executors, using the REST API. This REST API is also used by Mesos, when set up to run in cluster mode (i.e., when also running MesosClusterDispatcher), for job submission. Future versions of Spark will improve documentation on these points, and prohibit setting 'spark.authenticate.secret' when running the REST APIs, to make this clear. Future versions will also disable the REST API by default in the standalone master by changing the default value of 'spark.master.rest.enabled' to 'false'.
ivanitlearning/CVE-2018-11770
CVE-2018-11776 (2018-08-22)
Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 suffer from possible Remote Code Execution when alwaysSelectFullNamespace is true (either by user or a plugin like Convention Plugin) and then: results are used with no namespace and in same time, its upper package have no or wildcard namespace and similar to results, same possibility when using url tag which doesn't have value and action set and in same time, its upper package have no or wildcard namespace.
trbpnd/CVE-2018-11776
xfox64x/CVE-2018-11776
jiguangin/CVE-2018-11776
hook-s3c/CVE-2018-11776-Python-PoC
mazen160/struts-pwn_CVE-2018-11776
bhdresh/CVE-2018-11776
knqyf263/CVE-2018-11776
Ekultek/Strutter
tuxotron/cve-2018-11776-docker
brianwrf/S2-057-CVE-2018-11776
649/Apache-Struts-Shodan-Exploit
jezzus/CVE-2018-11776-Python-PoC
cved-sources/cve-2018-11776
OzNetNerd/apche-struts-vuln-demo-cve-2018-11776
cucadili/CVE-2018-11776
LightC0der/Apache-Struts-0Day-Exploit
freshdemo/ApacheStruts-CVE-2018-11776
CVE-2018-11788 (2019-01-07)
Apache Karaf provides a features deployer, which allows users to "hot deploy" a features XML by dropping the file directly in the deploy folder. The features XML is parsed by XMLInputFactory class. Apache Karaf XMLInputFactory class doesn't contain any mitigation codes against XXE. This is a potential security risk as an user can inject external XML entities in Apache Karaf version prior to 4.1.7 or 4.2.2. It has been fixed in Apache Karaf 4.1.7 and 4.2.2 releases.
brianwrf/CVE-2018-11788
CVE-2018-11882 (2018-10-29)
Incorrect bound check can lead to potential buffer overwrite in WLAN controller in Snapdragon Mobile in version SD 835, SD 845, SD 850, SDA660.
jguard01/cve-2018-11882
CVE-2018-12018 (2018-07-04)
The GetBlockHeadersMsg handler in the LES protocol implementation in Go Ethereum (aka geth) before 1.8.11 may lead to an access violation because of an integer signedness error for the array index, which allows attackers to launch a Denial of Service attack by sending a packet with a -1 query.Skip value. The vulnerable remote node would be crashed by such an attack immediately, aka the EPoD (Ethereum Packet of Death) issue.
k3v142/CVE-2018-12018
CVE-2018-12031 (2018-06-07)
Local file inclusion in Eaton Intelligent Power Manager v1.6 allows an attacker to include a file via server/node_upgrade_srv.js directory traversal with the firmware parameter in a downloadFirmware action.
EmreOvunc/Eaton-Intelligent-Power-Manager-Local-File-Inclusion
CVE-2018-12038 (2018-11-20)
An issue was discovered on Samsung 840 EVO devices. Vendor-specific commands may allow access to the disk-encryption key.
