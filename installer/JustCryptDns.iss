; JustCryptDns Windows x64 Installer (Inno Setup 6+)
; Builds a signed-ready installer with Windows Service registration (LocalSystem) and clean uninstall.

#define MyAppName "JustCryptDns"
#define MyAppVersion "1.3.0"
#define MyAppPublisher "Longtygu (JustCryptDns)"
#define MyAppURL "https://github.com/longtygu/JustCryptDns"
#define MyAppExeName "JustCryptDns.exe"
#define MyServiceExeName "JustCryptDns.Service.exe"
#define MyServiceName "JustCryptDnsService"
#ifndef PublishDir
#define PublishDir "..\dist\publish\win-x64"
#endif

[Setup]
AppId={{8D6E4A2F-59C1-4B3D-9E6A-42B17C80F3E5}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
LicenseFile=..\LICENSE
OutputDir=..\dist
OutputBaseFilename=JustCryptDns-{#MyAppVersion}-win-x64-setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.19045
PrivilegesRequired=admin
CloseApplications=yes
RestartApplications=no
SetupIconFile=..\src\JustCryptDns.App\Resources\AppIcon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "installservice"; Description: "Install and start JustCryptDns background Windows Service (recommended)"; GroupDescription: "Background Protection:"

[Files]
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\THIRD-PARTY-NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\docs\USER_GUIDE.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\docs\TROUBLESHOOTING.md"; DestDir: "{app}\docs"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Register JustCryptDnsService under LocalSystem with delayed auto-start and crash recovery
Filename: "{sys}\sc.exe"; Parameters: "stop {#MyServiceName}"; Flags: runhidden; Tasks: installservice
Filename: "{sys}\sc.exe"; Parameters: "delete {#MyServiceName}"; Flags: runhidden; Tasks: installservice
Filename: "{sys}\sc.exe"; Parameters: "create {#MyServiceName} binPath= ""\""{app}\{#MyServiceExeName}\"""" start= delayed-auto DisplayName= ""JustCryptDns Background Service"""; Flags: runhidden; Tasks: installservice
Filename: "{sys}\sc.exe"; Parameters: "description {#MyServiceName} ""Encrypted DNS proxy, routing, filtering and failover service for JustCryptDns."""; Flags: runhidden; Tasks: installservice
Filename: "{sys}\sc.exe"; Parameters: "failure {#MyServiceName} reset= 86400 actions= restart/5000/restart/15000/restart/30000"; Flags: runhidden; Tasks: installservice
Filename: "{sys}\sc.exe"; Parameters: "start {#MyServiceName}"; Flags: runhidden; Tasks: installservice
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM {#MyAppExeName}"; Flags: runhidden; RunOnceId: "KillApp"
Filename: "{sys}\sc.exe"; Parameters: "stop {#MyServiceName}"; Flags: runhidden; RunOnceId: "StopSvc"
Filename: "{sys}\sc.exe"; Parameters: "delete {#MyServiceName}"; Flags: runhidden; RunOnceId: "DelSvc"
Filename: "{app}\{#MyAppExeName}"; Parameters: "--recover-and-exit"; Flags: runhidden; RunOnceId: "RecoverNetwork"
