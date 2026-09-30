#define AppName "Nusantara AI Device Guardian"
#define AppVersion "0.5.0"
#define AppPublisher "Nusantara AI"
#define AppExeName "Nusantara-AI-Device-Guardian.exe"

[Setup]
AppId={{9D5A6A0E-0A7B-4E4D-9C9B-4A1E6F2F7C12}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\Nusantara AI Device Guardian
DefaultGroupName={#AppName}
OutputDir=installer
OutputBaseFilename=Nusantara-AI-Device-Guardian-Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible

[Files]
Source: "..\dist\Nusantara-AI-Device-Guardian\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent
