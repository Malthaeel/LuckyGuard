#ifndef MyAppVersion
  #define MyAppVersion "1.0.0-rc.5"
#endif
#ifndef PayloadDir
  #define PayloadDir "..\\artifacts\\release\\payload"
#endif
#ifndef OutputDir
  #define OutputDir "..\\artifacts\\release\\packages"
#endif

#define MyAppName "LuckyGuard"
#define MyAppPublisher "LuckyGuard Project"
#define MyAppExeName "LuckyGuard.exe"

[Setup]
AppId={{7D11DE91-2974-45E6-B685-A95D3550B846}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\LuckyGuard
DefaultGroupName=LuckyGuard
DisableProgramGroupPage=yes
OutputDir={#OutputDir}
OutputBaseFilename=LuckyGuard-Setup-{#MyAppVersion}-win-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
SetupLogging=yes
CloseApplications=no
RestartApplications=no
ChangesEnvironment=yes

[Tasks]
Name: "guardservice"; Description: "Install and start LuckyGuard Realtime Guard Windows Service"; GroupDescription: "Realtime protection:"; Flags: checkedonce

[Files]
Source: "{#PayloadDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Registry]
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\LuckyGuard.exe"; ValueType: string; ValueName: ""; ValueData: "{app}\LuckyGuard.exe"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\LuckyGuard.exe"; ValueType: string; ValueName: "Path"; ValueData: "{app}"; Flags: uninsdeletekey

[Icons]
Name: "{group}\LuckyGuard Status"; Filename: "{cmd}"; Parameters: "/k """"{app}\LuckyGuard.exe"" status"""; WorkingDir: "{app}"
Name: "{group}\LuckyGuard Guard Status"; Filename: "{cmd}"; Parameters: "/k """"{app}\LuckyGuard.exe"" guard service status"""; WorkingDir: "{app}"

[Run]
Filename: "{app}\LuckyGuard.exe"; Parameters: "guard service install --confirm INSTALL"; Description: "Install LuckyGuard Realtime Guard service"; Flags: runhidden waituntilterminated; Tasks: guardservice
Filename: "{app}\LuckyGuard.exe"; Parameters: "guard service start"; Description: "Start LuckyGuard Realtime Guard service"; Flags: runhidden waituntilterminated; Tasks: guardservice

[UninstallRun]
Filename: "{app}\LuckyGuard.exe"; Parameters: "guard service stop"; Flags: runhidden waituntilterminated; RunOnceId: "StopLuckyGuardGuard"
Filename: "{app}\LuckyGuard.exe"; Parameters: "guard service uninstall --confirm UNINSTALL"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveLuckyGuardGuard"

[Code]
const
  EnvironmentKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

function TrimTrailingSlash(Value: String): String;
begin
  Result := Value;
  while (Length(Result) > 3) and ((Result[Length(Result)] = '\') or (Result[Length(Result)] = '/')) do
    Delete(Result, Length(Result), 1);
end;

function PathHasEntry(const PathValue, Entry: String): Boolean;
var
  Haystack, Needle: String;
begin
  Haystack := ';' + Lowercase(PathValue) + ';';
  Needle := ';' + Lowercase(TrimTrailingSlash(Entry)) + ';';
  Result := Pos(Needle, Haystack) > 0;
end;

procedure AddLuckyGuardToMachinePath;
var
  PathValue, AppPath: String;
begin
  AppPath := TrimTrailingSlash(ExpandConstant('{app}'));
  if not RegQueryStringValue(HKLM, EnvironmentKey, 'Path', PathValue) then
    PathValue := '';
  if PathHasEntry(PathValue, AppPath) then
    Exit;
  if (Length(PathValue) > 0) and (PathValue[Length(PathValue)] <> ';') then
    PathValue := PathValue + ';';
  PathValue := PathValue + AppPath;
  if not RegWriteExpandStringValue(HKLM, EnvironmentKey, 'Path', PathValue) then
    RaiseException('Could not add LuckyGuard to the machine PATH.');
end;

procedure RemoveLuckyGuardFromMachinePath;
var
  PathValue, AppPath, LowerPath, LowerApp: String;
  P: Integer;
begin
  AppPath := TrimTrailingSlash(ExpandConstant('{app}'));
  if not RegQueryStringValue(HKLM, EnvironmentKey, 'Path', PathValue) then
    Exit;
  LowerApp := Lowercase(AppPath);
  repeat
    LowerPath := Lowercase(PathValue);
    P := Pos(';' + LowerApp + ';', ';' + LowerPath + ';');
    if P = 0 then Break;
    { P is relative to the delimiter-prefixed string. Remove the exact segment from PathValue. }
    if LowerPath = LowerApp then
      PathValue := ''
    else if Pos(LowerApp + ';', LowerPath) = 1 then
      Delete(PathValue, 1, Length(AppPath) + 1)
    else if Copy(LowerPath, Length(LowerPath) - Length(LowerApp), Length(LowerApp) + 1) = ';' + LowerApp then
      Delete(PathValue, Length(PathValue) - Length(AppPath), Length(AppPath) + 1)
    else
    begin
      P := Pos(';' + LowerApp + ';', LowerPath);
      if P > 0 then Delete(PathValue, P, Length(AppPath) + 1);
    end;
  until False;
  RegWriteExpandStringValue(HKLM, EnvironmentKey, 'Path', PathValue);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    AddLuckyGuardToMachinePath;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    RemoveLuckyGuardFromMachinePath;
end;
