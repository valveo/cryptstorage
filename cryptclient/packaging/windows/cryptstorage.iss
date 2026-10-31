; Inno Setup script for the CryptStorage client on Windows.
; Build:  ISCC.exe /DAppVersion=1.0.0 cryptstorage.iss      (cryptclient.exe and CryptStorage.exe must be in this folder)
; Output: Output\CryptStorageSetup.exe
;
; What it does: copies cryptclient.exe (the console client) and CryptStorage.exe (the same program built as a
; window program: the padlock next to the clock, which asks for the password when the stick is plugged in),
; puts them on PATH, installs the drivers and programs the client
; needs (Dokan, WinFsp, SSHFS-Win; cppcryptfs follows on first setup because it lives in the user's own
; folder) by calling `cryptclient.exe install-deps --msi`, which downloads them from their official
; release pages and checks a pinned SHA-256 first. Then it offers to start the guided setup.
; Code signing is done on the finished file (signtool), not here: see docs/design-setup-app.md.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
; the same AppId as when the product was called secdisk: an update replaces that installation
; and keeps its folder (Program Files\secdisk) and Start menu group
AppId={{6F1D4C0E-5B7A-4C0B-9A57-5EC0D15C0001}
AppName=CryptStorage client
AppVersion={#AppVersion}
AppPublisher=Venomia
DefaultDirName={autopf}\CryptStorage
DefaultGroupName=CryptStorage
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=Output
OutputBaseFilename=CryptStorageSetup
Compression=lzma2
SolidCompression=yes
ChangesEnvironment=yes
DisableProgramGroupPage=yes
UninstallDisplayName=CryptStorage client
UninstallDisplayIcon={app}\CryptStorage.exe
WizardStyle=modern
; IsSetUp below only reads the user's %AppData%, on purpose
UsedUserAreasWarning=no
; Inno Setup turns on Windows' RedirectionGuard for Setup by default, and the setup started from the last
; page got it too: it then could not use its own temporary mount points ("the path cannot be traversed
; because it contains an untrusted mount point") and showed the ciphertext at a drive letter. This
; installer writes only to {app} and the machine Path, not to folders others can write.
RedirectionGuard=no

[Files]
Source: "cryptclient.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "CryptStorage.exe"; DestDir: "{app}"; Flags: ignoreversion

; the tray and its shortcuts under the earlier name
[InstallDelete]
Type: files; Name: "{app}\secdisk.exe"
Type: files; Name: "{group}\secdisk.lnk"
Type: files; Name: "{group}\secdisk setup.lnk"
Type: files; Name: "{group}\secdisk connect (console).lnk"
Type: files; Name: "{group}\Uninstall secdisk.lnk"

[Icons]
Name: "{group}\CryptStorage"; Filename: "{app}\CryptStorage.exe"; WorkingDir: "{app}"
Name: "{group}\CryptStorage setup"; Filename: "{cmd}"; Parameters: "/k """"{app}\cryptclient.exe"" setup"""; WorkingDir: "{app}"
Name: "{group}\CryptStorage connect (console)"; Filename: "{cmd}"; Parameters: "/k """"{app}\cryptclient.exe"" connect"""; WorkingDir: "{app}"
Name: "{group}\Uninstall CryptStorage"; Filename: "{uninstallexe}"

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
  ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; \
  Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
Filename: "{app}\cryptclient.exe"; Parameters: "install-deps --msi"; \
  StatusMsg: "Installing the drivers and programs the client needs (downloads a few MB)..."; \
  Flags: runhidden waituntilterminated
; Only one of the two: a first install starts the guided setup, which starts the padlock when it is
; done; an update of a set-up client starts the padlock. Both at once asked for the stick's password
; twice, in a window and in the console.
Filename: "{cmd}"; Parameters: "/k """"{app}\cryptclient.exe"" setup"""; \
  Description: "Start the guided setup now"; Flags: postinstall nowait skipifsilent runasoriginaluser; \
  Check: not IsSetUp
; the tray turns on starting at sign-in itself, for the user it runs as (the installer runs as administrator)
Filename: "{app}\CryptStorage.exe"; Description: "Start CryptStorage (the padlock next to the clock)"; \
  Flags: postinstall nowait skipifsilent runasoriginaluser; Check: IsSetUp

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM CryptStorage.exe"; Flags: runhidden; RunOnceId: "StopTray"

; install-deps --msi downloads these next to the client (out of the user profile)
[UninstallDelete]
Type: files; Name: "{app}\cppcryptfs.exe"
Type: files; Name: "{app}\cppcryptfsctl.exe"
Type: files; Name: "{app}\rclone.exe"

[Code]
// setup (and connect) save the username in %AppData%\cryptstorage (%AppData%\secdisk before the rename, moved
// by the client when it next runs); the original user's, as the Run entries above run as that user
function IsSetUp(): Boolean;
begin
  Result := FileExists(ExpandConstant('{userappdata}\cryptstorage\username')) or
            FileExists(ExpandConstant('{userappdata}\secdisk\username'));
end;

// the tray under its earlier name holds secdisk.exe open, which [InstallDelete] removes
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Rc: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM secdisk.exe', '', SW_HIDE, ewWaitUntilTerminated, Rc);
  Result := '';
end;

function NeedsAddPath(Param: string): Boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Lowercase(Param) + ';', ';' + Lowercase(OrigPath) + ';') = 0;
end;

// --- Uninstall: the drivers install-deps put in -------------------------------------------------
// They are not ours alone (rclone, Cryptomator and others use WinFsp and Dokan), so the user is asked,
// and a silent uninstall keeps them.

// FindMsiProduct finds an installed MSI whose name starts with Prefix and returns its product code.
function FindMsiProduct(Prefix: string; var Code: string): Boolean;
var
  Roots: array[0..1] of Integer;
  Keys: TArrayOfString;
  Base, Name: string;
  R, I: Integer;
begin
  Result := False;
  Base := 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall';
  Roots[0] := HKLM64;
  Roots[1] := HKLM32;
  for R := 0 to 1 do
    if RegGetSubkeyNames(Roots[R], Base, Keys) then
      for I := 0 to GetArrayLength(Keys) - 1 do
        // MSI products are registered under their product code; bundles and other entries are not
        if (Copy(Keys[I], 1, 1) = '{') and
           RegQueryStringValue(Roots[R], Base + '\' + Keys[I], 'DisplayName', Name) and
           (Pos(Prefix, Name) = 1) then
        begin
          Code := Keys[I];
          Result := True;
          exit;
        end;
end;

procedure RemoveDrivers();
var
  Names: array[0..2] of string;
  Code, List: string;
  I, N, Rc: Integer;
  Restart: Boolean;
begin
  // SSHFS-Win first: it is built on WinFsp
  Names[0] := 'SSHFS-Win';
  Names[1] := 'WinFsp';
  Names[2] := 'Dokan Library';
  List := '';
  for I := 0 to 2 do
    if FindMsiProduct(Names[I], Code) then
      List := List + #13#10 + '    ' + Names[I];
  if (List = '') or UninstallSilent then
    exit;
  if MsgBox('CryptStorage is removed. It also installed these programs:' + #13#10 + List + #13#10#13#10 +
            'Choose Yes to remove them as well.' + #13#10 +
            'Choose No to keep them, for example if another program such as rclone or Cryptomator uses them.',
            mbConfirmation, MB_YESNO or MB_DEFBUTTON2) <> IDYES then
    exit;
  Restart := False;
  for I := 0 to 2 do
    for N := 1 to 3 do // a product can be registered more than once
    begin
      if not FindMsiProduct(Names[I], Code) then
        break;
      Exec(ExpandConstant('{sys}\msiexec.exe'), '/x ' + Code + ' /qn /norestart', '', SW_HIDE,
           ewWaitUntilTerminated, Rc);
      if (Rc = 3010) or (Rc = 1641) then
        Restart := True
      else if Rc <> 0 then
      begin
        MsgBox(Names[I] + ' could not be removed (msiexec code ' + IntToStr(Rc) + '). ' +
               'Remove it in Settings, Apps.', mbError, MB_OK);
        break;
      end;
    end;
  if Restart then
    MsgBox('Restart Windows to finish removing the drivers.', mbInformation, MB_OK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveDrivers();
end;
