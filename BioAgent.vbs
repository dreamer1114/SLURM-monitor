' BioAgent.vbs �� HPC ��Ⱥ��ع���
' ˫�������������ã���������
' ========================================
' �״�ʹ�ã�˫�� �� ��������� �� �� ?? ���ü�Ⱥ��Ϣ �� ������Զ�����
' �ٴ�ʹ�ã�˫�� �� ������Զ��� �� ֱ�ӿ�����Ⱥ״̬
' ========================================

Dim shell, fso, targetPath, nodePath, retCode, configFile, needSetup

Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
targetPath = fso.GetParentFolderName(WScript.ScriptFullName)
configFile = targetPath & "\cluster.config.json"

' --- �� Node.js ---
nodePath = ""
retCode = shell.Run("cmd /c where node > nul 2>&1", 0, True)
If retCode = 0 Then
    nodePath = "node"
Else
    Dim paths, p
    paths = Array( _
        "C:\Program Files\nodejs\node.exe", _
        "C:\Program Files (x86)\nodejs\node.exe", _
        "C:\Users\" & CreateObject("WScript.Network").UserName & "\AppData\Roaming\npm\node.exe" _
    )
    For Each p In paths
        If fso.FileExists(p) Then
            nodePath = p
            Exit For
        End If
    Next
    If nodePath = "" Then
        MsgBox "Node.js not found!" & vbCrLf & "Please install from https://nodejs.org", vbCritical, "BioAgent"
        WScript.Quit 1
    End If
End If

' --- ����Ƿ������� ---
needSetup = False
If fso.FileExists(configFile) Then
    Dim fileContent
    fileContent = fso.OpenTextFile(configFile, 1).ReadAll()
    If InStr(fileContent, """host"": """) > 0 And InStr(fileContent, """password"": """) > 0 Then
        ' ���ô���
    Else
        needSetup = True
    End If
Else
    needSetup = True
End If

' --- ɱ�ɽ��� ---
shell.Run "cmd /c taskkill /f /im node.exe 2>nul", 0, True
WScript.Sleep 1500

' --- npm install ---
If Not fso.FolderExists(targetPath & "\node_modules") Then
    shell.Run "cmd /c cd /d """ & targetPath & """ && npm install --no-audit --no-fund", 0, True
End If

' --- ������� ---
shell.Run "cmd /c cd /d """ & targetPath & """ && " & nodePath & " server.js", 0, False

' --- �ȼ����÷��������� ---
WScript.Sleep 4000

' --- ������� ---
' --- 打开 index.html（登录页） ---
shell.Run "cmd /c start http://localhost:3000/cluster.html", 1, False
