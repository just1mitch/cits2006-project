'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
' EV script 005 -  Update EVI files for all EV files in folders
' Example Echoview COM script downloaded from www.echoview.com
' For support, contact the Echoview support team <support@echoview.com>
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

' Strict syntax checking
Option Explicit

''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
' Edit this path for the top folder location
Const ExampleDataFolder = "C:\My EV Files Folder\"

''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
' We want these objects to be available all through the script
Dim FSO
Set FSO = CreateObject("Scripting.FileSystemObject")
Dim EvApp
Set EvApp = CreateObject("EchoviewCOM.EvApplication")

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
' Keep statistics about how many EV files were updated
Dim NumEVFilesUpdated
NumEVFilesUpdated = 0

''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
' A subroutine to update EV files
Sub UpdateFile(Folder)
	Dim File
	For Each File In Folder.Files
		Dim FileName
		FileName = File.Name
		If Not (UCase(Right(FileName, 3)) <> ".EV" Or UCase(Right(FileName, 12)) = " (BACKUP).EV" Or UCase(Right(FileName, 4)) = ".EVI")  Then
			
			Dim EvFile: Set EvFile = EvApp.OpenFile(Folder.Path & "\" & FileName)

			EvFile.PreReadDataFiles
			EvFile.Save
			EvFile.Close
			NumEVFilesUpdated = NumEVFilesUpdated + 1 ' Count how many ev files were updated in total
		End If
	Next
End Sub


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
' Start at the base folder. This code will check two subfolders deep - add more levels if required
Dim BaseFolder
Set BaseFolder = FSO.GetFolder(ExampleDataFolder)
	UpdateFile(BaseFolder)

	Dim SecondFolder
	For Each SecondFolder In BaseFolder.SubFolders
		UpdateFile(SecondFolder)
			
		Dim ThirdFolder
		For Each ThirdFolder In SecondFolder.SubFolders
			UpdateFile(ThirdFolder)
			
			Dim FourthFolder
			For Each FourthFolder In ThirdFolder.SubFolders
				UpdateFile(FourthFolder)
			Next
		Next 
	Next


' If it gets here, it's finished.  Show a dialog saying so
Dim strMessage
strMessage = "Success! " & CStr(NumEVFilesUpdated) & " EV files were updated."
MsgBox strMessage, vbOkOnly + vbInformation, "Process complete"
