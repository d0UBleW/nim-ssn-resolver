import winim/[lean, winstr, utils]
import std/[strformat, strutils]
import osproc

proc get_error_message(err_code: DWORD): string =
    var pBuffer = newWString(512)
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM or FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL,
                   err_code,
                   cast[DWORD](MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)),
                   pBuffer,
                   cast[DWORD](pBuffer.len),
                   NULL);
    nullTerminate(pBuffer)
    var errMsg = %$pBuffer
    return strip(errMsg)

proc err(msg: string, get_err = true) =
    if get_err:
        var err_code = GetLastError()
        var err_msg = get_error_message(err_code)
        echo(fmt"[!] {msg}: (Err: {err_code}) {err_msg}")
    else:
        echo(fmt"[!] {msg}")
    quit(QuitFailure)

type MODULEINFO = object
    lpBaseOfDll: LPVOID
    SizeOfImage: DWORD
    EntryPoint: LPVOID

type
    LPMODULEINFO = ptr MODULEINFO

proc K32GetModuleInformation(hProcess: HANDLE, hModule: HMODULE, lpmodinfo: LPMODULEINFO, cb: DWORD): BOOL
  {.discardable, stdcall, dynlib: "kernel32.dll", importc.}

type ParsedPE = object
    base_addr: QWORD
    dos_header: PIMAGE_DOS_HEADER
    nt_header: PIMAGE_NT_HEADERS
    export_dir: PIMAGE_EXPORT_DIRECTORY

proc parse_pe(lpRawData: LPVOID, parsed: ptr ParsedPE) =
    parsed.base_addr = cast[QWORD](lpRawData)
    parsed.dos_header = cast[PIMAGE_DOS_HEADER](parsed.base_addr)
    parsed.nt_header = cast[PIMAGE_NT_HEADERS](parsed.base_addr + parsed.dos_header.e_lfanew)
    var export_dir_rva = parsed.nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    parsed.export_dir = cast[PIMAGE_EXPORT_DIRECTORY](parsed.base_addr + export_dir_rva)

proc get_ssn(fn_name: string, parsed: ptr ParsedPE): DWORD =
    var num_of_names = parsed.export_dir.NumberOfNames
    var names_addr = parsed.base_addr + parsed.export_dir.AddressOfNames
    var fns_addr = parsed.base_addr + parsed.export_dir.AddressOfFunctions
    for i in 0..<num_of_names:
        var pName = cast[ptr uint32](names_addr + i * 4)
        var name = cast[LPCSTR](parsed.base_addr + cast[QWORD](pName[]))
        if %$name == fn_name:
            var pFnAddrRva = cast[ptr uint32](fns_addr + (i+1) * 4)
            var fn_addr = parsed.base_addr + cast[QWORD](pFnAddrRva[])
            var ssn = (cast[ptr DWORD](fn_addr + 4))[]
            return ssn

proc get_unhook_ntdll(): seq[byte] =
    echo("[+] Creating dummy process")
    var dummy_proc = startProcess("calc.exe")
    echo(fmt"    PID: {dummy_proc.processID()}")
    defer:
        echo("[+] Killing dummy process")
        dummy_proc.terminate()
        dummy_proc.close()
    dummy_proc.suspend()
    var hDummy = OpenProcess(PROCESS_ALL_ACCESS, false, cast[DWORD](dummy_proc.processID()))
    defer: CloseHandle(hDummy)
    var hNtDll = GetModuleHandleA("ntdll.dll")
    var modinfo: MODULEINFO
    var hCurr = GetCurrentProcess()
    defer: CloseHandle(hCurr)
    var ret = K32GetModuleInformation(hCurr, hNtDll, addr modinfo, cast[DWORD](sizeof(modinfo)))
    if ret == 0:
        echo("[+] Killing dummy process")
        dummy_proc.terminate()
        dummy_proc.close()
        err("GetModuleInformation")
    var buffer: seq[byte]
    newSeq(buffer, modinfo.SizeOfImage)
    var nb: SIZE_T
    ret = ReadProcessMemory(hDummy, modinfo.lpBaseOfDll, addr buffer[0], modinfo.SizeOfImage, addr nb)
    if ret == 0:
        echo("[+] Killing dummy process")
        dummy_proc.terminate()
        dummy_proc.close()
        err("ReadProcessMemory")
    return buffer



proc main() =
    echo("[+] Getting unhook ntdll from suspended process")
    var unhook_ntdll = get_unhook_ntdll()
    var unhook_ntdll_ptr = addr unhook_ntdll[0]
    var pe: ParsedPE
    parse_pe(unhook_ntdll_ptr, addr pe)
    var NtCreateThreadExSSN = get_ssn("NtCreateThreadEx", addr pe)
    echo(fmt"NtCreateThreadEx SSN: {NtCreateThreadExSSN.toHex()}")
    var NtProtectVirtualMemorySSN = get_ssn("NtProtectVirtualMemory", addr pe)
    echo(fmt"NtProtectVirtualMemory SSN: {NtProtectVirtualMemorySSN.toHex()}")

when isMainModule:
    main()
