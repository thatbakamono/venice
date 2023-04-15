# Venice
Venice is a C++ library that allows extracting information from Portable Executable (PE) files. PE is a widely used file format used mainly by Windows operating systems and UEFI for executable files.

## Functionality
The library allows extracting the following information from PE files:
* DOS header
* NT headers
* Section list
* List of imported libraries
* List of exported functions

## Example
```cpp
#include <string>
#include <iostream>
#include "PeFile.hpp"

int main() {
  // Specify executable path
  std::string path = "a.exe";

  // Construct parser object
  venice::PeFile peFile { path };
  
  // Check for errors during parsing
  if (peFile.ParseFile() != venice::PeFile::OK) {
    std::cout << "An error occurred";
    
    return 1;
  }
  
  // Get sections
  for (const auto& section : peFile.GetSections()) {
    std::cout << "Section " << section->Name << " with virtual address " << section->VirtualAddress << std::endl;
  }
  
  // Get imports
  for (const auto& import: peFile.GetImports()) {
    std::cout << "Executable imports " << import.function_name << " from " << import.dll_name << std::endl;
  }
  
  // You can use lambda as well
  peFile.ForEachImport([](const std::string& library_name, const std::string& function_name, uint64_t RVA) {
    std::cout << "Executable imports " << function_name << " from " << library_name << std::endl;
  });

  return 0;
}
```

Result:
```
Section .text with virtual address 4096  
Section .rdata with virtual address 36864
Section .data with virtual address 49152 
Section .pdata with virtual address 53248
Section .idata with virtual address 57344
Section .00cfg with virtual address 61440
Section .rsrc with virtual address 65536 
Section .reloc with virtual address 69632
Executable imports GetModuleHandleW from KERNEL32.dll
Executable imports RaiseException from KERNEL32.dll
Executable imports MultiByteToWideChar from KERNEL32.dll
Executable imports WideCharToMultiByte from KERNEL32.dll
Executable imports QueryPerformanceCounter from KERNEL32.dll
Executable imports GetCurrentProcessId from KERNEL32.dll
Executable imports GetCurrentThreadId from KERNEL32.dll
Executable imports GetSystemTimeAsFileTime from KERNEL32.dll
Executable imports TerminateProcess from KERNEL32.dll
Executable imports GetCurrentProcess from KERNEL32.dll
Executable imports GetProcAddress from KERNEL32.dll
Executable imports FreeLibrary from KERNEL32.dll
Executable imports VirtualQuery from KERNEL32.dll
Executable imports GetProcessHeap from KERNEL32.dll
Executable imports HeapFree from KERNEL32.dll
Executable imports HeapAlloc from KERNEL32.dll
Executable imports GetLastError from KERNEL32.dll
Executable imports IsDebuggerPresent from KERNEL32.dll
Executable imports IsProcessorFeaturePresent from KERNEL32.dll
Executable imports GetStartupInfoW from KERNEL32.dll
Executable imports SetUnhandledExceptionFilter from KERNEL32.dll
Executable imports UnhandledExceptionFilter from KERNEL32.dll
Executable imports RtlVirtualUnwind from KERNEL32.dll
Executable imports RtlLookupFunctionEntry from KERNEL32.dll
Executable imports RtlCaptureContext from KERNEL32.dll
Executable imports InitializeSListHead from KERNEL32.dll

```
