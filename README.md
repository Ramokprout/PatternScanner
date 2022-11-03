
# PatternScanner

A single header ready-to-use pattern scanner.


## Features

- Module scanning
- Section scanner
- IDA style scanning
- Resolve RVA


## Example

```cpp
PatternScanner *scanner = new PatternScanner(lpModuleName, "sectionName");
uintptr_t address = scanner->scanPattern("signature", skipBytes, bRelative, dwInstructionSize);
```




## Documentation

**operator new PatternScanner**(LPCWSTR lpModuleName, LPCSTR sectionName)

uintptr_t **scanPattern**(LPCSTR signature, int skipBytes = 0, bool bRelative = false, int instruction_size = 0)
## References

- [[Help] Pattern scan c++ - UnknownCheats](https://www.unknowncheats.me/forum/counterstrike-global-offensive/433203-pattern-scan.html) (**patternToBytes**)
- [PE Format](https://learn.microsoft.com/fr-fr/windows/win32/debug/pe-format) (**sections**)
