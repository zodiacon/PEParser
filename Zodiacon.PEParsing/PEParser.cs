using System;
using System.Collections.Generic;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO;
using Zodiacon.PEParsing.Interop;

namespace Zodiacon.PEParsing {
    public unsafe sealed class PEParser : IDisposable {
        readonly MemoryMappedFile _memFile;
        readonly byte* _address;
        IMAGE_OPTIONAL_HEADER64* _header64;
        IMAGE_OPTIONAL_HEADER32* _header32;
        IMAGE_DOS_HEADER* _dosHeader;
        IMAGE_FILE_HEADER* _fileHeader;
        IMAGE_NT_HEADERS32* _ntHeaders32;
        IMAGE_NT_HEADERS64* _ntHeaders64;
        bool _isPE64;
        IMAGE_SECTION_HEADER[] _sections;
        IntPtr _workBuffer;

        public bool IsPE64 => _isPE64;

        public FileHeader FileHeader { get; private set; }

        public OptionalHeader OptionalHeader { get; private set; }

        public string FileName { get; }

        public PEParser(void* address) {
            _address = (byte*)address;
            CalcHeaders();
        }

        public PEParser(string filename) {
            var stm = File.Open(filename, FileMode.Open, FileAccess.Read, FileShare.Read);
            _memFile = MemoryMappedFile.CreateFromFile(stm, null, 0, MemoryMappedFileAccess.Read, HandleInheritability.None, false);
            _address = (byte*)Win32.MapViewOfFile(_memFile.SafeMemoryMappedFileHandle, 4, 0, 0, new IntPtr(0));
            FileName = filename;
            CalcHeaders();
        }

        void CalcHeaders() {
            _dosHeader = (IMAGE_DOS_HEADER*)_address;
            if (_dosHeader->e_magic != 0x5a4d || _dosHeader->e_lfanew > 1 << 12)
                throw new BadImageFormatException("Not a PE file");

            _ntHeaders32 = (IMAGE_NT_HEADERS32*)(_address + _dosHeader->e_lfanew);
            _ntHeaders64 = (IMAGE_NT_HEADERS64*)(_address + _dosHeader->e_lfanew);
            _isPE64 = _ntHeaders32->OptionalHeader.Magic == (ushort)OptionalHeaderMagic.PE32Plus;

            _fileHeader = _isPE64 ? &_ntHeaders64->FileHeader : &_ntHeaders32->FileHeader;

            _header32 = &_ntHeaders32->OptionalHeader;
            _header64 = &_ntHeaders64->OptionalHeader;
            _sections = new IMAGE_SECTION_HEADER[_fileHeader->NumberOfSections];

            var offset = _isPE64 ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32);
            fixed (void* sections = _sections) {
                Buffer.MemoryCopy((byte*)_ntHeaders32 + offset, sections, _sections.Length * sizeof(IMAGE_SECTION_HEADER), _sections.Length * sizeof(IMAGE_SECTION_HEADER));
            }

            FileHeader = new FileHeader(_fileHeader);
            if (IsPE64)
                OptionalHeader = new OptionalHeader(_header64);
            else
                OptionalHeader = new OptionalHeader(_header32);

            _workBuffer = Marshal.AllocCoTaskMem(1 << 12);
        }

        public uint Signature => _ntHeaders32->Signature;

        public T Read<T>(int offset) where T : struct {
            var p = _address + offset;
            Buffer.MemoryCopy(p, _workBuffer.ToPointer(), Marshal.SizeOf<T>(), Marshal.SizeOf<T>());
            return (T)Marshal.PtrToStructure(_workBuffer, typeof(T));
        }

        public void Read(int offset, int size, void* buffer) {
            var p = _address + offset;
            Buffer.MemoryCopy(p, buffer, size, size);
        }

        public void ReadArray<T>(int offset, T[] buffer, int startIndex, int count) where T : struct {
            var p = _address + offset;
            var h = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            var dst = Marshal.UnsafeAddrOfPinnedArrayElement(buffer, startIndex);
            Buffer.MemoryCopy(p, dst.ToPointer(), count * Marshal.SizeOf<T>(), count * Marshal.SizeOf<T>());
            h.Free();
        }

        public void ReadArray<T>(int offset, T[] buffer) where T : struct {
            ReadArray<T>(offset, buffer, 0, buffer.Length);
        }

        public int RvaToFileOffset(int rva) {
            for (int i = 0; i < _sections.Length; ++i) {
                if (rva >= _sections[i].VirtualAddress && rva < _sections[i].VirtualAddress + _sections[i].VirtualSize)
                    return _sections[i].PointerToRawData + rva - _sections[i].VirtualAddress;
            }

            return rva;
        }

        ImportedSymbol GetSymbolFromImport(int pointer) {
            bool pe64 = IsPE64;
            var ordinal = -1;
            var nameRva = 0;
            if (pe64) {
                var lvalue = Read<ulong>(pointer);
                if (lvalue == 0) return null;

                var isOrdinal = (lvalue & (1UL << 63)) > 0;
                if (isOrdinal)
                    ordinal = (ushort)(lvalue & 0xffff);
                else
                    nameRva = (int)(lvalue & ((1L << 31) - 1));
            }
            else {
                var ivalue = Read<uint>(pointer);
                if (ivalue == 0) return null;
                if ((ivalue & 0x80000000) > 0)
                    ordinal = (ushort)(ivalue & 0xffff);
                else
                    nameRva = (int)(ivalue & ((1L << 31) - 1));
            }

            if (nameRva > 0) {
                var offset2 = RvaToFileOffset(nameRva);
                var hint = Read<ushort>(offset2);
                var chars = new List<byte>();
                for (; ; ) {
                    var ch = Read<byte>(offset2 + 2 + chars.Count);
                    if (ch == 0) {
                        var symbol = new ImportedSymbol {
                            Name = Encoding.ASCII.GetString(chars.ToArray()),
                            Hint = hint,
                        };
                        if (symbol.Name.Contains("@@"))
                            symbol.UndecoratedName = GetUndecoratedName(symbol.Name);
                        return symbol;
                    }
                    chars.Add(ch);
                };
            }
            return null;
        }


        public ICollection<ImportedSymbol> GetImportAddressTable() {
            var dir = OptionalHeader.ImportAddressTableDirectory;
            var offset = RvaToFileOffset(dir.VirtualAddress);
            var pe64 = IsPE64;
            var size = pe64 ? 8 : 4;
            var symbols = new List<ImportedSymbol>(16);

            var pointer = offset;
            for (; ; ) {
                var symbol = GetSymbolFromImport(pointer);
                if (symbol == null)
                    break;

                symbols.Add(symbol);
                pointer += size;
            }

            return symbols;
        }

        public unsafe ICollection<ImportedLibrary> GetImports() {
            var dir = OptionalHeader.ImportDirectory;
            if (dir.Size == 0)
                return null;

            var offset = RvaToFileOffset(dir.VirtualAddress);
            var pe64 = IsPE64;
            var size = pe64 ? 8 : 4;
            var imports = new List<ImportedLibrary>(8);

            for (; ; ) {
                var importDirectory = Read<IMAGE_IMPORT_DIRECTORY>(offset);
                if (importDirectory.ImportLookupTable == 0)
                    importDirectory.ImportLookupTable = importDirectory.ImportAddressTable;
                if (importDirectory.ImportLookupTable == 0)
                    break;

                ImportedLibrary library = null;
                var importLookupTable = RvaToFileOffset(importDirectory.ImportLookupTable);
                var hintNameTable = RvaToFileOffset(importDirectory.ImportAddressTable);
                var nameOffset = RvaToFileOffset(importDirectory.NameRva);

                var pointer = importLookupTable;
                for (; ; ) {
                    var ordinal = -1;
                    var nameRva = 0;
                    if (pe64) {
                        var lvalue = Read<ulong>(pointer);
                        if (lvalue == 0) break;

                        var isOrdinal = (lvalue & (1UL << 63)) > 0;
                        if (isOrdinal)
                            ordinal = (ushort)(lvalue & 0xffff);
                        else
                            nameRva = (int)(lvalue & ((1L << 31) - 1));
                    }
                    else {
                        var ivalue = Read<uint>(pointer);
                        if (ivalue == 0) break;
                        if ((ivalue & 0x80000000) > 0)
                            ordinal = (ushort)(ivalue & 0xffff);
                        else
                            nameRva = (int)(ivalue & ((1L << 31) - 1));
                    }

                    if (library == null) {
                        var bytes = new sbyte[128];
                        fixed (sbyte* p = bytes) {
                            ReadArray(nameOffset, bytes, 0, bytes.Length);
                            library = new ImportedLibrary {
                                LibraryName = new string(p)
                            };
                        }
                    }

                    if (nameRva > 0) {
                        var offset2 = RvaToFileOffset(nameRva);
                        var hint = Read<ushort>(offset2);
                        var chars = new List<byte>();
                        for (; ; ) {
                            var ch = Read<byte>(offset2 + 2 + chars.Count);
                            if (ch == 0) {
                                var symbol = new ImportedSymbol {
                                    Name = Encoding.ASCII.GetString(chars.ToArray()),
                                    Hint = hint,
                                };
                                if (symbol.Name.Contains("@@"))
                                    symbol.UndecoratedName = GetUndecoratedName(symbol.Name);
                                library.Symbols.Add(symbol);
                                break;
                            }
                            chars.Add(ch);
                        };
                    }

                    pointer += size;
                }
                imports.Add(library);
                library = null;

                offset += 20;
            }

            return imports;
        }

        [DllImport("dbghelp.dll", CharSet = CharSet.Unicode), SuppressUnmanagedCodeSecurity]
        internal static extern uint UnDecorateSymbolName(string name, StringBuilder undecoratedName, int length, uint flags);

        public static string GetUndecoratedName(string name, uint flags = 0) {
            var sb = new StringBuilder(128);
            if (UnDecorateSymbolName(name, sb, sb.Capacity, flags) == 0)
                return null;
            return sb.ToString();
        }

        public unsafe ICollection<ExportedSymbol> GetExports() {
            var dir = OptionalHeader.ExportDirectory;
            if (dir.Size == 0)
                return null;

            var offset = RvaToFileOffset(dir.VirtualAddress);
            var exportDirectory = Read<IMAGE_EXPORT_DIRECTORY>(offset);

            //var nameOffset = RvaToFileOffset(exportDirectory.Name);
            //var nameBuffer = stackalloc sbyte[64];
            //Read(nameOffset, 64, nameBuffer);
            //var tableName = new string(nameBuffer);

            var count = exportDirectory.NumberOfNames;
            var exports = new List<ExportedSymbol>(count);

            var namesOffset = exportDirectory.AddressOfNames != 0 ? RvaToFileOffset(exportDirectory.AddressOfNames) : 0;
            var ordinalOffset = exportDirectory.AddressOfOrdinals != 0 ? RvaToFileOffset(exportDirectory.AddressOfOrdinals) : 0;
            var functionsOffset = RvaToFileOffset(exportDirectory.AddressOfFunctions);

            var ordinalBase = exportDirectory.Base;

            var name = new sbyte[64];
            fixed (sbyte* p = name) {
                for (int i = 0; i < count; i++) {

                    //read name

                    var offset2 = Read<uint>(namesOffset + i * 4);
                    var offset3 = RvaToFileOffset((int)offset2);
                    ReadArray(offset3, name, 0, name.Length);
                    var functionName = new string(p);

                    // read ordinal

                    var ordinal = Read<ushort>(ordinalOffset + i * 2) + ordinalBase;

                    // read function address

                    string forwarder = null;
                    var address = Read<uint>(functionsOffset + i * 4);
                    var fileAddress = RvaToFileOffset((int)address);
                    if (fileAddress > dir.VirtualAddress && fileAddress < dir.VirtualAddress + dir.Size) {
                        // forwarder
                        ReadArray(RvaToFileOffset((int)address), name, 0, name.Length);
                        forwarder = new string(p);
                    }

                    exports.Add(new ExportedSymbol {
                        Name = functionName,
                        Ordinal = ordinal,
                        Address = address,
                        ForwardName = forwarder,
                        UndecoratedName = forwarder == null ? GetUndecoratedName(functionName) : string.Empty
                    });
                }
            }

            return exports;
        }

        internal IMAGE_LOAD_CONFIG_DIRECTORY32 GetLoadConfigDirectory32() {
            var dir = OptionalHeader.LoadConfigurationDirectory;
            var offset = RvaToFileOffset(dir.VirtualAddress);

            var configDirectory = Read<IMAGE_LOAD_CONFIG_DIRECTORY32>(offset);

            return configDirectory;
        }

        internal IMAGE_LOAD_CONFIG_DIRECTORY64 GetLoadConfigDirectory64() {
            var dir = OptionalHeader.LoadConfigurationDirectory;
            var offset = RvaToFileOffset(dir.VirtualAddress);

            var configDirectory = Read<IMAGE_LOAD_CONFIG_DIRECTORY64>(offset);
            return configDirectory;
        }

        public LoadConfiguration GetLoadConfiguration() {
            LoadConfiguration loadConfig;
            if (Environment.Is64BitProcess) {
                var config64 = GetLoadConfigDirectory64();
                loadConfig = new LoadConfiguration(this, ref config64);
            }
            else {
                var config32 = GetLoadConfigDirectory32();
                loadConfig = new LoadConfiguration(this, ref config32);
            }


            return loadConfig;
        }

        public DebugInformation GetDebugInformation() {
            var dir = OptionalHeader.DebugDirectory;
            if (dir.Size == 0)
                return null;    // no debug information

            var offset = RvaToFileOffset(dir.VirtualAddress);
            var debugDirectory = Read<IMAGE_DEBUG_DIRECTORY>(offset);
            // sanity check
            Debug.Assert(debugDirectory.Characteristics == 0);

            var debugInfo = new DebugInformation(debugDirectory);
            return debugInfo;
        }

        public ICollection<SectionHeader> GetSectionHeaders() {
            return _sections.Select(s => new SectionHeader(s)).ToList();
        }

        public void Dispose() {
            Marshal.FreeCoTaskMem(_workBuffer);
            if (_memFile != null) {
                Win32.UnmapViewOfFile(_address);
                _memFile.Dispose();
            }
        }
    }
}
