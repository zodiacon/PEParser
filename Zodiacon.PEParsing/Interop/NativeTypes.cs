using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static Zodiacon.PEParsing.Win32;

namespace Zodiacon.PEParsing.Interop {
    [StructLayout(LayoutKind.Explicit, Size = 64)]
    internal struct IMAGE_DOS_HEADER {
        public const short IMAGE_DOS_SIGNATURE = 0x5A4D;       // MZ 
        [FieldOffset(0)]
        public short e_magic;
        [FieldOffset(60)]
        public int e_lfanew;            // Offset to the IMAGE_FILE_HEADER
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct IMAGE_NT_HEADERS32 {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct IMAGE_NT_HEADERS64 {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct IMAGE_DATA_DIRECTORY {
        public int VirtualAddress;
        public int Size;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct IMAGE_FILE_HEADER {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    public enum OptionalHeaderMagic : short {
        PE32 = 0x10b,
        PE32Plus = 0x20b,
        Rom = 0x107
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct IMAGE_OPTIONAL_HEADER32 {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public uint BaseOfData;
        public uint ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public uint SizeOfStackReserve;
        public uint SizeOfStackCommit;
        public uint SizeOfHeapReserve;
        public uint SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        public unsafe fixed int DataDirectory[32];
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct IMAGE_OPTIONAL_HEADER64 {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        public unsafe fixed int DataDirectory[32];
    }

    [StructLayout(LayoutKind.Sequential)]
    unsafe internal struct IMAGE_SECTION_HEADER {
        public string Name {
            get {
                fixed (byte* ptr = NameBytes) {
                    if (ptr[7] == 0)
                        return System.Runtime.InteropServices.Marshal.PtrToStringAnsi((IntPtr)ptr);
                    else
                        return System.Runtime.InteropServices.Marshal.PtrToStringAnsi((IntPtr)ptr, 8);
                }
            }
        }
        public fixed byte NameBytes[8];
        public int VirtualSize;
        public int VirtualAddress;
        public int SizeOfRawData;
        public int PointerToRawData;
        public int PointerToRelocations;
        public int PointerToLinenumbers;
        public short NumberOfRelocations;
        public short NumberOfLinenumbers;
        public uint Characteristics;
    };

    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGE_DEBUG_DIRECTORY {
        public int Characteristics;
        public int TimeDateStamp;
        public short MajorVersion;
        public short MinorVersion;
        public IMAGE_DEBUG_TYPE Type;
        public int SizeOfData;
        public int AddressOfRawData;
        public int PointerToRawData;
    };

    internal enum IMAGE_DEBUG_TYPE {
        UNKNOWN = 0,
        COFF = 1,
        CODEVIEW = 2,
        FPO = 3,
        MISC = 4,
        BBT = 10,
    };

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_LOAD_CONFIG_DIRECTORY32 {
        public uint Size;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint GlobalFlagsClear;
        public uint GlobalFlagsSet;
        public uint CriticalSectionDefaultTimeout;
        public uint DeCommitFreeBlockThreshold;
        public uint DeCommitTotalFreeThreshold;
        public uint LockPrefixTable;
        public uint MaximumAllocationSize;
        public uint VirtualMemoryThreshold;
        public uint ProcessAffinityMask;
        public uint ProcessHeapFlags;
        public ushort CSDVersion;
        public ushort Reserved1;
        public uint EditList;
        public uint SecurityCookie;
        public uint SEHandlerTable;
        public uint SEHandlerCount;
        public uint GuardCFCheckFunctionPointer;       // VA
        public uint GuardCFDispatchFunctionPointer;    // VA
        public uint GuardCFFunctionTable;              // VA
        public uint GuardCFFunctionCount;
        public ControlFlowGuardFlags GuardFlags;

        internal IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
        ulong GuardAddressTakenIatEntryTable; // VA
        ulong GuardAddressTakenIatEntryCount;
        ulong GuardLongJumpTargetTable;       // VA
        ulong GuardLongJumpTargetCount;
        ulong DynamicValueRelocTable;         // VA
        ulong HybridMetadataPointer;          // VA
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY {
        public ushort Flags;
        public ushort Catalog;
        public uint CatalogOffset;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_LOAD_CONFIG_DIRECTORY64 {
        public uint Size;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint GlobalFlagsClear;
        public uint GlobalFlagsSet;
        public uint CriticalSectionDefaultTimeout;
        public ulong DeCommitFreeBlockThreshold;
        public ulong DeCommitTotalFreeThreshold;
        public ulong LockPrefixTable;
        public ulong MaximumAllocationSize;
        public ulong VirtualMemoryThreshold;
        public ulong ProcessAffinityMask;
        public uint ProcessHeapFlags;
        public ushort CSDVersion;
        public ushort Reserved1;
        public ulong EditList;
        public ulong SecurityCookie;
        public ulong SEHandlerTable;
        public ulong SEHandlerCount;
        public ulong GuardCFCheckFunctionPointer;       // VA
        public ulong GuardCFDispatchFunctionPointer;    // VA
        public ulong GuardCFFunctionTable;              // VA
        public ulong GuardCFFunctionCount;
        public ControlFlowGuardFlags GuardFlags;

        public IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
        uint GuardAddressTakenIatEntryTable; // VA
        uint GuardAddressTakenIatEntryCount;
        uint GuardLongJumpTargetTable;       // VA
        uint GuardLongJumpTargetCount;
        uint DynamicValueRelocTable;         // VA
        uint HybridMetadataPointer;          // VA
    }

}
