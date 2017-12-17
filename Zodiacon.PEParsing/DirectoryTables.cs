using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Zodiacon.PEParsing {
    public enum DataDirectoryType {
        Export = 0,   // Export Directory
        Import = 1,   // Import Directory
        Resource = 2,   // Resource Directory
        Exception = 3,   // Exception Directory
        Security = 4,   // Security Directory
        BaseRelocation = 5,   // Base Relocation Table
        Debug = 6,   // Debug Directory
        Copyright = 7,   // (X86 usage)
        Architecture = 7,   // Architecture Specific Data
        GlobalPointer = 8,   // RVA of GP
        ThreadLocalStorage = 9,   // TLS Directory
        LoadConfiguration = 10,   // Load Configuration Directory
        BoundImport = 11,   // Bound Import Directory in headers
        ImportAddressTable = 12,   // Import Address Table
        DelayImport = 13,   // Delay Load Import Descriptors
        ComDescriptor = 14,   // COM Runtime descriptor
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_EXPORT_DIRECTORY {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public int Name;
        public int Base;
        public int NumberOfFunctions;
        public int NumberOfNames;
        public int AddressOfFunctions;     // RVA from base of image
        public int AddressOfNames;         // RVA from base of image
        public int AddressOfOrdinals;  // RVA from base of image
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_RESOURCE_DIRECTORY {
        public int Characteristics;
        public int TimeDateStamp;
        public short MajorVersion;
        public short MinorVersion;
        public ushort NumberOfNamedEntries;
        public ushort NumberOfIdEntries;
        //  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_IMPORT_DIRECTORY {
        public int ImportLookupTable;
        public int TimeDateStamp;
        public int ForwarderChain;
        public int NameRva;
        public int ImportAddressTable;
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DEBUG_DIRECTORY {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public ImageDebugType Type;
        public uint SizeOfData;
        public uint AddressOfRawData;
        public uint PointerToRawData;
    }


    public sealed class DataDirectory {
        public int VirtualAddress { get; internal set; }
        public int Size { get; internal set; }

        public override string ToString() => $"RVA: 0x{VirtualAddress:X}, Size: 0x{Size:X}";
    }
}