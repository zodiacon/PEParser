using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Zodiacon.PEParsing.Interop;
using static Zodiacon.PEParsing.Win32;

namespace Zodiacon.PEParsing {
    public unsafe sealed class OptionalHeader {
        readonly IMAGE_OPTIONAL_HEADER32* _header32;
        readonly IMAGE_OPTIONAL_HEADER64* _header64;

        internal OptionalHeader(IMAGE_OPTIONAL_HEADER32* header) {
            _header32 = header;
        }

        internal OptionalHeader(IMAGE_OPTIONAL_HEADER64* header) {
            _header64 = header;
        }

        public OptionalHeaderMagic Magic => (OptionalHeaderMagic)(_header32 == null ? _header64->Magic : _header32->Magic);
        public byte MajorLinkerVersion => _header32 == null ? _header64->MajorLinkerVersion : _header32->MajorLinkerVersion;
        public byte MinorLinkerVersion => _header32 == null ? _header64->MinorLinkerVersion : _header32->MinorLinkerVersion;
        public uint SizeOfCode => _header32 == null ? _header64->SizeOfCode : _header32->SizeOfCode;
        public uint SizeOfInitializedData => _header32 == null ? _header64->SizeOfInitializedData : _header32->SizeOfInitializedData;
        public uint SizeOfUninitializedData => _header32 == null ? _header64->SizeOfUninitializedData : _header32->SizeOfUninitializedData;
        public uint AddressOfEntryPoint => _header32 == null ? _header64->AddressOfEntryPoint : _header32->AddressOfEntryPoint;
        public uint BaseOfCode => _header32 == null ? _header64->BaseOfCode: _header32->BaseOfCode;
        public ulong ImageBase => _header32 == null ? _header64->ImageBase : _header32->ImageBase;
        public uint SectionAlignment => _header32 == null ? _header64->SectionAlignment : _header32->SectionAlignment;
        public uint FileAlignment => _header32 == null ? _header64->FileAlignment : _header32->FileAlignment;
        public ushort MajorOperatingSystemVersion => _header32 == null ? _header64->MajorOperatingSystemVersion : _header32->MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion => _header32 == null ? _header64->MinorOperatingSystemVersion : _header32->MinorOperatingSystemVersion;
        public ushort MajorImageVersion => _header32 == null ? _header64->MajorImageVersion : _header32->MajorImageVersion;
        public ushort MinorImageVersion => _header32 == null ? _header64->MinorImageVersion : _header32->MinorImageVersion;
        public ushort MajorSubsystemVersion => _header32 == null ? _header64->MajorSubsystemVersion : _header32->MajorSubsystemVersion;
        public ushort MinorSubsystemVersion => _header32 == null ? _header64->MinorSubsystemVersion : _header32->MinorSubsystemVersion;
        public uint Win32VersionValue => _header32 == null ? _header64->Win32VersionValue : _header32->Win32VersionValue;
        public uint SizeOfImage => _header32 == null ? _header64->SizeOfImage : _header32->SizeOfImage;
        public uint SizeOfHeaders => _header32 == null ? _header64->SizeOfHeaders : _header32->SizeOfHeaders;
        public uint CheckSum => _header32 == null ? _header64->CheckSum : _header32->CheckSum;
        public SubsystemType Subsystem => (SubsystemType)(_header32 == null ? _header64->Subsystem : _header32->Subsystem);
        public DllCharacteristics DllCharacteristics => (DllCharacteristics)(_header32 == null ? _header64->DllCharacteristics: _header32->DllCharacteristics);
        public ulong SizeOfStackReserve => _header32 == null ? _header64->SizeOfStackReserve : _header32->SizeOfStackReserve;
        public ulong SizeOfStackCommit => _header32 == null ? _header64->SizeOfStackCommit : _header32->SizeOfStackCommit;
        public ulong SizeOfHeapReserve => _header32 == null ? _header64->SizeOfHeapReserve : _header32->SizeOfHeapReserve;
        public ulong SizeOfHeapCommit => _header32 == null ? _header64->SizeOfHeapCommit : _header32->SizeOfHeapCommit;
        public uint LoaderFlags => _header32 == null ? _header64->LoaderFlags : _header32->LoaderFlags;
        public uint NumberOfRvaAndSizes => _header32 == null ? _header64->NumberOfRvaAndSizes : _header32->NumberOfRvaAndSizes;

        public DataDirectory DataDirectory(int index) {
            var rva = _header32 == null ? _header64->DataDirectory[index * 2] : _header32->DataDirectory[index * 2];
            var size = _header32 == null ? _header64->DataDirectory[index * 2 + 1] : _header32->DataDirectory[index * 2 + 1];
            return new DataDirectory {
                VirtualAddress = rva,
                Size = size
            };
        }

        public bool IsManaged => DataDirectory(DataDirectoryType.ComDescriptor).VirtualAddress != 0;

        public DataDirectory DataDirectory(DataDirectoryType type) => DataDirectory((int)type);

        public DataDirectory ImportAddressTableDirectory => DataDirectory(DataDirectoryType.ImportAddressTable);
        public DataDirectory ImportDirectory => DataDirectory(DataDirectoryType.Import);
        public DataDirectory ExportDirectory => DataDirectory(DataDirectoryType.Export);
        public DataDirectory LoadConfigurationDirectory => DataDirectory(DataDirectoryType.LoadConfiguration);
        public DataDirectory ResourceDirectory => DataDirectory(DataDirectoryType.Resource);
        public DataDirectory DebugDirectory => DataDirectory(DataDirectoryType.Debug);
        public DataDirectory ExceptionDirectory => DataDirectory(DataDirectoryType.Exception);
        public DataDirectory ComDescriptorDirectory => DataDirectory(DataDirectoryType.ComDescriptor);
        public DataDirectory ThreadLocalStorageDirectory => DataDirectory(DataDirectoryType.ThreadLocalStorage);
        public DataDirectory BaseRelocationDirectory => DataDirectory(DataDirectoryType.BaseRelocation);
        public DataDirectory DelayImportDirectory => DataDirectory(DataDirectoryType.DelayImport);
        public DataDirectory BoundImportDirectory => DataDirectory(DataDirectoryType.BoundImport);
        public DataDirectory ArchitectureDirectory => DataDirectory(DataDirectoryType.Architecture);
        public DataDirectory CertificatesDirectory => DataDirectory(DataDirectoryType.Security);
        public DataDirectory GlobalPointerDirectory => DataDirectory(DataDirectoryType.GlobalPointer);

    }
}
