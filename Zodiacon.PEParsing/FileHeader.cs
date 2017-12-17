using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Zodiacon.PEParsing.Interop;

namespace Zodiacon.PEParsing {
    public unsafe sealed class FileHeader {
        readonly IMAGE_FILE_HEADER* _header;

        internal FileHeader(IMAGE_FILE_HEADER* header) {
            _header = header;
        }

        public MachineType Machine => (MachineType)_header->Machine;
        public ushort NumberOfSections => _header->NumberOfSections;
        public uint TimeDateStamp => _header->TimeDateStamp;
        public uint PointerToSymbolTable => _header->PointerToSymbolTable;
        public uint NumberOfSymbols => _header->NumberOfSymbols;

        public ushort SizeOfOptionalHeader => _header->SizeOfOptionalHeader;
        public ImageCharacteristics Characteristics => (ImageCharacteristics)_header->Characteristics;
    }
}
