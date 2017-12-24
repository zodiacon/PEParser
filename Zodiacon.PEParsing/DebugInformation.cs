using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Zodiacon.PEParsing {
    public sealed class DebugInformation {
        readonly IMAGE_DEBUG_DIRECTORY _directory;

        internal DebugInformation(IMAGE_DEBUG_DIRECTORY directory) {
            _directory = directory;
        }

        public uint TimeDateStamp => _directory.TimeDateStamp;
        public ushort MajorVersion => _directory.MajorVersion;
        public ushort MinorVersion => _directory.MinorVersion;
        public uint SizeOfData => _directory.SizeOfData;
        public uint AddressOfRawData => _directory.AddressOfRawData;
        public uint PointerToRawData => _directory.PointerToRawData;
        public ImageDebugType DebugType => _directory.Type;
    }
}
