using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Zodiacon.PEParsing.Interop;

namespace Zodiacon.PEParsing {
	public sealed class SectionHeader {
		IMAGE_SECTION_HEADER _header;
		internal SectionHeader(IMAGE_SECTION_HEADER header) {
			_header = header;
		}

		public string Name => _header.Name;
		public int VirtualSize => _header.VirtualSize;
		public int VirtualAddress => _header.VirtualAddress;
		public int SizeOfRawData => _header.SizeOfRawData;
		public int PointerToRawData => _header.PointerToRawData;
		public int PointerToRelocations => _header.PointerToRelocations;
		public int PointerToLineNumbers => _header.PointerToLinenumbers;

		public short NumberOfRelocations => _header.NumberOfRelocations;
		public short NumberOfLineNumbers => _header.NumberOfLinenumbers;
		public SectionFlags Characteristics => (SectionFlags)_header.Characteristics;

	}
}
