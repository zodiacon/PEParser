using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Zodiacon.PEParsing {
    public sealed class ImportedLibrary {
        public string LibraryName { get; internal set; }

        public ICollection<ImportedSymbol> Symbols { get; } = new List<ImportedSymbol>(16);
    }
}
