using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Zodiacon.PEParsing {
   public sealed class ImportedSymbol {
        public string Name { get; internal set; }
        public int Hint { get; internal set; }
        public string UndecoratedName { get; internal set; }
    }
}
