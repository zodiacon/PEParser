using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Zodiacon.PEParsing;

namespace DumpPE {
    class Program {
        static void Main(string[] args) {
            if (args.Length == 0) {
                Console.WriteLine("Usage: dumppe [options] <filename>");
            }

            try {
                var parser = new PEParser(args.Last());
                Dump(parser);
            }
            catch (Exception ex) {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        private static void Dump(PEParser parser) {
            Console.WriteLine("File Header:");
            WriteObject(parser.FileHeader);

            Console.WriteLine();
            Console.WriteLine("Optional Header:");
            WriteObject(parser.OptionalHeader);

            Console.WriteLine();
            Console.WriteLine("Exports:");
            var exports = parser.GetExports();
            if (exports != null) {
                foreach (var export in exports) {
                    Console.WriteLine($"{export.Name} {export.Ordinal} 0x{export.Address:X}");
                }
            }

            Console.WriteLine();
            Console.WriteLine("Imports:");
            var imports = parser.GetImports();
            if (imports != null) {
                foreach (var import in imports) {
                    Console.WriteLine($"{import.LibraryName}");
                    foreach (var imp in import.Symbols)
                        Console.WriteLine($"\t{imp.Name}");
                }
            }

        }

        private static void WriteObject(object obj) {
            foreach (var pi in obj.GetType().GetProperties()) {
                Console.WriteLine($"{pi.Name}: {pi.GetValue(obj)}");
            }
        }
    }
}
