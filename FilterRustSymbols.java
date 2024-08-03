//Demangle Rust Packages using the _ZN package name structure.
//@author 
//@category Demangler
//@keybinding 
//@menupath 
//@toolbar 

// Import Ghidra classes
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolIterator;

import java.util.HashSet;
import java.util.Set;

/**
 * Script to find all symbol names in a Rust binary and filter out those starting with _ZN.
 */
public class FilterRustSymbols extends GhidraScript {

    protected void run() throws Exception {
        // Get the Symbol Table from the current program
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        
        // Get all symbols using SymbolIterator
        SymbolIterator symbolIterator = symbolTable.getAllSymbols(true);
        
        // A set to keep track of unique filtered symbol names
        Set<String> filteredSymbols = new HashSet<>();
        
        // Iterate through all symbols
        while (symbolIterator.hasNext()) {
            Symbol symbol = symbolIterator.next();
            
            // Get the name of the symbol
            String symbolName = symbol.getName();
            
            // Check if the symbol name starts with "_ZN"
            if (symbolName.startsWith("_ZN")) {
                filteredSymbols.add(symbolName);
            }
        }
        
        // Output the filtered symbol names to the Ghidra console
        println("Filtered symbols starting with _ZN:");
        for (String name : filteredSymbols) {
            println(name);
        }
    }
}

