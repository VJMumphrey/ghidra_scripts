//Find the Go packages using the string "go:itab.*github.com" delimiter 
//@author
//@category Strings
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.util.Msg;

public class FilterGoStrings extends GhidraScript {

    private static final String SEARCH_PATTERN = "go:itab.*github.com"; // Define the pattern to search for

    protected void run() throws Exception {
        // Retrieve the Listing object for accessing code units (strings) in the program
        Listing listing = currentProgram.getListing();

        // Iterate over all code units in the program
        for (CodeUnit codeUnit : listing.getCodeUnits(true)) {
            // Check if the code unit is a string
            String str = codeUnit.getComment(CodeUnit.EOL_COMMENT); // Get the string from the code unit comment
            if (str != null && str.contains(SEARCH_PATTERN)) {
                Address address = codeUnit.getMinAddress();
                println("Pattern found at address: " + address + " - " + str);
            }
        }

        // Check memory blocks
        Memory memory = currentProgram.getMemory();
        for (MemoryBlock block : memory.getBlocks()) {
            Address start = block.getStart();
            Address end = block.getEnd();
            Address address = start;

            // Read and check bytes within the memory block
            while (address.compareTo(end) <= 0) {
                String str = getStringAt(address);
                if (str != null && str.contains(SEARCH_PATTERN)) {
                    println("Pattern found in memory block at address: " + address + " - " + str);
                }
                address = address.add(1000); // Move forward by 1000 bytes
            }
        }
    }

    private String getStringAt(Address address) {
        try {
            // Read bytes from memory; adjust size if needed
            byte[] bytes = new byte[1000]; // Buffer to store bytes
            int length = currentProgram.getMemory().getBytes(address, bytes); // Read bytes into buffer
            if (length <= 0) {
                return null;
            }
            return new String(bytes, 0, length).trim(); // Convert bytes to string
        } catch (MemoryAccessException e) {
            // Handle memory access exceptions
            Msg.error(this, "Failed to read memory at " + address + ": " + e.getMessage());
            return null;
        }
    }
}

