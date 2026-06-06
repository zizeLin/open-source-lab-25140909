import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;

public class ExportDecompile extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File output = new File(args.length > 0 ? args[0] : "ghidra-decompile.txt");
        String addressText = args.length > 1 ? args[1] : "0x401264";

        Address address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addressText);
        Function function = getFunctionContaining(address);

        try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(new FileOutputStream(output), "UTF-8"))) {
            if (function == null) {
                writer.println("No function found at " + addressText);
                return;
            }

            writer.println("Function: " + function.getName());
            writer.println("Entry: " + function.getEntryPoint());

            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(currentProgram);
            DecompileResults results = decompiler.decompileFunction(function, 60, monitor);

            if (results.decompileCompleted()) {
                writer.println(results.getDecompiledFunction().getC());
            } else {
                writer.println("Decompile failed: " + results.getErrorMessage());
            }
            decompiler.dispose();
        }
    }
}
