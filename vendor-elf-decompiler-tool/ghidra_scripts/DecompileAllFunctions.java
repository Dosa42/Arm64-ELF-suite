// Deterministically export every Ghidra-discovered function and instruction.
// @category VendorELF

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class DecompileAllFunctions extends GhidraScript {
    private static String oneLine(String value) {
        if (value == null) {
            return "";
        }
        return value.replace('\t', ' ').replace('\r', ' ').replace('\n', ' ');
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            out.append(String.format("%02x", value & 0xff));
        }
        return out.toString();
    }

    private static BufferedWriter writer(Path path) throws IOException {
        return Files.newBufferedWriter(
            path,
            StandardCharsets.UTF_8,
            StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING,
            StandardOpenOption.WRITE
        );
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4) {
            throw new IllegalArgumentException(
                "Expected: <output-directory> <input-sha256> <input-relative-path> <tool-version>"
            );
        }

        Path outputDirectory = Paths.get(args[0]).toAbsolutePath().normalize();
        String inputSha256 = args[1];
        String inputRelativePath = args[2];
        String toolVersion = args[3];
        Files.createDirectories(outputDirectory);

        Path decompiledPath = outputDirectory.resolve("decompiled.c");
        Path functionsPath = outputDirectory.resolve("functions.tsv");
        Path failuresPath = outputDirectory.resolve("decompilation-failures.tsv");
        Path warningsPath = outputDirectory.resolve("decompilation-warnings.tsv");
        Path disassemblyPath = outputDirectory.resolve("disassembly.tsv");
        Path summaryPath = outputDirectory.resolve("summary.properties");
        Path completePath = outputDirectory.resolve(".complete");
        Files.deleteIfExists(completePath);

        int functionCount = 0;
        int decompiledCount = 0;
        int externalCount = 0;
        int failureCount = 0;
        int warningCount = 0;
        long instructionCount = 0;

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");

        if (!decompiler.openProgram(currentProgram)) {
            throw new IOException("Ghidra decompiler could not open the imported program");
        }

        try (
            BufferedWriter source = writer(decompiledPath);
            BufferedWriter functions = writer(functionsPath);
            BufferedWriter failures = writer(failuresPath);
            BufferedWriter warnings = writer(warningsPath)
        ) {
            source.write("/* Input: " + oneLine(inputRelativePath) + " */\n");
            source.write("/* SHA-256: " + oneLine(inputSha256) + " */\n");
            source.write("/* Ghidra language: " + oneLine(currentProgram.getLanguageID().toString()) + " */\n\n");

            functions.write("entry\tname\tnamespace\texternal\tthunk\tbody\tstatus\n");
            failures.write("entry\tname\terror\n");
            warnings.write("entry\tname\twarning\n");

            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                Function function = iterator.next();
                functionCount++;

                String entry = function.getEntryPoint().toString();
                String name = function.getName();
                String namespace = function.getParentNamespace().getName(true);
                AddressSetView body = function.getBody();
                String bodyText = body == null ? "" : body.toString();

                MemoryBlock entryBlock = currentProgram.getMemory().getBlock(function.getEntryPoint());
                boolean externalLike = function.isExternal() ||
                    (entryBlock != null && "EXTERNAL".equals(entryBlock.getName()));
                if (externalLike) {
                    externalCount++;
                    functions.write(
                        entry + "\t" + oneLine(name) + "\t" + oneLine(namespace) +
                        "\ttrue\t" + function.isThunk() + "\t" + oneLine(bodyText) +
                        "\texternal\n"
                    );
                    continue;
                }

                String[] styles = { "decompile", "normalize", "register", "firstpass" };
                String decompiledC = "";
                String selectedStyle = "";
                StringBuilder errors = new StringBuilder();
                boolean fatalOutputSeen = false;
                boolean selectedHasWarning = false;
                boolean decompileSucceeded = false;
                for (String style : styles) {
                    decompiler.setSimplificationStyle(style);
                    DecompileResults result = decompiler.decompileFunction(function, 0, monitor);
                    DecompiledFunction decompiled = result.getDecompiledFunction();
                    String candidateC = decompiled == null ? "" : decompiled.getC();
                    boolean candidateHasWarning = candidateC.contains("/* WARNING:");
                    boolean candidateFatal = candidateC.contains("halt_baddata(") ||
                        candidateC.contains("Bad instruction - Truncating control flow here") ||
                        candidateC.contains("Control flow encountered bad instruction data");
                    if (result.decompileCompleted() && decompiled != null &&
                        !candidateC.isBlank() && !candidateFatal) {
                        decompiledC = candidateC;
                        selectedStyle = style;
                        selectedHasWarning = candidateHasWarning;
                        decompileSucceeded = true;
                        break;
                    }
                    if (!candidateC.isEmpty() && decompiledC.isEmpty()) {
                        decompiledC = candidateC;
                    }
                    fatalOutputSeen = fatalOutputSeen || candidateFatal;
                    if (errors.length() > 0) {
                        errors.append(" | ");
                    }
                    errors.append(style).append(": ");
                    errors.append(candidateFatal
                        ? "output contains fatal bad-instruction/truncated-control-flow marker"
                        : oneLine(result.getErrorMessage()));
                    decompiler.flushCache();
                }

                if (decompileSucceeded) {
                    decompiledCount++;
                    if (selectedHasWarning) {
                        warningCount++;
                        warnings.write(
                            entry + "\t" + oneLine(name) +
                            "\tDecompiler produced C with nonfatal WARNING comments; see decompiled.c and raw-ghidra.log\n"
                        );
                    }
                    functions.write(
                        entry + "\t" + oneLine(name) + "\t" + oneLine(namespace) +
                        "\tfalse\t" + function.isThunk() + "\t" + oneLine(bodyText) +
                        "\tdecompiled_" + selectedStyle +
                        (selectedHasWarning ? "_with_warning" : "") + "\n"
                    );
                    source.write("/* Function " + oneLine(name) + " @ " + entry + " */\n");
                    source.write(decompiledC);
                    source.write("\n\n");
                }
                else {
                    failureCount++;
                    String error = oneLine(errors.toString());
                    functions.write(
                        entry + "\t" + oneLine(name) + "\t" + oneLine(namespace) +
                        "\tfalse\t" + function.isThunk() + "\t" + oneLine(bodyText) +
                        "\t" + (fatalOutputSeen ? "failed_with_fatal_output" : "failed") + "\n"
                    );
                    failures.write(entry + "\t" + oneLine(name) + "\t" + error + "\n");
                    if (!decompiledC.isEmpty()) {
                        source.write("/* Function " + oneLine(name) + " @ " + entry + " */\n");
                        source.write(decompiledC);
                        source.write("\n\n");
                    }
                    else {
                        source.write(
                            "/* DECOMPILATION FAILED: " + oneLine(name) + " @ " + entry +
                            ": " + error + " */\n\n"
                        );
                    }
                }
            }
        }
        finally {
            decompiler.flushCache();
            decompiler.dispose();
        }

        try (BufferedWriter disassembly = writer(disassemblyPath)) {
            disassembly.write("address\tbytes\tinstruction\n");
            InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
            while (instructions.hasNext()) {
                monitor.checkCancelled();
                Instruction instruction = instructions.next();
                instructionCount++;
                String instructionBytes;
                try {
                    instructionBytes = hex(instruction.getBytes());
                }
                catch (Exception error) {
                    instructionBytes = "<unavailable:" + oneLine(error.getMessage()) + ">";
                }
                disassembly.write(
                    instruction.getAddress().toString() + "\t" + instructionBytes + "\t" +
                    oneLine(instruction.toString()) + "\n"
                );
            }
        }

        boolean complete = failureCount == 0 && (functionCount > externalCount || instructionCount > 0);
        try (BufferedWriter summary = writer(summaryPath)) {
            summary.write("input_path=" + oneLine(inputRelativePath) + "\n");
            summary.write("input_sha256=" + oneLine(inputSha256) + "\n");
            summary.write("tool_version=" + oneLine(toolVersion) + "\n");
            summary.write("language=" + oneLine(currentProgram.getLanguageID().toString()) + "\n");
            summary.write("compiler_spec=" + oneLine(currentProgram.getCompilerSpec().getCompilerSpecID().toString()) + "\n");
            summary.write("image_base=" + currentProgram.getImageBase().toString() + "\n");
            summary.write("functions_total=" + functionCount + "\n");
            summary.write("functions_decompiled=" + decompiledCount + "\n");
            summary.write("functions_external=" + externalCount + "\n");
            summary.write("functions_failed=" + failureCount + "\n");
            summary.write("functions_with_warnings=" + warningCount + "\n");
            summary.write("instructions=" + instructionCount + "\n");
            summary.write("complete=" + complete + "\n");
        }

        if (complete) {
            Files.writeString(
                completePath,
                inputSha256 + "\t" + toolVersion + "\n",
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE
            );
        }
        else {
            throw new IOException(
                "Decompilation incomplete: functions=" + functionCount +
                ", external=" + externalCount +
                ", failed=" + failureCount +
                ", instructions=" + instructionCount
            );
        }
    }
}
