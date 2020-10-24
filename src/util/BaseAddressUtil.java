package util;

import base.ExecutionPath;
import core.ExecutionEngine;
import core.ExecutionPathFinder;
import ghidra.GhidraJarApplicationLayout;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.store.LockException;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageProvider;

import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.test.TestProgramManager;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import main.Constant;
import main.Logger;

import java.io.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class BaseAddressUtil {


    public static long getBaseAddressFromFile(String programName) {
        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader("./base/base.txt"));
            String line = reader.readLine();
            while (line != null) {
                String name = line.split("\t")[0].strip();
                if (name.equals(programName)) {
                    long address = Integer.parseInt(line.split("\t")[1]);
                    return address;
                }
                line = reader.readLine();
            }

        } catch (IOException e) {
            // not found
            Logger.printE(e.toString());
            return 0;
        }

        Logger.printE("Base not found");
        return -1;
    }

    public static boolean isBaseInFile(String tag) {
        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader("./base/base.txt"));
            String line = reader.readLine();
            while (line != null) {
                String name = line.split("\t")[0].strip();
                if (name.equals(tag)) {
                    return true;
                }
                line = reader.readLine();
            }

        } catch (IOException e) {
            // not found
            Logger.printE(e.toString());
            return false;
        }

        return false;
    }

    public static List<Long> getE7Address(Program program) {
        Address current = program.getMinAddress();
        long length = program.getMaxAddress().getUnsignedOffset();

        ArrayList<Long> result = new ArrayList<>();
        while (current.getUnsignedOffset() < length) {
            try {
                if (program.getMemory().getByte(current) == Constant.E7) {
                    result.add(current.getUnsignedOffset());
                }
            } catch (MemoryAccessException e) {

            }
            current = current.next();
        }

        return result;
    }


    public static List<Long> getFunctionEntries(Program program) {
        Address current = program.getMinAddress();
        long length = program.getMaxAddress().getUnsignedOffset();

        ArrayList<Long> entry = new ArrayList<>();
        while (current.getUnsignedOffset() < length) {
            if (isFunctionPrologue(program, current)) {
                entry.add(current.getUnsignedOffset()-1);
            }
            current = current.next();
        }
        return entry;
    }


    public static boolean isFunctionPrologue(Program program, Address current) {
        try {
            if (program.getMemory().getByte(current) == Constant.PUSH)
                return true;
            else if (program.getMemory().getByte(current) == Constant.STMFD1) {
                if (program.getMemory().getByte(current.next()) == Constant.STMFD2) {
                    return true;
                }
            }
        } catch (MemoryAccessException e) {
            return false;
        }
        return false;
    }


}
