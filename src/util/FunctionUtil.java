package util;

import base.ExecutionPath;
import core.ExecutionEngine;
import core.ExecutionPathFinder;
import core.STRInsSolver;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.DataConverter;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import main.Constant;
import main.Logger;

import java.util.*;
import java.util.concurrent.TimeUnit;

public class FunctionUtil {

    // locate Nordic functions
    public static Map<Integer, List<Address>> locate_nordic(Program program) {
        FunctionIterator funcs = getAllFunctions(program);
        Map<Integer, List<Address>> results = new HashMap<>();

        Listing listing = program.getListing();
        for (Function fun: funcs) {
            // Logger.print(String.format("%s, %s", fun.getName(), fun.getEntryPoint()));
            AddressIterator addressIterator = fun.getBody().getAddresses(true);
            for (Address address: addressIterator) {
                Instruction inst = listing.getInstructionAt(address);
                if (inst == null)
                    continue;
                else{
                    String mnem = InstructionUtil.removePostfix(inst.getMnemonicString());

                    if (InstructionUtil.isSTRInstruction(mnem) || InstructionUtil.isMultipleSTRInstruction(mnem)) {
                        STRInsSolver.addIns(address);
                    } else if (inst.getMnemonicString().equals("svc")) {
                        // Logger.print(String.format("%s, %s", inst.getMnemonicString(), inst));
                        for (int i = 0; i < inst.getNumOperands(); ++i) {
                            Object[] operands = inst.getOpObjects(i);
                            Scalar op = (Scalar) operands[0];
                            int value = (int) op.getValue();
                            if (Constant.NORDIC_FUNCTIONS.contains(value)) {
                                Logger.print(value + "\t" + address);
                                addIntoMap(results, value, address);
                            }
                        }
                    }
                }
            }
        }
        return results;
    }


    // locate TI functions
    public static Map<Integer, List<Address>> locate_TI(Program program) {
        FunctionIterator funcs = getAllFunctions(program);
        Map<Integer, List<Address>> results = new HashMap<>();

        Listing listing = program.getListing();
        for (Function fun: funcs) {
            Logger.print(String.format("%s, %s", fun.getName(), fun.getEntryPoint()));
            AddressIterator addressIterator = fun.getBody().getAddresses(true);
            for (Address address: addressIterator) {
                Instruction inst = listing.getInstructionAt(address);
                if (inst == null)
                    continue;
                else{
                    String mnem = InstructionUtil.removePostfix(inst.getMnemonicString());

                    if (InstructionUtil.isSTRInstruction(mnem) || InstructionUtil.isMultipleSTRInstruction(mnem)) {
                        STRInsSolver.addIns(address);
                    } else if (mnem.equals("mov")) {
                        int type = inst.getOperandType(1);
                        if (inst.getOperandType(1) == OperandType.SCALAR || inst.getOperandType(1) == OperandType.DYNAMIC ) {
                            Register reg = (Register) inst.getOpObjects(0)[0];
                            Scalar constant = (Scalar) inst.getOpObjects(1)[0];

                            int value = (int) constant.getValue();
                            if (Constant.TI_FUNCTIONS.contains(value)) {
                                if (reg.getName().equals("r1") && (value == Constant.TI_DEVICE_ADDR || value == Constant.TI_REGISTER_SERVICE)) {
                                    // static address API
                                    Logger.print(value + "\t" + address);
                                    addIntoMap(results, value, address);
                                }
                                else if (reg.getName().equals("r2")) {
                                    // pairing APIs
                                    Logger.print(value + "\t" + address);
                                    addIntoMap(results, value, address);
                                }
                            }
                        }

                    }
                }
            }
        }
        return results;
    }


    public static List<Long> findAllImmediateInLDR(Program program) {
        List<Long> results = new ArrayList<>();

        TaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(Constant.DISASSEMBLE_TIMEOUT, TimeUnit.SECONDS);
        Disassembler disassembler = Disassembler.getDisassembler(program, monitor, null);
        Listing listing = program.getListing();
        Address current = program.getMinAddress();
        long length = program.getMaxAddress().getUnsignedOffset();

        while (current.getUnsignedOffset() < length) {
            Instruction inst = listing.getInstructionAt(current);
            if (inst == null) {
                // try to disassemble
                try {
                    AddressSetView addressSetView = disassembler.disassemble(current, new AddressSet(current));
                } catch (Exception e) {
                    current = current.add(2);
                    continue;
                }

                inst = listing.getInstructionAt(current);
                if (inst == null) {
                    current = current.add(2);
                    continue;
                }
            }
            if (InstructionUtil.isLDRInstruction(inst.getMnemonicString())) {
                if (inst.getOpObjects(1).length == 1) {
                    if (inst.getOpObjects(1)[0] instanceof Address) {
                        Address add = (Address) (inst.getOpObjects(1)[0]);
                        try {
                            long val = (long) program.getMemory().getInt(add);
                            if (val < 0) {
                                // overflow
                                byte[] bytes = new byte[8];
                                int len = program.getMemory().getBytes(add, bytes, 0, 4);
                                val = DataConverter.getInstance(false).getLong(bytes);
                            }

                            if (!results.contains(val))
                                results.add(val);
                        } catch (MemoryAccessException e) {
                        }
                    }
                }
            }
            current = current.add(inst.getLength());
        }

        return results;
    }




    public static List<Long> findAllRelativeInADR(Program program) {
        List<Long> results = new ArrayList<>();

        TaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(Constant.DISASSEMBLE_TIMEOUT, TimeUnit.SECONDS);
        Disassembler disassembler = Disassembler.getDisassembler(program, monitor, null);
        Listing listing = program.getListing();
        Address current = program.getMinAddress();
        long length = program.getMaxAddress().getUnsignedOffset();

        while (current.getUnsignedOffset() < length) {
            Instruction inst = listing.getInstructionAt(current);
            if (inst == null) {
                // try to disassemble
                try {
                    AddressSetView addressSetView = disassembler.disassemble(current, new AddressSet(current));
                } catch (Exception e) {
                    current = current.add(2);
                    continue;
                }

                inst = listing.getInstructionAt(current);
                if (inst == null) {
                    current = current.add(2);
                    continue;
                }
            }
            if (InstructionUtil.isADRInstruction(inst.getMnemonicString())) {
                if (inst.getOpObjects(1).length == 1) {
                    if (inst.getOpObjects(1)[0] instanceof Scalar) {
                        long val = ((Scalar) inst.getOpObjects(1)[0]).getValue();
                        if (!results.contains(val))
                            results.add(val);
                    }
                }
            }
            current = current.add(inst.getLength());
        }

        return results;
    }



    private static void addIntoMap(Map<Integer, List<Address>> map, Integer key, Address value) {
        if (map.keySet().contains(key))
            map.get(key).add(value);
        else {
            List<Address> l = new ArrayList<>(List.of(value));
            map.put(key, l);
        }
    }

    public static FunctionIterator getAllFunctions(Program program) {
        FunctionManager functionManager = program.getFunctionManager();
        return functionManager.getFunctions(program.getMinAddress(), true);
    }


    /**
     * Given an address, find its function
     */
    public static Function findFunctionWithAddress(Program program, Address address) {
        Function fun;
        try {
            fun = program.getListing().getFunctionContaining(address);
        }
        catch (Exception e) {
            fun = null;
        }
        return fun;

    }

}
