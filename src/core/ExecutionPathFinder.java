package core;

import base.ExecutionPath;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import main.Constant;
import main.Logger;
import util.BlockUtil;
import util.FunctionUtil;
import util.InstructionUtil;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ExecutionPathFinder {

    static List<ExecutionPath> paths;
    static Program program;

    /**
     * Find all execution paths to the current address in the current function
     * @param address target address
     * @param initial initial variable set to taint
     * @return execution paths
     */
    public static List<ExecutionPath> findAllExecPaths(Program p, Address address, List<String> initial) {
        if (initial == null)
            return null;
        paths = new ArrayList<ExecutionPath>();
        program = p;
        Listing listing = program.getListing();

        CodeBlock[] codeBlocks = BlockUtil.locateBlockWithAddress(program, address);
        CodeBlock initialBlock;
        if (codeBlocks != null && codeBlocks.length != 0) {
            initialBlock = codeBlocks[0];
        }
        else {
            Logger.printW("Block not found!");
            return null;
        }
        CodeUnitIterator codeUnitIterator = listing.getCodeUnits(initialBlock, true);

        // initialize the first path
        ExecutionPath tempPath = new ExecutionPath();
        tempPath.addInst(program.getListing().getInstructionAt(address));
        tempPath.taintVariables = new ArrayList<String>(initial);

        // Iterate forward until target address is reached (in the initial block)
        List<Instruction> temp = new ArrayList<>();
        for(CodeUnit unit: codeUnitIterator) {
            if (unit.getAddress().compareTo(address) > 0) {
                break;
            }
            else {
                temp.add(listing.getInstructionAt(unit.getAddress()));
            }
        }
        for(int i=temp.size()-1; i>=0; --i) {
            if (taintDecision(temp.get(i), tempPath)) {
                tempPath.addInst(temp.get(i));
            }
        }

        if (tempPath.isTaintFinish()) // no taint variable left, end search
            paths.add(tempPath);
        else {
            // current block ends, jump to previous blocks
            List<CodeBlockReference> parentBlocks = BlockUtil.getPreviousBlocks(initialBlock);

            if (parentBlocks == null || parentBlocks.size() == 0) {
                // search ends
                paths.add(tempPath);
            } else {
                // record history
                List<Integer> history = new ArrayList<>();
                history.add((int) initialBlock.getFirstStartAddress().getUnsignedOffset());

                for (CodeBlockReference block : parentBlocks) {
                    Logger.print("Block: " + initialBlock.getName() + " -> " + block.getSourceBlock().getName());
                    dfsSearchPath(program, block.getReferent(), tempPath.clone(), block.getSourceBlock(), new ArrayList<>(history));
                }
            }
        }

        return paths;
    }

    public static void dfsSearchPath(Program program, Address startAddress, ExecutionPath currentPath, CodeBlock currentBlock, List<Integer> history) {

        if (history.size() >= Constant.MAX_CYCLE_DIVE)
            return;

        Listing listing = program.getListing();
        CodeUnitIterator codeUnitIterator = listing.getCodeUnits(currentBlock, true);

        // Logger.print(String.format("Current Block: %s %d", currentBlock.toString(), currentBlock.hashCode()) );

        // Iterate and add all instructions to path in the current block
        List<Instruction> temp = new ArrayList<>();
        for(CodeUnit unit: codeUnitIterator) {
            if (unit.getAddress().compareTo(startAddress) > 0) {
                break;
            }
            temp.add(listing.getInstructionAt(unit.getAddress()));
        }
        for(int i=temp.size()-1; i>=0; --i) {
            if (taintDecision(temp.get(i), currentPath)) {
                currentPath.addInst(temp.get(i));
                if (currentPath.isTaintFinish()) { // no taint variable left
                    paths.add(currentPath);
                    return;
                }
            }
        }

        // current block ends, jump to next blocks
        List<CodeBlockReference> parentBlocks = BlockUtil.getPreviousBlocks(currentBlock);

        if (parentBlocks == null || parentBlocks.size() == 0) {
            // search ends
            paths.add(currentPath);
        }
        else {
            for (CodeBlockReference block : parentBlocks) {

                if (history.contains((int) block.getSourceAddress().getUnsignedOffset())) {
                    // encountering cycle block, remove it, search ends
                    // paths.add(currentPath);
                    continue;
                }


//                if (BlockUtil.isCycle(currentBlock, block.getSourceBlock(), new HashSet<>())) {
//                    continue; // encountering cycle block, remove it, search ends
//                }

                // record history, continue searching in next block
                List<Integer> newHistory = new ArrayList<>(history);
                newHistory.add((int) block.getSourceAddress().getUnsignedOffset());
                Logger.print("Block: " + currentBlock.getName() + " -> " + block.getSourceBlock().getName());
                dfsSearchPath(program, block.getReferent(), currentPath.clone(), block.getSourceBlock(), newHistory);
            }
        }
    }

    public static List<Instruction> diveIntoFunction(Address startAddress, Address endAddress) {
        List<Instruction> results = new ArrayList<>();

        // initiate last block, and perform backward slicing
        CodeBlock[] codeBlocks = BlockUtil.locateBlockWithAddress(program, endAddress);
        CodeBlock currentBlock;
        if (codeBlocks != null && codeBlocks.length != 0) {
            currentBlock = codeBlocks[0];
        }
        else {
            Logger.printW("Block not found!");
            return null;
        }

        while (currentBlock.getMinAddress().compareTo(startAddress) >= 0) {

            CodeUnitIterator codeUnitIterator = program.getListing().getCodeUnits(currentBlock, true);

            // initialize the first path
            ExecutionPath tempPath = new ExecutionPath();

            // backward slicing
            List<Instruction> temp = new ArrayList<>();
            for (CodeUnit unit : codeUnitIterator)
                temp.add(program.getListing().getInstructionAt(unit.getAddress()));

            for (int i = temp.size() - 1; i >= 0; --i) {
                if (taintDecision(temp.get(i), tempPath)) {
                    tempPath.addInst(temp.get(i));
                    results.add(temp.get(i));
                }
            }

            // to next block
            List<CodeBlockReference> preBlocks = BlockUtil.getPreviousBlocks(currentBlock);
            if (preBlocks == null || preBlocks.size() == 0)
                break;
            currentBlock = preBlocks.get(0).getSourceBlock();
        }

        return results;
    }

    /**
     * Decide whether to taint this instruction, given the taint variable set
     * @return true/false
     */
    public static boolean taintDecision(Instruction ins, ExecutionPath path) {
        String mnem = ins.getMnemonicString();
        mnem = InstructionUtil.removePostfix(mnem);

        switch (mnem) {
            case "mov":
            case "movw":
            case "movs":
            case "add":
            case "sub":
            case "mul":
            case "and":
            case "bic":
            case "orr":
            case "eor":
            case "bfi":
            case "bfc":
            case "ldr":
            case "ldrb":
            case "ldrsb":
            case "ldrh":
            case "ldrsh":
            case "adr":
                Register rn = null;
                if (OperandType.isRegister(ins.getOperandType(0))) {
                    rn = (Register) ins.getOpObjects(0)[0];
                    if (!path.taintVariables.contains(rn.getName()))
                        return false; // do not need to taint
                    else {
                        if (mnem.equals("mov") || mnem.equals("movw") || InstructionUtil.isLDRInstruction(mnem))
                            path.removeTaintVariable(rn.getName()); // remove from taint variable
                        else if (ins.getNumOperands() == 3 && (mnem.equals("add") || mnem.equals("sub") || mnem.equals("mul")))
                            path.removeTaintVariable(rn.getName()); // remove from taint variable
                        else if (ins.getNumOperands() == 2) {
                            if (ins.getOpObjects(1)[0] instanceof Register) {
                                if (((Register) ins.getOpObjects(1)[0]).getName().equals("sp")) {
                                    path.removeTaintVariable(rn.getName()); // remove from taint variable
                                }
                            }
                        }
                    }
                }

                // taint all variables
                for (int i=1; i<ins.getNumOperands(); ++i) {
                    Object[] op = ins.getOpObjects(i);
                    if (OperandType.isRegister(ins.getOperandType(i))) {
                        path.addTaintVariable(((Register) op[0]).getName());
                    }
                    else if (OperandType.isAddress(ins.getOperandType(i)) || ins.getOperandType(i) == OperandType.DYNAMIC) {
                        // taint memory?
                        for (Object o: op) {
                            if (o instanceof Register)
                                path.addTaintVariable(((Register) o).getName());
                        }
                    }
                    else if (OperandType.isScalar(ins.getOperandType(i))) {
                        // constants, do not need to taint
                    }
                    else {
                        Logger.printW("Unhandled type: " + ins.getOperandType(i));
                    }
                }

                return true;

            case "ldmia":
                // op = 2
                boolean taintFlag = false;
                if (OperandType.isRegister(ins.getOperandType(0))) {
                    rn = (Register) ins.getOpObjects(0)[0];

                    Object[] ops = ins.getOpObjects(1);
                    for (Object op: ops) {
                        // remove the regs in the list
                        if (op instanceof Register) {
                            String regName = ((Register) op).getName();
                            if (path.taintVariables.contains(regName)) {
                                // need to taint
                                taintFlag = true;
                                path.removeTaintVariable(regName);
                                path.addTaintVariable(rn.getName()); // taint the first op
                            }
                        }
                    }
                    return taintFlag;



                }
                return false;

            case "lsl":
            case "lsr":
            case "asr":
            case "ror":
                if (OperandType.isRegister(ins.getOperandType(0))) {
                    rn = (Register) ins.getOpObjects(0)[0];
                    if (!path.taintVariables.contains(rn.getName()))
                        return false; // do not need to taint
                    else {
                        path.removeTaintVariable(rn.getName()); // remove from taint variable
                    }
                }

                // taint all variables
                for (int i=1; i<ins.getNumOperands(); ++i) {
                    Object[] op = ins.getOpObjects(i);
                    if (OperandType.isRegister(ins.getOperandType(i))) {
                        path.addTaintVariable(((Register) op[0]).getName());
                    }
                    else if (OperandType.isAddress(ins.getOperandType(i)) || ins.getOperandType(i) == OperandType.DYNAMIC) {
                        // taint memory?
                        for (Object o: op) {
                            if (o instanceof Register)
                                path.addTaintVariable(((Register) o).getName());
                        }
                    }
                    else if (OperandType.isScalar(ins.getOperandType(i))) {
                        // constants, do not need to taint
                    }
                    else {
                        Logger.printW("Unhandled type: " + ins.getOperandType(i));
                    }
                }

                return true;

            case "push":
                return true;

            case "str":
            case "strb":
            case "strh":
            case "strmia":
            case "stm":
                if (Constant.MCU.equals("Nordic"))
                    return false;

                // STR R1, [R2, R3]
                // taint strategy: if R2 or R3 is in target variable set, then taint R1

                Object[] op = ins.getOpObjects(1);
                taintFlag = false;
                for (Object o: op) {
                    if (o instanceof Register) {
                        if (path.taintVariables.contains(o.toString()))
                            taintFlag = true;
                    }
                }

                if (taintFlag) {
                    Object o = ins.getOpObjects(0)[0];
                    if (o instanceof Register) {
                        path.addTaintVariable(((Register) o).getName());
                    }
                    return true;
                }



            case "pop":
                return false;

            case "b":
            case "bl":
                // unconditional branch
                return false;

            case "bne":
            case "beq":
            case "bcc":
            case "bgt":
            case "ble":
            case "bcs":
            case "bx":
            case "blx":
            case "tst":
                // branch related operations
                return true;

            case "cmp":
                // op = 2
                boolean taint = false;
                Set<String> regs = new HashSet<>();
                for (int i=0; i< ins.getNumOperands(); ++i) {
                    if (OperandType.isRegister(ins.getOperandType(i))) {
                        String tar = ((Register) ins.getOpObjects(i)[0]).getName();
                        regs.add(tar);
                        if (path.taintVariables.contains(tar))
                            taint = true;
                    }
                }
                if (taint) {
                    for (String reg: regs)
                        path.addTaintVariable(reg);
                    return true;
                }
                else
                    return false;


            case "svc":
                return false;

            default:
                Logger.printW("Unhandled taint option: " + mnem);
                return false;
        }
    }


}