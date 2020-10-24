package core;

import base.ExecutionPath;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.DataConverter;
import main.Constant;
import main.Logger;
import util.AddressUtil;

import org.json.*;
import util.FunctionUtil;
import util.InstructionUtil;
import util.NumUtil;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class ExecutionEngine {

    public HashMap<String, Long> registers = new HashMap<>();
    public HashMap<Long, Long> memory = new HashMap<>();
    public ExecutionPath path;
    public Program program;
    public List<String> targets;
    public boolean solved;
    public List<Long> dependencies;
    public long basicSP = 0;

    public ExecutionEngine(Program program, ExecutionPath path, List<String> targets) {
        this.path = path;
        this.program = program;
        this.targets = targets;
        this.dependencies = new ArrayList<>();
        init();
    }

    // restore the engine, clear register, memory
    public void restore() {
        init(); // clear register
        this.path.restore();
        this.memory.clear();
        this.dependencies.clear();
    }

    public void printResult() {
        Logger.print("\n----Registers----");
        for(String key: registers.keySet()) {
            Logger.print(String.format("%s -> %d", key, registers.get(key)));
        }
        Logger.print("\n----Memory----");
        for(long key: memory.keySet()) {
            Logger.print(String.format("%d -> %d", key, memory.get(key)));
        }
    }

    public void init() {
        // initialize registers and memory
        long v = 0;
        registers.put("r0", v);
        registers.put("r1", v);
        registers.put("r2", v);
        registers.put("r3", v);
        registers.put("r4", v);
        registers.put("r5", v);
        registers.put("r6", v);
        registers.put("r7", v);
        registers.put("r8", v);
        registers.put("r9", v);
        registers.put("r10", v);
        registers.put("r11", v);
        registers.put("r12", v);
        registers.put("sp", v);
        initSP();
        // registers.put("sp", Integer.toUnsignedLong(0x20010000));

        registers.put("lr", v);
        registers.put("pc", v);

        // initialize label and memory
        // Data dataIterator = program.getListing().get(program.getMinAddress());
    }

    public void execute() {
        Instruction lastIns = path.getLastInst();
        Function insFunction = FunctionUtil.findFunctionWithAddress(program, lastIns.getAddress());
        if (insFunction != null) {
            // update sp
            updateSP(insFunction.getEntryPoint().getUnsignedOffset());
        }

        while(!path.finished()) {
            Instruction nextIns = path.getNextInst();
            executeInst(nextIns);
        }

    }


    /**
     * init sp pointer value
     */
    public void initSP() {
        if (Constant.MCU.equals("Nordic")) {
            SymbolTable symbolTable = program.getSymbolTable();
            for (Symbol sym : symbolTable.getAllSymbols(true)) {
                if (sym.getName().equals("MasterStackPointer")) {
                    try {
                        long d1 = program.getMemory().getInt(sym.getAddress());
                        registers.put("sp", d1);
                        basicSP = d1;
                        return;
                    } catch (MemoryAccessException e) {
                        Logger.printW("Unable to initialize SP pointer!");
                        return;
                    }
                }
            }
        }
        else if (Constant.MCU.equals("TI")) {
            basicSP = 0x20050000;
        }
    }

    /**
     * update sp pointer value when function changed
     */
    public void updateSP(long offset) {
        registers.put("sp", basicSP + offset);
    }


    public long getValFromMemory(long address, int numByte) {
        if (memory.keySet().contains(address)) {
            // look up address in cache
            long[] bytes = new long[]{0, 0, 0, 0};
            for (int i=0; i<numByte; ++i) {
                if (memory.containsKey(address+i))
                    bytes[i] = memory.get(address+i);
                else
                    bytes[i] = 0;
            }

            // calculate value
            long val = NumUtil.byteToLongLittleEndian(bytes);
            return val;
        }
        else if (STRInsSolver.AddSTRMap.keySet().contains(address)){
            // look up in STR map
            return STRInsSolver.getValueFromMap(address, numByte);
        }
        else {
            // look up address in memory
            Memory mem = program.getMemory();
            try {
                Address tarAddress = AddressUtil.lookupAddress(address, program);
                if (tarAddress == null) {
                    dependencies.add(address); // add to dependencies
                    return 0; // not found in current address space
                }
                long val;

                if (numByte == 4)
                    val= mem.getInt(tarAddress);
                else if (numByte == 2)
                    val = mem.getInt(tarAddress) & 0xFFFF;
                else if (numByte == 1)
                    val = mem.getInt(tarAddress) & 0xFF;
                else
                    val = -1; // should not happen

                if (val < 0) {
                    // overflow
                    byte[] bytes = new byte[8];
                    int len = mem.getBytes(tarAddress, bytes, 0, 4);
                    val = DataConverter.getInstance(false).getLong(bytes);
                }

                // load value in cache
                memory.put(address, val & 0xFF);
                memory.put(address+1, val >> 8 & 0xFF);
                memory.put(address+2, val >> 16 & 0xFF);
                memory.put(address+3, val >> 24 & 0xFF);

                return val;
            }
            catch (MemoryAccessException e) {
                e.printStackTrace();
                return -9999;
            }
        }
    }


    public long getValueFromOperand(Object[] op, int type, int numByte) {
        int opNum = op.length;
        if (opNum == 1) {
            return getValueSingleOp(op[0], numByte);
        }
        else {
            if (OperandType.isScalar(type)) {
                long temp = 0;
                for (int i=0; i<opNum; ++i) {
                    temp += getValueSingleOp(op[i], numByte);
                }
                return temp;
            }
            else if (OperandType.isAddress(type)) {
                // e.g., [R1 #0x3]
                long temp = 0;
                for (int i=0; i<opNum; ++i) {
                    temp += getValueSingleOp(op[i], numByte);
                }
                return getValFromMemory(temp, numByte);
            }
            else if (OperandType.isRegister(type)) {
                long temp = 0;
                for (int i=0; i<opNum; ++i) {
                    temp += getValueSingleOp(op[i], numByte);
                }
                return temp;
            }
            else if (type == OperandType.DYNAMIC) {
                long temp = 0;
                for (Object o: op) {
                    temp += getValueSingleOp(o, numByte);
                }
                return getValFromMemory(temp, numByte);
            }
            else {
                Logger.printW("getValueFromOperand, with type " + type); // other types, should not happen
                return -9999;
            }
        }
    }

    public long getValueFromOperand(Object[] op, int type, boolean dereference, int numByte) {
        int opNum = op.length;
        if(opNum == 1) {
            return getValueSingleOp(op[0], 4);
        }
        else {
            if (OperandType.isScalar(type)) {
                long temp = 0;
                for (int i=0; i<opNum; ++i) {
                    temp += getValueSingleOp(op[i], numByte);
                }
                return temp;
            }
            else if (OperandType.isAddress(type)) {
                // e.g., [R1 #0x3]
                long temp = 0;
                for (int i=0; i<opNum; ++i) {
                    temp += getValueSingleOp(op[i], numByte);
                }
                if (dereference)
                    return getValFromMemory(temp, numByte);
                else
                    return temp;
            }
            else if (type == OperandType.DYNAMIC) {
                long temp = 0;
                for (Object o: op) {
                    temp += getValueSingleOp(o, numByte);
                }
                return temp;
            }
            else {
                Logger.printW("Other type: " + type); // other types
                return -9999;
            }
        }
    }

    public long getValueSingleOp(Object op, int numByte) {
        if(op instanceof Register) {
            return registers.get(((Register)(op)).getName());
        }
        else if (op instanceof Scalar) {
            return ((Scalar)(op)).getValue();
        }
        else if (op instanceof Address) {
            return getValFromMemory(((Address) op).getUnsignedOffset(), numByte);
        }
        else {
            Logger.printW("Unhandled type of operands ");
            throw new NumberFormatException();
        }
    }

    public void executeInst(Instruction ins) {
        String mnem = ins.getMnemonicString();
        int opNum = ins.getNumOperands();
        long regVal;
        long sourceVal;
        Register targetReg;
        Object[] source;
        long byte1, byte2, byte3, byte4;

        mnem = InstructionUtil.removePostfix(mnem);

        switch (mnem) {
            case "movw":
            case "movs":
            case "mov":
                // 2 ops
                Logger.print("Handling MOV!");
                targetReg = (Register) (ins.getOpObjects(0)[0]);

                source = ins.getOpObjects(1);
                long value = getValueFromOperand(source, ins.getOperandType(0), 4);
                registers.put(targetReg.getName(), value);
                break;

            case "add":
                // 2/3 ops
                Logger.print("Handling ADD!");
                targetReg = (Register) (ins.getOpObjects(0)[0]);

                boolean containSP = false;
                if (ins.toString().contains("sp"))
                    containSP = true;

                if(opNum == 2 && !containSP) {
                    long leftVal = registers.get(targetReg.getName());
                    source = ins.getOpObjects(1);
                    long rightVal = getValueFromOperand(source, ins.getOperandType(0), 4);
                    long result = leftVal + rightVal;
                    registers.put(targetReg.getName(), result);
                }
                else if (opNum == 2 && containSP) {
                    // this is a trap of Ghidra
                    // if the inst has sp as operand, it will detect the operand # as 2, even if it has 3 operands (e.g., add r2 sp #0x3)
                    // the reason is Ghidra will take [sp #0x3] as a whole operand
                    long result = 0;
                    for (Object o: ins.getOpObjects(1)) {
                        result += getValueSingleOp(o, 4);
                    }
                    // long result = getValueFromOperand(ins.getOpObjects(1), ins.getOperandType(1));;
                    registers.put(targetReg.getName(), result);
                }
                else if (opNum == 3) {
                    long leftVal = getValueFromOperand(ins.getOpObjects(1), ins.getOperandType(1), 4);
                    long rightVal = getValueFromOperand(ins.getOpObjects(2), ins.getOperandType(2), 4);
                    long result = leftVal + rightVal;
                    registers.put(targetReg.getName(), result);
                }
                break;

            case "sub":
                // 2/3 ops
                Logger.print("Handling SUB!");
                targetReg = (Register) (ins.getOpObjects(0)[0]);

                containSP = false;
                if (ins.toString().contains("sp"))
                    containSP = true;

                if(opNum == 2 && !containSP) {
                    long leftVal = registers.get(targetReg.getName());
                    source = ins.getOpObjects(1);
                    long rightVal = getValueFromOperand(source, ins.getOperandType(0), 4);
                    long result = leftVal - rightVal;
                    registers.put(targetReg.getName(), result);
                }
                else if (opNum == 3) {
                    long leftVal = getValueFromOperand(ins.getOpObjects(1), ins.getOperandType(1), 4);
                    long rightVal = getValueFromOperand(ins.getOpObjects(2), ins.getOperandType(2), 4);
                    long result = leftVal - rightVal;
                    registers.put(targetReg.getName(), result);
                }
                break;

            case "mul":
                // 2/3 ops
                Logger.print("Handling MUL!");
                targetReg = (Register) (ins.getOpObjects(0)[0]);
                if(opNum == 2) {
                    long leftVal = registers.get(targetReg.getName());
                    source = ins.getOpObjects(1);
                    long rightVal = getValueFromOperand(source, ins.getOperandType(0), 4);
                    long result = leftVal * rightVal;
                    registers.put(targetReg.getName(), result);
                }
                else if (opNum == 3) {
                    long leftVal = getValueFromOperand(ins.getOpObjects(1), ins.getOperandType(1),4);
                    long rightVal = getValueFromOperand(ins.getOpObjects(2), ins.getOperandType(2), 4);
                    long result = leftVal * rightVal;
                    registers.put(targetReg.getName(), result);
                }
                break;


            case "and":
                // 2/3 ops
                Logger.print("Handling AND!");
                targetReg = (Register) (ins.getOpObjects(0)[0]);
                if(opNum == 2) {
                    long leftVal = registers.get(targetReg.getName());
                    source = ins.getOpObjects(1);
                    long rightVal = getValueFromOperand(source, ins.getOperandType(0), 4);
                    long result = leftVal & rightVal;
                    registers.put(targetReg.getName(), result);
                }
                else if (opNum == 3) {
                    long leftVal = getValueFromOperand(ins.getOpObjects(1), ins.getOperandType(1), 4);
                    long rightVal = getValueFromOperand(ins.getOpObjects(2), ins.getOperandType(2), 4);
                    long result = leftVal & rightVal;
                    registers.put(targetReg.getName(), result);
                }
                break;


            case "orr":
                // 2/3 ops
                Logger.print("Handling ORR!");
                targetReg = (Register) (ins.getOpObjects(0)[0]);
                if(opNum == 2) {
                    long leftVal = registers.get(targetReg.getName());
                    source = ins.getOpObjects(1);
                    long rightVal = getValueFromOperand(source, ins.getOperandType(0), 4);
                    long result = leftVal | rightVal;
                    registers.put(targetReg.getName(), result);
                }
                else if (opNum == 3) {
                    long leftVal = getValueFromOperand(ins.getOpObjects(1), ins.getOperandType(1), 4);
                    long rightVal = getValueFromOperand(ins.getOpObjects(2), ins.getOperandType(2), 4);
                    long result = leftVal | rightVal;
                    registers.put(targetReg.getName(), result);
                }
                break;

            case "eor":
                // 2/3 ops
                Logger.print("Handling ORR!");
                targetReg = (Register) (ins.getOpObjects(0)[0]);
                if(opNum == 2) {
                    long leftVal = registers.get(targetReg.getName());
                    source = ins.getOpObjects(1);
                    long rightVal = getValueFromOperand(source, ins.getOperandType(0), 4);
                    long result = leftVal ^ rightVal;
                    registers.put(targetReg.getName(), result);
                }
                else if (opNum == 3) {
                    long leftVal = getValueFromOperand(ins.getOpObjects(1), ins.getOperandType(1), 4);
                    long rightVal = getValueFromOperand(ins.getOpObjects(2), ins.getOperandType(2), 4);
                    long result = leftVal ^ rightVal;
                    registers.put(targetReg.getName(), result);
                }
                break;


            case "bic":
                // 2/3 ops
                Logger.print("Handling BIC!");
                targetReg = (Register) (ins.getOpObjects(0)[0]);
                if(opNum == 2) {
                    long leftVal = registers.get(targetReg.getName());
                    source = ins.getOpObjects(1);
                    long rightVal = getValueFromOperand(source, ins.getOperandType(0), 4);
                    long result = leftVal ^ (~rightVal);
                    registers.put(targetReg.getName(), result);
                }
                else if (opNum == 3) {
                    long leftVal = getValueFromOperand(ins.getOpObjects(1), ins.getOperandType(1), 4);
                    long rightVal = getValueFromOperand(ins.getOpObjects(2), ins.getOperandType(2), 4);
                    long result = leftVal ^ (~rightVal);
                    registers.put(targetReg.getName(), result);
                }
                break;


            case "lsl":
                // op = 3
                Logger.print("Handling LSL!");
                if (opNum == 3) {
                    targetReg = (Register) (ins.getOpObjects(0)[0]);
                    long leftVal = getValueFromOperand(ins.getOpObjects(1), ins.getOperandType(1), 4);
                    long rightVal = getValueFromOperand(ins.getOpObjects(2), ins.getOperandType(2), 4);
                    long result = leftVal << rightVal;
                    registers.put(targetReg.getName(), result);
                }
                else
                    Logger.printW("Unhandled instruction " + ins);
                break;

            case "lsr":
                // op = 3
                Logger.print("Handling LSR!");
                if (opNum == 3) {
                    targetReg = (Register) (ins.getOpObjects(0)[0]);
                    long leftVal = getValueFromOperand(ins.getOpObjects(1), ins.getOperandType(1), 4);
                    long rightVal = getValueFromOperand(ins.getOpObjects(2), ins.getOperandType(2), 4);
                    long result = leftVal >> rightVal;
                    registers.put(targetReg.getName(), result);
                }
                else
                    Logger.printW("Unhandled instruction " + ins);
                break;

            case "asr":
                // op = 3
                Logger.print("Handling ASR!");
                if (opNum == 3) {
                    targetReg = (Register) (ins.getOpObjects(0)[0]);
                    long leftVal = getValueFromOperand(ins.getOpObjects(1), ins.getOperandType(1), 4);
                    long rightVal = getValueFromOperand(ins.getOpObjects(2), ins.getOperandType(2), 4);
                    long result = leftVal >>> rightVal;
                    registers.put(targetReg.getName(), result);
                }
                else
                    Logger.printW("Unhandled instruction " + ins);
                break;

            case "ror":
                // op = 3
                Logger.print("Handling ROR!");
                if (opNum == 3) {
                    targetReg = (Register) (ins.getOpObjects(0)[0]);
                    int leftVal = (int) getValueFromOperand(ins.getOpObjects(1), ins.getOperandType(1), 4);
                    int rightVal = (int) getValueFromOperand(ins.getOpObjects(2), ins.getOperandType(2), 4);
                    long result = leftVal << rightVal | leftVal >> (32-rightVal);
                    registers.put(targetReg.getName(), result);
                }
                else
                    Logger.printW("Unhandled instruction " + ins);
                break;

            case "beq":
                break;

            case "b":
                break;

            case "bl":
                break;

            case "bne":
                break;

            case "bgt":
                break;

            case "blx":
                break;

            case "cmp":
                // op = 2
                /*Object leftOp = ins.getOpObjects(0)[0];
                Object rightOp = ins.getOpObjects(1)[0];

                long leftval = getValueFromOperand(ins.getOpObjects(0), ins.getOperandType(0));

                if (leftOp instanceof Register) {
                    long rightval = getValueFromOperand(ins.getOpObjects(1), ins.getOperandType(1));
                    // control dependency
                    registers.put(((Register) leftOp).getName(), rightval);
                }
                else {

                }*/

                break;

            case "tst":
                break;

            case "str":
                // op = 2
                Logger.print("Handling STR!");
                targetReg = (Register) (ins.getOpObjects(0)[0]);
                regVal = registers.get(targetReg.getName());

                // take all 4 bytes
                byte1= regVal & 0xFF;
                byte2 = (regVal >> 8) & 0xFF;
                byte3 = (regVal >> 16) & 0xFF;
                byte4 = (regVal >> 24) & 0xFF;

                // target memory address
                source = ins.getOpObjects(1);
                sourceVal = getValueFromOperand(source, ins.getOperandType(1), false, 4);

                // put 4 bytes according, little endian
                memory.put(sourceVal, byte1);
                memory.put(sourceVal+1, byte2);
                memory.put(sourceVal+2, byte3);
                memory.put(sourceVal+3, byte4);

                break;

            case "strmia":
            case "stm":
                // op = 2
                Logger.print("Handling STMIA!");

                Object[] targets = ins.getOpObjects(1);
                Register sourceR = (Register) ins.getOpObjects(0)[0];

                for (int i=0; i<targets.length; ++i) {
                    if (targets[i] instanceof Register) {
                        Register reg = (Register) targets[i];

                        long sourceadd = registers.get(sourceR.getName()) + i*4; // incremental
                        regVal = registers.get(reg.getName());

                        // take all 4 bytes
                        byte1= regVal & 0xFF;
                        byte2 = (regVal >> 8) & 0xFF;
                        byte3 = (regVal >> 16) & 0xFF;
                        byte4 = (regVal >> 24) & 0xFF;

                        // put 4 bytes according, little endian
                        memory.put(sourceadd, byte1);
                        memory.put(sourceadd+1, byte2);
                        memory.put(sourceadd+2, byte3);
                        memory.put(sourceadd+3, byte4);
                    }
                }

                break;

            case "ldr":
                // op = 2
                Logger.print("Handling LDR!");
                targetReg = (Register) (ins.getOpObjects(0)[0]);

                source = ins.getOpObjects(1);

                sourceVal = getValueFromOperand(source, ins.getOperandType(1), 4);

                registers.put(targetReg.getName(), sourceVal);

                break;

            case "ldmia":
                // op = 2
                Logger.print("Handling LDMIA!");

                targets = ins.getOpObjects(1);
                sourceR = (Register) ins.getOpObjects(0)[0];

                for (int i=0; i<targets.length; ++i) {
                    if (targets[i] instanceof Register) {
                        Register reg = (Register) targets[i];

                        long sourceadd = registers.get(sourceR.getName()) + i*4; // incremental
                        long sourceval = getValFromMemory(sourceadd, 4);
                        registers.put(reg.getName(), sourceval);
                    }
                }

                break;

            case "adr":
                // op = 2
                Logger.print("Handling LDR!");
                targetReg = (Register) (ins.getOpObjects(0)[0]);

                source = ins.getOpObjects(1);
                sourceVal = getValueFromOperand(source, ins.getOperandType(1), 4);

                registers.put(targetReg.getName(), sourceVal);

                break;

            case "ldrb":
            case "ldrsb":
                Logger.print("Handling LDRB!");
                targetReg = (Register) (ins.getOpObjects(0)[0]);

                source = ins.getOpObjects(1);
                sourceVal = getValueFromOperand(source, ins.getOperandType(1), 1); // only reserve 1 byte, little endian

                registers.put(targetReg.getName(), sourceVal);
                break;

            case "strb":
                Logger.print("Handling STRB!");
                targetReg = (Register) (ins.getOpObjects(0)[0]);
                regVal = registers.get(targetReg.getName());

                // target memory address
                source = ins.getOpObjects(1);
                sourceVal = getValueFromOperand(source, ins.getOperandType(1), false, 4);
                regVal &= 0xFF; // only reserve 1 byte, little endian

                memory.put(sourceVal, regVal);
                break;

            case "ldrh":
            case "ldrsh":
                Logger.print("Handling LDRH!");
                targetReg = (Register) (ins.getOpObjects(0)[0]);

                source = ins.getOpObjects(1);
                sourceVal = getValueFromOperand(source, ins.getOperandType(1), 2);
                sourceVal &= 0xFFFF; // only reverse half word (2 byte), little endian

                registers.put(targetReg.getName(), sourceVal);
                break;

            case "strh":
                Logger.print("Handling STRH!");
                targetReg = (Register) (ins.getOpObjects(0)[0]);
                regVal = registers.get(targetReg.getName());

                // target memory address
                source = ins.getOpObjects(1);
                sourceVal = getValueFromOperand(source, ins.getOperandType(1), false, 4);

                // take half word (2 bytes), little endian
                byte1= regVal & 0xFF;
                byte2 = (regVal >> 8) & 0xFF;

                // put 2 bytes according, little endian
                memory.put(sourceVal, byte1);
                memory.put(sourceVal+1, byte2);

                break;

            case "push":
                // op = 1
                Logger.print("Handling PUSH!");
                for (Object obj: ins.getOpObjects(0)) {
                    long tempsp = registers.get("sp");
                    Register tempReg;
                    if (obj instanceof Register)
                        tempReg = (Register) obj;
                    else {
                        Logger.printW("Other type: " + obj); // not a register?
                        break;
                    }
                    // push value onto stack
                    // registers.put("sp", registers.get("sp")-4);
                    tempsp -= 4;
                    regVal = getValueSingleOp(tempReg, 4);
                    memory.put(tempsp, regVal);
                }
                break;

            case "pop":
                // op = 1
                Logger.print("Handling POP!");
                for (Object obj: ins.getOpObjects(0)) {
                    Register tempReg;
                    if (obj instanceof Register)
                        tempReg = (Register) obj;
                    else {
                        Logger.printW("Other type: " + obj); // not a register?
                        break;
                    }
                    // push value out of stack
                    registers.put(tempReg.toString(), getValFromMemory(registers.get("sp"), 4));
                    // increase sp by 4
                    registers.put("sp", registers.get("sp")+4);
                }
                break;

            case "bfc":
                // op = 3
                Logger.print("Handling BFC!");
                {
                    long width = getValueFromOperand(ins.getOpObjects(2), ins.getOperandType(2), 4);
                    long start = getValueFromOperand(ins.getOpObjects(1), ins.getOperandType(1), 4);
                    long end = start + width - 1;

                    targetReg = (Register) (ins.getOpObjects(0)[0]);
                    // clear bit
                    long targetRegVal = registers.get(targetReg.getName());
                    sourceVal = 0xFFFFFFFF >> (32 - width);
                    sourceVal = ~(sourceVal << start);
                    targetRegVal = targetRegVal & sourceVal;

                    registers.put(targetReg.getName(), targetRegVal);
                }
            break;

            case "bfi":
                // op = 4;
                Logger.print("Handling BFI!");
                {
                    long width = getValueFromOperand(ins.getOpObjects(3), ins.getOperandType(3), 4);
                    long start = getValueFromOperand(ins.getOpObjects(2), ins.getOperandType(2), 4);
                    long end = start + width - 1;

                    targetReg = (Register) (ins.getOpObjects(0)[0]);
                    long targetRegVal = registers.get(targetReg.getName());
                    Register sourceReg = (Register) (ins.getOpObjects(1)[0]);
                    long sourceRegVal = registers.get(sourceReg.getName());

                    // clear bit
                    sourceVal = 0xFFFFFFFF >> (32 - width);
                    sourceRegVal = (sourceRegVal & sourceVal) << start;
                    sourceVal = ~(sourceVal << start);
                    targetRegVal = targetRegVal & sourceVal;

                    // replace bit
                    targetRegVal = targetRegVal | sourceRegVal;

                    registers.put(targetReg.getName(), targetRegVal);
                }
                break;

            case "svc":
                break;

            default:
                Logger.printW("Unhandled operation: " + mnem);

        }
    }
}
