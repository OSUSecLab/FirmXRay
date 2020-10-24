package core;

import base.ExecutionPath;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import main.Constant;
import util.InstructionUtil;
import util.NumUtil;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * This is designed to resolve implicit dependencies such as initialization of global variables
 * Right now the solution is to solve all the STR-like instructions and record them in a mapping
 */
public class STRInsSolver {

    public static List<Address> allSTRIns = new ArrayList<>();

    public static HashMap<Long, ArrayList<Long>> AddSTRMap = new HashMap<>();

    public static List<ExecutionEngine> unSolvedList = new ArrayList<>();

    public static int spCount = 0;

    public static int unSolvedCount = 0;

    public static void addIns(Address address) {
        allSTRIns.add(address);
    }

    // Search for all STR instructions in the program
    // Use backward slicing and simulate execution to solve all the instructions
    public static void solveAllSTRIns(Program program) {

        for (Address address: allSTRIns) {
            Instruction instruction = program.getListing().getInstructionAt(address); // STR instruction
            String mnem = InstructionUtil.removePostfix(instruction.getMnemonicString());

            if (InstructionUtil.isSTRInstruction(mnem)) {

                int numByte; // number of bytes to store
                if (mnem.equals("str"))
                    numByte = 4;
                else if (mnem.equals("strh"))
                    numByte = 2;
                else if (mnem.equals("strb"))
                    numByte = 1;
                else
                    numByte = 4; // should not happen

                List<String> targetVarSet = new ArrayList<>();
                Object[] op = instruction.getOpObjects(0);
                String valueReg = ((Register) op[0]).getName();
                targetVarSet.add(((Register) op[0]).getName());

                op = instruction.getOpObjects(1);
                List<String> memOps = new ArrayList<>();
                for (Object o : op) {
                    if (o instanceof Register) {
                        String targetReg = ((Register) o).getName();
                        targetVarSet.add(targetReg);
                        memOps.add(targetReg);
                    } else if (o instanceof Scalar) {
                        Long value = ((Scalar) (o)).getValue();
                        memOps.add(String.valueOf(value));
                    }
                }

                if (valueReg.equals("sp") || targetVarSet.contains("sp")) {
                    ++spCount;
                    // continue; // give up solving sp
                }


                List<ExecutionPath> paths = ExecutionPathFinder.findAllExecPaths(program, address, targetVarSet);
                for (ExecutionPath path : paths) {
                    // execution
                    ExecutionEngine engine = new ExecutionEngine(program, path, targetVarSet);
                    engine.execute();


                    if (engine.dependencies.size() != 0) {
                        // unsolved, solve it later
                        unSolvedList.add(engine);
                        continue;
                    }

                    long valueToSTR = engine.registers.get(valueReg);
                    long addressToSTR = 0;
                    for (String memop : memOps) {
                        if (engine.registers.keySet().contains(memop)) {
                            // register
                            addressToSTR += engine.registers.get(memop);
                        } else {
                            // constant
                            addressToSTR += Integer.parseInt(memop);
                        }
                    }


                    if (addressToSTR != 0) {
                        addToMap(addressToSTR, valueToSTR, numByte);
                        engine.solved = true;
                        // break;
                    }
                }
            }
            else if (InstructionUtil.isMultipleSTRInstruction(mnem)) {
                List<String> targetVarSet = new ArrayList<>();

                Object[] op = instruction.getOpObjects(0);
                List<String> memOps = new ArrayList<>();
                memOps.add(((Register) op[0]).getName());
                targetVarSet.add(((Register) op[0]).getName());


                List<String> valueRegs = new ArrayList<>();

                op = instruction.getOpObjects(1);
                for (Object o : op) {
                    if (o instanceof Register) {
                        String targetReg = ((Register) o).getName();
                        targetVarSet.add(targetReg);
                        valueRegs.add(targetReg);
                    }
                }

                if (memOps.contains("sp") || targetVarSet.contains("sp")) {
                    ++spCount;
                    // continue; // give up solving sp
                }


                List<ExecutionPath> paths = ExecutionPathFinder.findAllExecPaths(program, address, targetVarSet);
                for (ExecutionPath path : paths) {
                    // execution
                    ExecutionEngine engine = new ExecutionEngine(program, path, targetVarSet);
                    engine.execute();


                    if (engine.dependencies.size() != 0) {
                        // unsolved, solve it later
                        unSolvedList.add(engine);
                        continue;
                    }

                    for (int i=0; i<valueRegs.size(); ++i) {
                        String currentReg = valueRegs.get(i);
                        long valueToSTR = engine.registers.get(currentReg);

                        long addressToSTR = 0;
                        for (String memop : memOps) {
                            if (engine.registers.keySet().contains(memop)) {
                                // register
                                addressToSTR += engine.registers.get(memop);
                            } else {
                                // constant
                                addressToSTR += Integer.parseInt(memop);
                            }
                        }

                        // increment
                        addressToSTR += 4 * i;

                        if (addressToSTR != 0) {
                            addToMap(addressToSTR, valueToSTR, 4);
                            engine.solved = true;
                            // break;
                        }
                    }
                }
            }
        }


        // round 1 finished, try to solve all unsolved points
        solveUnsolvedPoints();

    }

    public static void addToMap(long key, long value, long numByte) {
        for (int i=0; i<numByte; ++i) {
            long tmpVal = value >> (i*8) & 0xFF;
            if (AddSTRMap.keySet().contains(key+i)) {
                // conflict
                if (!AddSTRMap.get(key+i).contains(tmpVal)) {
                    AddSTRMap.get(key+i).add(tmpVal);
                }
            } else {
                ArrayList<Long> tmp = new ArrayList<>();
                tmp.add(tmpVal);
                AddSTRMap.put(key+i, tmp);
            }
        }
    }

    public static void solveUnsolvedPoints() {

        unSolvedCount = unSolvedList.size();
        int iteration = Constant.MAX_ITERATION;

         while (unSolvedCount != 0) {

             if (iteration == 0) // reach max iterations
                 break;

            // loop until solve all points
            for (int i=0; i<unSolvedList.size(); ++i) {

                ExecutionEngine engine = unSolvedList.get(i);
                if (engine.solved)
                    continue;

                engine.restore();
                engine.path.taintVariables = new ArrayList<>(engine.targets);

                Instruction instruction = engine.path.getFirstIns(); // STR instruction

                List<String> targetVarSet = new ArrayList<>();

                Object[] op = instruction.getOpObjects(0);
                String valueReg = ((Register) op[0]).getName();
                targetVarSet.add(((Register) op[0]).getName());

                int numByte; // number of bytes to store
                String mnem = InstructionUtil.removePostfix(instruction.getMnemonicString());
                if (mnem.equals("str"))
                    numByte = 4;
                else if (mnem.equals("strh"))
                    numByte = 2;
                else if (mnem.equals("strb"))
                    numByte = 1;
                else
                    numByte = 4; // should not happen

                op = instruction.getOpObjects(1);
                List<String> memOps = new ArrayList<>();
                for (Object o: op) {
                    if (o instanceof Register) {
                        String targetReg = ((Register) o).getName();
                        targetVarSet.add(targetReg);
                        memOps.add(targetReg);
                    }
                    else if (o instanceof Scalar) {
                        Long value = ((Scalar)(o)).getValue();
                        memOps.add(String.valueOf(value));
                    }
                }

//                if (valueReg.equals("sp") || targetVarSet.contains("sp"))
//                    continue; // give up solving sp

                // try to solve it
                engine.execute();

                // try to manually solve stack dependencies
                if (engine.dependencies.size() > 0) {
                    List<Long> toRemove = new ArrayList<>();
                    long spAdd = engine.registers.get("sp");
                    for (long add: engine.dependencies) {
                        if (add - spAdd < 0x100) {
                            toRemove.add(add);
                            addToMap(add, 0, numByte);
                        }
                    }

                    // remove dependencies
                    for (long val: toRemove) {
                        engine.dependencies.remove(val);
                    }

                    if (engine.dependencies.size() == 0)
                        continue; // solve in next round
                }



                long valueToSTR = engine.registers.get(valueReg);
                long addressToSTR = 0;
                for (String memop: memOps) {
                    if (engine.registers.keySet().contains(memop)) {
                        // register
                        addressToSTR += engine.registers.get(memop);
                    } else {
                        // constant
                        addressToSTR += Integer.parseInt(memop);
                    }
                }

                if (addressToSTR != 0) {
                    addToMap(addressToSTR, valueToSTR, numByte);
                    unSolvedCount -= 1;
                    engine.solved = true;
                }
            }

            iteration--;
            System.out.println(unSolvedCount);
         }

         // finish
    }

    public static long getValueFromMap(long address, long numByte) {
        if (AddSTRMap.containsKey(address)) {
            long[] bytes = new long[]{0, 0, 0, 0};
            for (int i=0; i<numByte; ++i) {
                if (AddSTRMap.containsKey(address + i)) {
                    ArrayList<Long> tmp = AddSTRMap.get(address+i);
                    if (tmp.size() == 1)
                        bytes[i] = tmp.get(0);
                    else {
                        // multiple conflicts
                        bytes[i] = tmp.get(tmp.size() - 1);
                    }
                } else
                    bytes[i] = 0;
            }
            return NumUtil.byteToLongLittleEndian(bytes);
        }
        else
            return Integer.MIN_VALUE;  // not exist
    }

}
