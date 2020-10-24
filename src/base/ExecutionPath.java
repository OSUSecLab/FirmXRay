package base;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

import java.util.ArrayList;
import java.util.List;
import java.util.Stack;

public class ExecutionPath {
    /**
     * Execution instruction path in forward order
     */
    public List<Instruction> path;
    public List<String> taintVariables;
    public int currentInstIndex = 0;

    public ExecutionPath() {
        path = new ArrayList<>();
        taintVariables = new ArrayList<>();
    }

    public void restore() {
        currentInstIndex = path.size();
    }

    public void addInst(Instruction i) {
        path.add(i);
        currentInstIndex += 1;
    }

    public boolean contains(Address address) {
        for (Instruction ins: path) {
            if (ins.getAddress().compareTo(address) == 0) {
                return true;
            }
        }
        return false;
    }

    public Instruction getNextInst() {
        return path.get(--currentInstIndex);
    }

    public Instruction getLastInst() {return path.get(currentInstIndex-1);}

    public void addTaintVariable(String v) {
//        if (!taintVariables.contains(v) && !v.equals("sp")) {
//            taintVariables.add(v);
//        }

        if (!taintVariables.contains(v)) {
            taintVariables.add(v);
        }
    }

    public boolean removeTaintVariable(String v) {
//        if (v.equals("sp"))
//            return false;
        return taintVariables.remove(v);
    }

    public boolean finished() {
        return currentInstIndex == 0;
    }

    public List<Instruction> getPath() {
        return path;
    }

    public Instruction getFirstIns() {
        return path.get(0);
    }

    public boolean isTaintFinish() {
        if (taintVariables.size() > 0) {
            if (taintVariables.size() == 1 && taintVariables.get(0).equals("sp")) {
                // only sp left is ok
                if (this.getLastInst().getMnemonicString().equals("push")) // reach beginning of function
                    return true;
                else
                    return false;
            }
            else
                return false;
        }
        else {
            return true;
        }
    }

    public ExecutionPath clone() {
        ExecutionPath newPath = new ExecutionPath();
        newPath.path = new ArrayList<>(this.path);
        newPath.taintVariables = new ArrayList<>(this.taintVariables);
        newPath.currentInstIndex = currentInstIndex;
        return newPath;
    }
}
