package core;

import base.BaseConstraints;
import ghidra.GhidraJarApplicationLayout;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageProvider;
import ghidra.program.model.listing.Program;
import ghidra.test.TestProgramManager;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TimeoutTaskMonitor;
import main.Constant;
import main.Logger;
import util.*;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class BaseAddressSolver {

    public static long getBaseAddressWithConstraint(String programName, String projectName) throws IOException, VersionException, CancelledException,
            DuplicateNameException, InvalidNameException {

        String projectDirectoryName = Constant.DIRECTORY_NAME;
        Set<Long> result = new HashSet<>();

        // Define Ghidra components
        GhidraProject ghidraProject;
        TestProgramManager programManager = new TestProgramManager();

        // Initialize application
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new HeadlessGhidraApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(new GhidraJarApplicationLayout(), configuration);
        }

        // Create a Ghidra project
        ghidraProject = GhidraProject.createProject(projectDirectoryName, projectName, true);

        // Load binary file
        File file = new File(programName);
        if (!file.exists()) {
            throw new FileNotFoundException("Can not find program: " + programName);
        }

        LanguageProvider languageProvider;
        try {
            languageProvider = new SleighLanguageProvider();
        } catch (Exception e) {
            System.out.println("Unable to build language provider.");
            return 0;
        }

        Program program = ghidraProject.importProgram(file, languageProvider.getLanguage(new LanguageID(Constant.ARM_CORTEX_LE_32)), null);

        // Analyze the loaded binary file
        int txId = program.startTransaction("Analysis");
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        mgr.initializeOptions();
        mgr.reAnalyzeAll(null);

        // The analysis will take sometime.
        System.out.println("Analyzing...");
        mgr.startAnalysis(TimeoutTaskMonitor.timeoutIn(Constant.DISASSEMBLE_TIMEOUT, TimeUnit.SECONDS));


        // Constraint 1: base range
        BaseConstraints range = getBaseRange(program);


        // find all absolute addresses
        List<Long> AbsAddrSet = FunctionUtil.findAllImmediateInLDR(program);
        Collections.sort(AbsAddrSet);

        // set up scores
        HashMap<Long, Integer> scores = new HashMap<>();


        // Constraint 2: function prologue
        long length = program.getMaxAddress().getUnsignedOffset();
        Address current = program.getMinAddress();
        List<Long> entry = BaseAddressUtil.getFunctionEntries(program);
        Collections.sort(entry);


        for (long ab : AbsAddrSet) {

            if (ab > Constant.MAX_BASE)
                continue;

            if (ab % 2 != 0) // deal with odd function entry
                ab -= 1;

            for (long start : entry) {
                // start + candidate = ab
                long candidate = ab - start;

                if (candidate < 0 || candidate > Constant.MAX_BASE)
                    continue;

                addScore(scores, candidate);
            }
        }


        // Constraint 3: absolute string pointer
        Map<Address, String> strs = StringUtil.getString(program);
        Set<Address> straddrs = strs.keySet();
        List<Long> relativeAddrSet = FunctionUtil.findAllRelativeInADR(program);
        for (Address add: straddrs) {
            if (relativeAddrSet.contains(add.getUnsignedOffset())) // get rid of relative string pointer
                continue;
            for (long ab: AbsAddrSet) {
                // add + candidate = ab
                long candidate = ab - add.getUnsignedOffset();

                if (candidate < 0 || candidate > Constant.MAX_BASE)
                    continue;

                addScore(scores, candidate);
            }
        }


        // Constraint 4: vector table
        Map<Address, Long> vec = new HashMap<>();
        if (Constant.MCU.equals("Nordic")) {
            vec = StringUtil.getVector(program);
            List<Long> e7 = BaseAddressUtil.getE7Address(program);

            for (long v : vec.values()) {
                for (long e : e7) {
                    // e + candidate = v
                    long candidate = v - e;

                    if (candidate < 0 || candidate > Constant.MAX_BASE)
                        continue;

                    addScore(scores, candidate);
                }
            }
        }


        scores = NumUtil.sortByValues(scores, true);


        int numAbsAddr = AbsAddrSet.size();
        int numPrologue = entry.size();
        int numAbsStr = straddrs.size();
        int numVec = vec.size();
        int score = 0;
        long base = 0;
        long lower = 0;
        long upper = program.getMaxAddress().getUnsignedOffset();


        // From high to low, tight with base constraint
        Iterator<Long> iterator = scores.keySet().iterator();
        while (iterator.hasNext()) {
            long candidate = iterator.next();
            int constraintIndex = checkConstraint(candidate, range);
            if (constraintIndex != -1) {
                base = candidate;
                score = scores.get(base);
                lower = range.getConstraint(constraintIndex).get(0);
                upper = range.getConstraint(constraintIndex).get(1);
                break;
            }
        }

        return base;
    }

    public static int checkConstraint(Long address, BaseConstraints constraints) {
        int size = constraints.getLength();
        for (int i=0; i<size; ++i) {
            long low = constraints.getConstraint(i).get(0);
            long high = constraints.getConstraint(i).get(1);
            if (address >= low && address <= high) // satisfy constraint
                return i;
        }
        return -1;
    }

    public static void addScore(HashMap<Long, Integer> map, long add) {
        if (map.containsKey(add))
            map.put(add, map.get(add) + 1);
        else
            map.put(add, 1);
    }


    public static BaseConstraints getBaseRange(Program program) {

        List<Long> LDRset = FunctionUtil.findAllImmediateInLDR(program);
        Collections.sort(LDRset);

        List<Long> lowerBound = new ArrayList<>();
        List<Long> upperBound = new ArrayList<>();

        long size = program.getMaxAddress().getUnsignedOffset();
        long low = 0;
        long high = 0;

        for (int i = 0; i < LDRset.size() - 1; ++i) {

            long diff = LDRset.get(i + 1) - LDRset.get(i);
            if (diff > Constant.THRESHOLD) {
                low = LDRset.get(i) - size;
                if (low < 0)
                    low = 0;

                if (high < Constant.MAX_BASE && high > Constant.MIN_BASE) {
                    if (low < Constant.MAX_BASE && low > Constant.MIN_BASE) {
                        lowerBound.add(low);
                        upperBound.add(high);
                    }
                }

                high = LDRset.get(i + 1);
            }
        }

        if (lowerBound.size() == 0) {
            lowerBound.add((long) 0);
            upperBound.add(size);
        }


        return new BaseConstraints(lowerBound, upperBound);
    }

}
