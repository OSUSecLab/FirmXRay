package main;

import base.ExecutionPath;
import core.BaseAddressSolver;
import core.ExecutionEngine;
import core.ExecutionPathFinder;
import core.STRInsSolver;
import ghidra.GhidraJarApplicationLayout;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageProvider;
import ghidra.program.model.listing.*;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.test.TestProgramManager;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TimeoutTaskMonitor;
import org.json.JSONArray;
import org.json.JSONObject;
import util.*;

import java.io.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class Main {

    private static Program program;
    private static long startTime;
    private static long endTime;

    public static void main(String[] args) throws
            IOException, VersionException, CancelledException, DuplicateNameException, InvalidNameException {

        startTime = System.currentTimeMillis();

        // Adjust the following
        String projectDirectoryName = Constant.DIRECTORY_NAME;

        final boolean DEBUG = false;
        String projectName = "FirmXRay";
        String programName;

        if (!DEBUG) {
            programName = args[0];
            Constant.MCU = args[1];
        }
        else {
            projectName = "FirmXRay";
            Constant.MCU = "Nordic";
            programName = "./examples/Nordic/example_nordic.bin";
            // programName = "./examples/TI/oad.bin";
        }
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
            return;
        }

        program = ghidraProject.importProgram(file, languageProvider.getLanguage(new LanguageID(Constant.ARM_CORTEX_LE_32)), null);

        // Initialize tag
        Logger.TAG = program.getName() + "@" + program.getExecutableMD5();


        try {
             getBase(programName, Logger.TAG, projectName);
        } catch (Exception e) {
           Logger.printE(e.toString());
        }


        if (Fileutil.isResultExist(Logger.TAG)) { // skip if result already exists
            System.out.println("Result already exist for " + Logger.TAG);
            return;
        }

        // analyze base address
        long base = BaseAddressUtil.getBaseAddressFromFile(Logger.TAG);
        if (base == -1) {
            Logger.printE("Base not found, using 0x00000000");
            base = 0;
        }


        Address add = program.getImageBase();
        try {
            program.setImageBase(add.getNewAddress(base), false);
        } catch (AddressOverflowException | LockException e) {
            e.printStackTrace();
            return;
        }

        // Display the Processor used by Ghidra
        System.out.println("Processor used : " + program.getLanguage().getProcessor().toString());

        // Analyze the loaded binary file
        int txId = program.startTransaction("Analysis");
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        mgr.initializeOptions();
        mgr.reAnalyzeAll(null);

        // The analysis will take sometime.
        System.out.println("Analyzing...");
        mgr.startAnalysis(TimeoutTaskMonitor.timeoutIn(Constant.DISASSEMBLE_TIMEOUT, TimeUnit.SECONDS));

        // Marked as analyzed
        GhidraProgramUtilities.setAnalyzedFlag(program, true);


        // Now to do something useful

        System.out.println("\n------------------ Starting Analysis ----------------\n");
        startTimeoutWatcher(Constant.TIMEOUT); // set timeout
        start();
        // getBase(programName);
        System.out.println("\n----------------- Ending Analysis ----------------\n");


        // Release Program
        programManager.release(program);

        // Close project without saving
        ghidraProject.setDeleteOnClose(true);
        ghidraProject.close();

    }

    private static void start() {

        // create address mapping

        Map<Integer, List<Address>> apis;
        if (Constant.MCU.equals("Nordic"))
            apis = FunctionUtil.locate_nordic(program);
        else
            apis = FunctionUtil.locate_TI(program);

        // solve all STR instructions
        // enabled when analyzing Nordic firmware because TI ones do not have many dependency on global vars
        if (Constant.MCU.equals("Nordic"))
            STRInsSolver.solveAllSTRIns(program);

        long pathNum = 0;

        JSONObject result = new JSONObject();
        result.put("Base", program.getImageBase().toString());
        result.put("Path", program.getExecutablePath());
        result.put("Vendor", Constant.MCU);


        for (int api: apis.keySet()) {
            List<Address> addresses = apis.get(api);
            List<ExecutionPath> paths = new ArrayList<>();

            JSONArray jsonArray = new JSONArray();
            for (Address add : addresses) {
                List<String> targetVarSet = Constant.getInitialTargetVars(api);

                paths = ExecutionPathFinder.findAllExecPaths(program, add, targetVarSet);

                if (paths == null) {
                    jsonArray.put(new JSONObject()); // put an empty object
                    continue;
                }

                pathNum += paths.size();

                for (ExecutionPath path : paths) {
                    ExecutionEngine engine = new ExecutionEngine(program, path, targetVarSet);
                    engine.execute();
                    engine.printResult();

                    // JSONObject r = engine.outputResult();
                    JSONObject r = ResultProcessor.ProcessResult(program, api, engine);
                    if (!JSONUtil.contains(jsonArray, r))
                        jsonArray.put(r);
                }
            }
            result.put(StringUtil.getAPIName(api), jsonArray);
        }

        endTime = System.currentTimeMillis();
        long totalTime = endTime - startTime;
        result.put("Time", totalTime);
        result.put("Path", pathNum);
        result.put("Size", program.getMaxAddress().getUnsignedOffset());

        // finish all apis
        Logger.printOutput(result.toString(4));
    }

    private static void getBase(String programName, String tag, String projectName) throws
            IOException, VersionException, CancelledException, DuplicateNameException, InvalidNameException {
        if (!BaseAddressUtil.isBaseInFile(tag)) {
            long base = BaseAddressSolver.getBaseAddressWithConstraint(programName, projectName);
            Fileutil.writeToFile("./base/base.txt", String.format("%s\t%d", tag, base), true);
        }
    }

    public static void startTimeoutWatcher(int sec) {
        Thread t = new Thread() {
            public void run() {
                try {
                    Thread.sleep(sec * 1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                // Logger.printOutput("TimeOut");
                Logger.printE("TimeOut!");
                System.exit(1);
            }
        };
        t.setDaemon(true);
        t.start();
    }

}
