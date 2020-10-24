package main;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

import static util.Fileutil.writeToFile;

public class Logger {

    public static String TAG;
    public static boolean log = false;

    public static void initLogFiles() {
        writeToFile("./logs/warnning.txt", "", false);
        writeToFile("./logs/error.txt", "", false);
    }

    public static void print(String s) {
        if (log)
            System.out.println(s);
    }

    public static String getDate() {
        SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
        Date date = new Date();
        return formatter.format(date);
    }

    public static void printW(String args) {
        String str = "[W] " + TAG + " " + args;
        Logger.print(str);
        writeToFile("./logs/warnning.txt", str, false);
    }

    public static void printE(String args) {
        String str = "[E] " + getDate() + " " + TAG + " " + args;
        System.out.println(str);
        writeToFile("./logs/error.txt", str, true);
    }


    public static void printOutput(String args) {
        System.out.println(args);
        writeToFile(String.format("./output/%s", TAG), args, false);
    }



}
