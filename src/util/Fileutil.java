package util;

import java.io.*;

public class Fileutil {

    public static void writeToFile(String path, String content, boolean append) {
        try {
            PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(path, append)));
            out.println(content);
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static boolean isResultExist(String tag) {
        File file = new File("./output");
        String[] files = file.list();
        if (files == null)
            return false;

        for (String fname : files) {
            if (fname.equals(tag))
                return true;
        }

        return false;
    }

}
