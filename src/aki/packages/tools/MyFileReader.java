package aki.packages.tools;

/**
 * Created by aakintol on 01/06/16.
 */

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;

/**
 * Created by aakin on 2016-04-02.
 */
public final class MyFileReader {

    private MyFileReader() {}

    private static ArrayList<String> getLines(String path) {
        if (path != null) {
            try {
                FileInputStream fis = new FileInputStream(new File(path));
                InputStreamReader isr = new InputStreamReader(fis);
                BufferedReader br = new BufferedReader(isr);

                String line;
                ArrayList<String> list = new ArrayList<String>();
                while ((line = br.readLine()) != null) {
                    list.add(line);
                }

                br.close();
                fis.close();

                return list;
            } catch (IOException e) {
                e.printStackTrace();
                MyLogger.error("MyFileReader", e.getMessage());
            }
            return null;
        }
        MyLogger.error("MyFileReader", "The path is null.");
        return null;
    }

    private static ArrayList<String> getLinesAndThrow(String path) throws IOException {
        if (path != null) {
            FileInputStream fis = new FileInputStream(new File(path));
            InputStreamReader isr = new InputStreamReader(fis);
            BufferedReader br = new BufferedReader(isr);

            String line;
            ArrayList<String> list = new ArrayList<String>();
            while ((line = br.readLine()) != null) {
                list.add(line);
            }

            br.close();
            fis.close();

            return list;
        }
        MyLogger.error("MyFileReader", "The path is null.");
        return null;
    }

    public static ArrayList<String> getLines(String... paths) {
        ArrayList<String> ps = new ArrayList<String>();
        for (String path : paths) {
            ArrayList<String> lines;
            try {
                 lines = getLines(path);
            } catch (Exception e) {
                return ps;
            }
            if (lines == null) continue;
            ps.addAll(lines);
        }
        return ps;
    }

    public static ArrayList<String> getLinesAndThrow(String... paths) throws IOException {
        ArrayList<String> ps = new ArrayList<>();
        for (String path : paths) {
            ArrayList<String> lines = getLinesAndThrow(path);
            if (lines == null) continue;
            ps.addAll(lines);
        }
        return ps;
    }

    public static ArrayList<String> getLines(File... files) {
        ArrayList<String> ps = new ArrayList<String>();
        for (File path : files) {
            ArrayList<String> lines;
            try {
                 lines = getLines(path.getPath());
            } catch (Exception e) {
                return ps;
            }
            if (lines == null) continue;
            ps.addAll(lines);
        }
        return ps;
    }

    public static int indexOf(String line, String path) {
        if (path != null && line != null) {
            try {
                return getLines(path).indexOf(line);
            } catch (NullPointerException e) {
                return -1;
            }
        }
        return -1;
    }
}