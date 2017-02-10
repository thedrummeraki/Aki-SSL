/**
 * Created by aakintol on 01/06/16.
 */
package aki.packages.tools;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;

/**
 * Created by aakin on 2016-04-02.
 */
public final class MyFileWriter {

    private static final String[] DIGITS = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"};
    private static final String[] HEX_LETTERS = {"A", "B", "C", "D", "E", "F"};
    private static final String[] LETTERS = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"};

    private MyFileWriter() {}

    public static synchronized boolean write(String line, String path, boolean new_line, boolean append) {
        if (line != null && path != null) {
            try {
                line = line.trim();
                //If the file does not exist, it will be created in APPEND mode. It gets overriden in PRIVATE mode.
                File file = new File(path);
                if (!file.exists() && file.getParentFile() != null) {
                    file.getParentFile().mkdirs();
                    file.createNewFile();
                }
                FileOutputStream fos = new FileOutputStream(file, append);
                fos.write((line+(new_line ? "\n" : "")).getBytes());
                fos.close();
                return true;
            } catch (IOException e) {
                MyLogger.error("MyFileWriter", e.getMessage());
                e.printStackTrace();
            }
            return false;
        }
        MyLogger.error("MyFileWriter", "Either the line or/and the path is/are null.");
        return false;
    }

    public static synchronized boolean write(byte[] line, String path, boolean new_line, boolean append) {
        if (line != null && path != null) {
            try {
                //If the file does not exist, it will be created in APPEND mode. It gets overriden in PRIVATE mode.
                File file = new File(path);
                if (!file.exists()) {
                    file.getParentFile().mkdirs();
                    file.createNewFile();
                }
                FileOutputStream fos = new FileOutputStream(file, append);
                fos.write(line);
                if (new_line) fos.write("\n".getBytes());
                fos.close();
                return true;
            } catch (IOException e) {
                MyLogger.error("MyFileWriter", e.getMessage());
                e.printStackTrace();
            }
            return false;
        }
        MyLogger.error("MyFileWriter", path == null && line == null ? "Path and Line are null." :
                (path == null ? "Path is null." : "Line is null"));
        return false;
    }

    public static synchronized boolean write(String line, String path, boolean append) {
        return write(line, path, true, append);
    }

    public static synchronized boolean write(String line, String path) {
        return write(line, path, false);
    }

    public static synchronized boolean write(List<?> list, String path) {
        boolean ok = true;
        for (Object o : list) {
            ok = append(o.toString(), path);
            if (!ok) {
                MyLogger.error(MyFileWriter.class.getName(), "Couldn't write the object '"+o+"' (Hash # "+o.hashCode()+" - Class: "+o.getClass().getName()+")");
            }
        }
        return ok;
    }

    public static synchronized boolean write(List<?> list, String path, boolean append) {
        if (!append) {
            new File(path).delete();
        }
        boolean ok = true;
        for (Object o : list) {
            ok = append(o.toString(), path);
            if (!ok) {
                MyLogger.error(MyFileWriter.class.getName(), "Couldn't write the object '"+o+"' (Hash # "+o.hashCode()+" - Class: "+o.getClass().getName()+")");
            }
        }
        return ok;
    }

    public static synchronized boolean append(String line, String path) {
        return write(line, path, true);
    }

    public static String dumpFilename(int length, boolean hex, String extension) {
        String filename;
        if (extension == null) {
            extension = ".txt";
        }
        if (!extension.startsWith(".") && !extension.isEmpty()) {
            extension = "." + extension;
        }
        if (length < 1) {
            length = 20;
        }
        String dummyFilename = "";
        int pos = 0;
        String[] letters = hex ? HEX_LETTERS : LETTERS;
        int maxRandomIndex = letters.length;
        while (pos < length) {
            // Random letter or digit
            int choice = (int) ((Math.random()*2));
            int ranIndex;
            if (choice == 0) {
                ranIndex = (int) ((Math.random()*maxRandomIndex));
                dummyFilename += letters[ranIndex];
            } else {
                ranIndex = (int) ((Math.random()*DIGITS.length));
                dummyFilename += DIGITS[ranIndex];
            }
            pos++;
        }
        filename = dummyFilename + extension;
        return filename;
    }
}