package aki.packages.scep;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;

/**
 * Created by aakin on 2016-04-02.
 */
public final class FileWriter {

    private FileWriter() {}

    public static synchronized boolean write(String line, String path, boolean new_line, boolean append) {
        if (line != null && path != null) {
            try {
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
                Logger.error("MyFileWriter", e.getMessage());
                e.printStackTrace();
            }
            return false;
        }
        return false;
    }

    public static synchronized boolean write(byte[] line, String path, boolean new_line, boolean append) {
        if (line != null && path != null) {
            try {
                //If the file does not exist, it will be created in APPEND mode. It gets overriden in PRIVATE mode.
                File file = new File(path);
                if (!file.exists() && file.getParentFile() != null) {
                    file.getParentFile().mkdirs();
                    file.createNewFile();
                }
                FileOutputStream fos = new FileOutputStream(file, append);
                fos.write(line);
                if (new_line) fos.write("\n".getBytes());
                fos.close();
                return true;
            } catch (IOException e) {
                Logger.error("MyFileWriter", e.getMessage());
                e.printStackTrace();
            }
            return false;
        }
        Logger.error("MyFileWriter", path == null && line == null ? "Path and Line are null." :
                (path == null ? "Path is null." : "Line is null"));
        return false;
    }

    public static synchronized boolean safeByteArrayToFile(String path, byte[] array) {
        if (path == null) return false;

        try  {
            FileOutputStream fos = new FileOutputStream(path);
            fos.write(array);
            fos.close();
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
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
                Logger.error(FileWriter.class.getName(), "Couldn't write the object '"+o+"' (Hash # "+o.hashCode()+" - Class: "+o.getClass().getName()+")");
            }
        }
        return ok;
    }

    public static synchronized boolean append(String line, String path) {
        return write(line, path, true);
    }
}
