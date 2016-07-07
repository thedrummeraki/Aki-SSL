/**
 * Created by aakintol on 01/06/16.
 */

package aki.packages.tools;

import java.util.ArrayList;

/**
 * Created by aakin on 2016-05-16.
 */
public final class Logger {

    public static final String LOG_PATH = "logs.log";
    private static final String DEFAULT_MESSAGE = "CBNCA Management Class";

    private Logger() {}

    public static void error(String tag, String message, boolean save) {
        System.err.println("[ERROR]: " + tag + " - " + message);
        if (save) save("[ERROR]: ", message);
    }

    public static void error(String tag, String message) {
        error(tag, message, false);
    }

    public static void error(Class<?> _class, String message, boolean save) {
        error(_class != null ? _class.getSimpleName() : DEFAULT_MESSAGE, message, save);
    }

    public static void error(String message) {
        error(DEFAULT_MESSAGE, message);
    }

    public static void debug(String tag, String message, boolean save) {
    	System.out.println("[DEBUG]: " + tag + " - " + message);
        if (save) save("[DEBUG]: ", message);
    }

    public static void debug(String tag, String message) {
        debug(tag, message, false);
    }

    public static void debug(Class<?> _class, String message, boolean save) {
        debug(_class != null ? _class.getSimpleName() : DEFAULT_MESSAGE, message, save);
    }

    public static void debug(String message) {
        debug(DEFAULT_MESSAGE, message);
    }

    public static void warn(String tag, String message, boolean save) {
    	System.err.println("[WARN]: " + tag + " - " + message);
        if (save) save("[WARN]: ", message);
    }


    public static void warn(String tag, String message) {
        warn(tag, message, false);
    }

    public static void warn(Class<?> _class, String message, boolean save) {
        warn(_class != null ? _class.getSimpleName() : DEFAULT_MESSAGE, message, save);
    }

    public static void warn(String message) {
        warn(DEFAULT_MESSAGE, message);
    }

    public static void info(String tag, String message, boolean save) {
    	System.out.println("[INFO]: " + tag + " - " + message);
        if (save) save("[INFO]: ", message);
    }

    public static void info(String tag, String message) {
        info(tag, message, false);
    }

    public static void info(Class<?> _class, String message, boolean save) {
        info(_class != null ? _class.getSimpleName() : DEFAULT_MESSAGE, message, save);
    }

    public static void info(String message) {
        info(DEFAULT_MESSAGE, message);
    }

    public static void verbose(String tag, String message, boolean save) {
    	System.out.println("[VERBOSE]: " + tag + " - " + message);
        if (save) save("[VERBOSE]: ", message);
    }

    public static void verbose(String tag, String message) {
        verbose(tag, message, false);
    }

    public static void verbose(Class<?> _class, String message, boolean save) {
        verbose(_class != null ? _class.getSimpleName() : DEFAULT_MESSAGE, message, save);
    }

    public static void verbose(String message) {
        verbose(DEFAULT_MESSAGE, message);
    }

    private static boolean save(String type, String message) {
        return FileWriter.append(type+message, LOG_PATH);
    }

    public static ArrayList<String> getLogHistory() {
        return FileReader.getLines(LOG_PATH);
    }

    public static void printOut(Object object) {
        System.out.println(object);
    }

    public static void errorOut(Object object) {
        System.err.println(object);
    }
}