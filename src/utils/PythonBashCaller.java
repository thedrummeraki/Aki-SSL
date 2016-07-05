package utils;

import tools.BashReader;

/**
 * Created by aakintol on 05/07/16.
 */
public final class PythonBashCaller {

    private static final String SCRIPT_FILE = "bash.py";

    private PythonBashCaller() {}

    public static int call(String command) {
        String[] args = {"python", SCRIPT_FILE, command};
        BashReader br = BashReader.read(args);
        if (br == null) {
            return Constants.NULL_OBJECT_RESULT_ERROR;
        }
        return br.getExitValue();
    }

    public static int call(String... args) {
        return call(BashReader.toSingleString(args));
    }

}
