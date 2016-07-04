package tools;

import org.omg.PortableInterceptor.INACTIVE;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;

/**
 * Created by aakintol on 01/06/16.
 */
public final class BashReader {

    private ArrayList<String> lines;
    private String output;
    private int exitValue;
    private String command;

    private BashReader(ArrayList<String> lines, String output, int exitValue) {
        this.lines = lines;
        this.output = output;
        this.exitValue = exitValue;
    }

    public ArrayList<String> getLines() {
        return lines;
    }

    public String getOutput() {
        if (output == null) {
            return "";
        }
        return output.trim();
    }

    public String getCommand() {
        return command;
    }

    public int getExitValue() {
        return exitValue;
    }

    public BashReader setCommand(String command) {
        this.command = command;
        return this;
    }

    public static BashReader read(String... subCommands) {
        String command = "";
        for (String s : subCommands) {
            command += (s + " ");
        }
        try {
            return readAndThrow(command);
        } catch (Exception e) {
            Logger.error(e.getClass(), e.getMessage(), true);
            return null;
        }
    }

    public static BashReader read(Object... subCommands) {
        String command = "";
        for (Object o : subCommands) {
            command += (o + " ");
        }
        try {
            return readAndThrow(command);
        } catch (Exception e) {
            Logger.error(e.getClass(), e.getMessage(), true);
            return null;
        }
    }

    public static BashReader readAndThrow(String... subCommands) throws IOException, InterruptedException {
        String command = "";
        for (String s : subCommands) {
            command += (s + " ");
        }
        return readAndThrow(command);
    }

    public static BashReader readAndThrow(String command) throws IOException, InterruptedException {
        Runtime runtime = Runtime.getRuntime();
        Process process = runtime.exec(command);
        InputStream is = process.getInputStream();
        InputStreamReader isr = new InputStreamReader(is);
        BufferedReader br = new BufferedReader(isr);
        StringBuilder sb = new StringBuilder();
        String line;

        ArrayList<String> output = new ArrayList<String>();

        while ((line = br.readLine()) != null) {
            output.add(line);
            sb.append(line).append("\n");
        }

        process.waitFor();
        BashReader bre = new BashReader(output, sb.toString(), process.exitValue());
        return bre.setCommand(command);
    }

    public static ArrayList<String> execute(String... subCommands) {
        String command = "";
        for (String s : subCommands) {
            command += (s + " ");
        }
        return execute(command);
    }

    public static ArrayList<String> execute(String command) {
        return execute(command, true);
    }

    public static ArrayList<String> execute(String command, boolean saveToLog) {
        try {
            return executeAndThrow(command, saveToLog);
        } catch (Exception e) {
            Logger.error(BashReader.class, e.getMessage(), saveToLog);
            return null;
        }
    }

    public static ArrayList<String> executeAndThrow(String command, boolean saveToLog) throws IOException {
        return executeAndThrow(command, false, saveToLog);
    }

    public static ArrayList<String> executeAndThrow(String command, boolean log, boolean saveToLog) throws IOException {
        command = command.trim();
        Runtime runtime = Runtime.getRuntime();
        Process process = runtime.exec(command);
        int code;
        try {
            code = process.waitFor();
        } catch (InterruptedException e) {
            code = Integer.MIN_VALUE;
            e.printStackTrace();
        }
        InputStream is = process.getInputStream();
        InputStreamReader isr = new InputStreamReader(is);
        BufferedReader br = new BufferedReader(isr);
        String line;

        ArrayList<String> output = new ArrayList<String>();

        if (log)
            Logger.info(command, "Output", saveToLog);
        while ((line = br.readLine()) != null) {
            if (log)
                Logger.info("", line, saveToLog);
            output.add(line);
        }
        Logger.info("BashReader", "Command executed: "+command+ (output.isEmpty() ? ". No output." : ".")+" Exited with code ("+code+").");
        return output;
    }

    public static String toSingleString(ArrayList<String> strings) {
        String s = "";
        if (strings != null) {
            for (String s1 : strings) {
                s += s1 + '\n';
            }
        }
        return s.trim();
    }

    public static String toSingleString(Object... args) {
        String s = "";
        if (args != null) {
            for (Object s1 : args) {
                s += s1 + " ";
            }
        }
        return s.trim();
    }
}
