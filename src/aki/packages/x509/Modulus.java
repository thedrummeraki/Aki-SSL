package aki.packages.x509;

import aki.packages.tools.*;

import java.io.File;
import java.util.ArrayList;

/**
 * Created by aakintol on 29/06/16.
 */
public final class Modulus {

    private Modulus() {}

    public static String get(String contents) {
        return get(contents, true);
    }

    public static String get(String contents, boolean cert) {
        return cert ? getFromCert(contents) : getFromKey(contents);
    }

    public static String get(File file) {
        return get(file, true);
    }

    public static String get(File file, boolean cert) {
        String contents = BashReader.toSingleString(true, FileReader.getLines(file));
        return cert ? getFromCert(contents) : getFromKey(contents);
    }

    private static String getFromCert(String contents) {
        File temp = new File("tmp/temp-modulus.pem");
        FileWriter.write(contents, temp.getPath());
        String[] args = {"openssl", "x509", "-noout", "-modulus", "-in", temp.getPath()};
        BashReader br = BashReader.read(args);
        if (br == null) {
            Logger.error("Modulus", String.format("The command \"%s\" from Modulus.getFromCert(String) was not valid.", BashReader.toSingleString(args)));
            return null;
        }
        if (br.getExitValue() != 0) {
            Logger.error("Modulus", String.format("The command \"%s\" from Modulus.getFromCert(String) exited with status of %s.", BashReader.toSingleString(args), br.getExitValue()));
            return null;
        }
        temp.delete();
        String output = br.getOutput();
        MD5 md5 = new MD5(output);
        return md5.asHex();
    }

    private static String getFromKey(String contents) {
        File temp = new File("tmp/temp-modulus.key");
        FileWriter.write(contents.trim(), temp.getPath());
        String[] args = {"openssl", "rsa", "-noout", "-modulus", "-in", temp.getPath()};
        BashReader br = BashReader.read(args);
        if (br == null) {
            Logger.debug("Modulus", "Attempt 1 for RSA failed (null).");
            args = new String[]{"openssl", "dsa", "-noout", "-modulus", "-in", temp.getPath()};
            br = BashReader.read(args);
            if (br == null) {
                Logger.error("Modulus", String.format("The command \"%s\" from Modulus.getFromKey(String) was not valid.", BashReader.toSingleString(args)));
                return null;
            }
        }
        if (br.getExitValue() != 0) {
            Logger.warn("Modulus", "Attempt 2 for RSA failed (errno "+br.getExitValue()+": "+br.getErrorMessage().trim()+")");
            args = new String[]{"openssl", "dsa", "-noout", "-modulus", "-in", temp.getPath()};
            br = BashReader.read(args);
            if (br == null) {
                Logger.error("Modulus", String.format("The command \"%s\" from Modulus.getFromKey(String) was not valid.", BashReader.toSingleString(args)));
                return null;
            }
            if (br.getExitValue() != 0) {
                Logger.error("Modulus", String.format("The command \"%s\" from Modulus.getFromKey(String) exited with status of %s.", BashReader.toSingleString(args), br.getExitValue()));
                return null;
            }
        }
        temp.delete();
        String output = br.getOutput();
        MD5 md5 = new MD5(output);
        return md5.asHex();
    }

    public static void main(String[] args) {
        String command = "openssl x509 -noout -modulus -in tmp/temp-modulus.pem | openssl md5";
        try {
            String[] argss = {"openssl x509 -noout -modulus -in tmp/temp-modulus.pem"};
            ArrayList<String> execute = BashReader.execute(argss);
            Logger.debug("Done");
            BashReader br = BashReader.read(argss);
            Logger.debug(""+br.getOutput());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
