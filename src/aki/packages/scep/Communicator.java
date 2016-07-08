package aki.packages.scep;

import aki.packages.tools.BashReader;
import aki.packages.tools.Logger;
import aki.packages.utils.VerifyUtils;
import aki.packages.x509.*;
import aki.packages.tools.FileReader;
import aki.packages.tools.FileWriter;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created by aakintol on 30/06/16.
 */
public final class Communicator {

    public static String[] PRIMARY_OPTIONS = {
            "sign",
            "keygen"
    };

    public static String[] SIGN_OPTIONS = {
            "-in",
            "-signer",
            "-inkey",
            "-out"
    };

    public static String[] KEYGEN_OPTTONS = {
            "-alg",
            "-bits",
            "-keyout",
            "-certout"
    };

    private Communicator() {}

    public static void main(String[] args) {
        if (args.length == 0) {
            showUsage();
            System.exit(0);
        }
        ArrayList<String> options = new ArrayList<>();
        // Get the primary option.
        String primary = args[0];
        if (!isPrimaryOption(primary)) {
            showUsage("Invalid option: "+primary);
            System.exit(1);
        }

        if (primary.equalsIgnoreCase("sign")) {
            int exec = execSign(args);
        }

        if (primary.equalsIgnoreCase("keygen")) {
            int exec = execKeyGen(args);
            System.exit(exec);
        }
    }

    private static ArrayList<String> checkForMissingSuboption(String primaryOption, String[] _args) {
        List<String> args = Arrays.asList(_args);
        ArrayList<String> missing = new ArrayList<>();
        switch (primaryOption.toLowerCase()) {
            case "sign" :
                for (String s : SIGN_OPTIONS) {
                    if (!args.contains(s)) missing.add(s);
                }
                break;
            case "keygen":
                for (String s : KEYGEN_OPTTONS) {
                    if (!args.contains(s)) missing.add(s);
                }
        }
        return missing;
    }

    private static boolean isPrimaryOption(String option) {
        for (String o : PRIMARY_OPTIONS) {
            if (o.equalsIgnoreCase(option)) return true;
        }
        return false;
    }

    private static void catchNonExistingFiles(String... filenames) {
        for (String filename : filenames) {
            if (!new File(filename).exists()) {
                showUsage(filename+ " does not exist.");
                System.exit(1);
            }
        }
    }

    private static int execKeyGen(String[] _args) {
        List<String> missingSuboptions = checkForMissingSuboption("keygen", _args);
        if (!missingSuboptions.isEmpty()) {
            showUsage("Missing option(s) for keygen: "+missingSuboptions);
            System.exit(1);
        }

        if (_args.length < 8) {
            showUsage("Impossible use of commands.");
            System.exit(1);
        }

        try {
            List<String> args = Arrays.asList(_args);
            String alg = args.get(args.indexOf("-alg")+1);
            String _bits = args.get(args.indexOf("-bits")+1);
            String keyout = args.get(args.indexOf("-keyout")+1);
            String certout = args.get(args.indexOf("-certout")+1);

            int bits;
            try {
                bits = Integer.parseInt(_bits);
            } catch (NumberFormatException e) {
                System.out.println("Invalid integer: "+_bits);
                return 1;
            }

            String format;
            if (args.contains("-format")) {
                format = args.get(args.indexOf("-format")+1);
            } else {
                format = "PEM";
            }

            Signable signable = new Signable();
            Subject subject;
            try {
                subject = Subject.load("/C=CA");
            } catch (CertificateException e) {
                e.printStackTrace();
                return 1;
            }
            return VerifyUtils.generateKey(alg, bits, new File(keyout), new File(certout), signable, subject);

        } catch (IndexOutOfBoundsException e) {
            showUsage("Impossible use of commands (misplaced or missing attributes).");
            System.exit(1);
        }

        return 0;
    }

    private static int execSign(String[] _args) {
        List<String> missingSuboptions = checkForMissingSuboption("sign", _args);
        if (!missingSuboptions.isEmpty()) {
            showUsage("Missing option(s) for sign: "+missingSuboptions);
            System.exit(1);
        }

        if (_args.length < 8) {
            showUsage("Impossible use of commands.");
            System.exit(1);
        }

        try {
            List<String> args = Arrays.asList(_args);
            String in = args.get(args.indexOf("-in")+1);
            String signer = args.get(args.indexOf("-signer")+1);
            String inkey = args.get(args.indexOf("-inkey")+1);
            String out = args.get(args.indexOf("-out")+1);

            String format;
            if (args.contains("-format")) {
                format = args.get(args.indexOf("-format")+1);
            } else {
                format = "PEM";
            }

            catchNonExistingFiles(in, inkey, signer);

            Signable signable = new Signable();
            signable.setContents(BashReader.toSingleString(true, FileReader.getLines(in)));
            try {
                signable.setCertSigner(Certificate.loadCertificateFromFile(signer));
                signable.setPrivateKeySigner(PrivateKey.loadPrivateKey(new File(inkey)));
            } catch (CertificateException e) {
                Logger.error(e.getClass(), e.getMessage(), false);
                System.exit(400);
            }

            int status = signable.sign(null, null, null);
            if (status == 0)
                FileWriter.write(format.equalsIgnoreCase("DER") ? signable.getDERSignedDataAsString() : signable.getSignedDataPEM(), out);
            return status;

        } catch (IndexOutOfBoundsException e) {
            showUsage("Impossible use of commands (misplaced or missing attributes).");
            System.exit(1);
        }

        return 0;
    }

    private static void showUsage(String message) {
        System.out.println(message);
        showUsage();
    }

    private static void showUsage() {
        System.out.println(USAGE);
    }

    private static final String USAGE = BashReader.toSingleString(true, FileReader.getLines("usage.txt"));
}
