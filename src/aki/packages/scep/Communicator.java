package aki.packages.scep;

import aki.packages.tools.BashReader;
import aki.packages.tools.Logger;
import aki.packages.utils.VerifyUtils;
import aki.packages.x509.*;
import aki.packages.tools.FileReader;
import aki.packages.tools.FileWriter;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created by aakintol on 30/06/16.
 */
public final class Communicator {

    private static String USAGE;

    static {
        try {
            USAGE = BashReader.toSingleString(true, FileReader.getLinesAndThrow("usage.txt"));
        } catch (IOException e) {
            USAGE = "Usage: java Communicator [option] [-suboptions].\n" +
                    "\n" +
                    "List of [options]:\n" +
                    "    sign (-in data.txt -signer signer.crt -inkey -signer.key -out output.txt -format [PEM (default) or DER])\n" +
                    "    sign2 (-signer signer.pem -inkey signer-key.der -out output.der -status 0|1|2 -ca my-ca.pem)\n" +
                    "    keygen (-alg RSA|DSA -bits [#bits for private key] -keyout new.key -certout new.cert)\n" +
                    "   \n" +
                    "Note: For the option \"sign2\", the tag \"-status\" takes the integers 0 to 2. 0 is the SCEP status \"SUCESS\", 1 \"FAILURE\" and 2 \"PENDING\".";
        }
    }

    public final static String[] PRIMARY_OPTIONS = {
            "sign",
            "keygen",
            "sign2",
            "clear",
            "req"
    };

    public final static String[] SIGN_OPTIONS = {
            "-in",
            "-signer",
            "-inkey",
            "-out"
    };

    public final static String[] SIGN2_OPTIONS = {
            "-signer",
            "-inkey",
            "-status",
            "-transid",
            "-recnonce",
            "-sendnonce",
            "-failinfo",
            "-reccert",
            "-cert",
            "-out"
    };

    public final static String[] SIGN2_MANDATORY_OPTIONS = {
            "-signer",
            "-inkey",
            "-status",
            "-out",
            "-ca"
    };

    public final static String[] KEYGEN_OPTTONS = {
            "-alg",
            "-bits",
            "-keyout",
            "-certout"
    };

    public final static String[] REQ_OPTIONS = {
            "-public",
            "-private",
            "-subject",
            "-basic_con",
            "-key_usage",
            "-ski"
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
            System.exit(exec);
        }

        if (primary.equalsIgnoreCase("keygen")) {
            int exec = execKeyGen(args);
            System.exit(exec);
        }

        if (primary.equalsIgnoreCase("sign2")) {
            int exec = execSign2(args);
            System.exit(exec);
        }

        if (primary.equalsIgnoreCase("req")) {
            int exec = execReq(args);
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
                break;
            case "sign2":
                for (String s : SIGN2_MANDATORY_OPTIONS) {
                    if (!args.contains(s)) missing.add(s);
                }
                break;
            case "req":
                for (String s : REQ_OPTIONS) {
                    if (!args.contains(s)) missing.add(s);
                }
        }
        return missing;
    }

    private static ArrayList<String> checkForMissingOptionalSuboptions(String primaryOption, String[] _args) {
        List<String> args = Arrays.asList(_args);
        ArrayList<String> missing = new ArrayList<>();
        switch (primaryOption.toLowerCase()) {
            case "sign2":
                for (String s : SIGN2_OPTIONS) {
                    if (!args.contains(s)) missing.add(s);
                }
                break;
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

        if (_args.length < KEYGEN_OPTTONS.length * 2) {
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

        if (_args.length < SIGN_OPTIONS.length * 2) {
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

    private static int execSign2(String[] _args) {
        List<String> missingSuboptions = checkForMissingSuboption("sign2", _args);
        if (!missingSuboptions.isEmpty()) {
            showUsage("Missing option(s) for sign2: "+missingSuboptions);
            System.exit(1);
        }

        if (_args.length < 8) {
            showUsage("Impossible use of commands.");
            System.exit(1);
        }

        List<String> args = Arrays.asList(_args);

        // Mandatory arguments
        final String signer = args.get(args.indexOf("-signer")+1);
        final String inkey = args.get(args.indexOf("-inkey")+1);
        final String out = args.get(args.indexOf("-out")+1);
        final String status = args.get(args.indexOf("-status")+1);
        final String ca = args.get(args.indexOf("-ca")+1);

        // Optional arguments
        String senderNonce;
        if (args.contains("-sendnonce")) {
            try {
                senderNonce = args.get(args.indexOf("-sendnonce") + 1);
            } catch (Exception e) {

                senderNonce = null;
            }
        } else {
            senderNonce = null;
        }
        String transactionID;
        if (args.contains("-transid")) {
            try {
                transactionID = args.get(args.indexOf("-transid")+1);
            } catch (Exception e) {
                transactionID = null;
            }
        } else {
            transactionID = null;
        }
        String recipientNonce;
        if (args.contains("-recnonce")) {
            try {
                recipientNonce = args.get(args.indexOf("-recnonce")+1);
            } catch (Exception e) {
                recipientNonce = null;
            }
        } else {
            recipientNonce = null;
        }

        String failureInfo;
        boolean provided = true;
        if (args.contains("-failinfo")) {
            try {
                failureInfo = args.get(args.indexOf("-failinfo")+1);
            } catch (Exception e) {
                failureInfo = null;
                provided = false;
            }
        } else {
            failureInfo = null;
        }

        if (failureInfo == null && !provided) {
            throw new IllegalArgumentException("You failed to provide a valid fail info.");
        }
        FailInfo failInfo;
        if (failureInfo != null) {
            int fi;
            try {
                fi = Integer.parseInt(failureInfo);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("The fail info provided is not a valid positive integer.");
            }
            if (fi < 0) {
                throw new IllegalArgumentException("The fail info provided is not a valid positive integer.");
            }
            failInfo = FailInfo.init(fi);
        } else {
            failInfo = null;
        }

//        String format;
//        if (args.contains("-format")) {
//            format = args.get(args.indexOf("-format")+1);
//        } else {
//            format = "PEM";
//        }

        catchNonExistingFiles(inkey, signer);

        SCEP scep = new SCEP();

        int res = scep.setSignerCertFromFile(signer);
        if (res != 0) {
            return res;
        }
        res = scep.setPrivateKeyFromFile(inkey);
        if (res != 0) {
            return res;
        }

        try {
            Integer.parseInt(status);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid status: "+status+". Expected 0 (success), 1 (failure) or 2 (pending).");
        }

        switch (status) {
            case "0": scep.setSuccess(); break;
            case "1": scep.setFailure(); break;
            case "2": scep.setPending(); break;
            default: throw new IllegalArgumentException("Invalid status: "+status+". Expected 0 (success), 1 (failure) or 2 (pending).");
        }

        if (scep.isSuccess()) {
            // Make sure the recipient certificate and the certificate have been provided.
            String recipientCert;
            if (args.contains("-reccert")) {
                try {
                    recipientCert = args.get(args.indexOf("-reccert")+1);
                } catch (Exception e) {
                    recipientCert = null;
                }
            } else {
                recipientCert = null;
            }
            scep.setRecipientCertFromFile(recipientCert);

            String certCert;
            if (args.contains("-cert")) {
                try {
                    certCert = args.get(args.indexOf("-cert")+1);
                } catch (Exception e) {
                    certCert = null;
                }
            } else {
                certCert = null;
            }
            res = scep.setCertFromFile(certCert);
            if (res != 0) {
                throw new IllegalArgumentException("You need to set a VALID certificate for the success response.");
            }
        }

        scep.setCaCertFromFile(ca);
        scep.setFailInfo(failInfo);
        scep.setTransactionId(transactionID);
        scep.setSenderNonce(senderNonce);
        scep.setRecipientNonce(recipientNonce);

        return scep.signData(scep.getStatus(), out);
    }

    private static int execReq(String[] _args) {
        List<String> args = Arrays.asList(_args);

        List<String> missingSuboptions = checkForMissingSuboption("req", _args);
        if (!missingSuboptions.isEmpty()) {
            showUsage("Missing option(s) for req: "+missingSuboptions);
            System.exit(1);
        }

        if (_args.length < REQ_OPTIONS.length * 2) {
            showUsage("Impossible use of commands.");
            System.exit(1);
        }

        String pubkeyFilename = args.get(args.indexOf("-public")+1);
        String privkeyFilename = args.get(args.indexOf("-private")+1);
        String subject = args.get(args.indexOf("-subject")+1);
        boolean basicCon = Boolean.valueOf(args.get(args.indexOf("-basic_con")+1));
        boolean keyUsage = Boolean.valueOf(args.get(args.indexOf("-key_usage")+1));
        byte[] ski = args.get(args.indexOf("-ski")+1).getBytes();

        return MakeA.certificateRequest(pubkeyFilename, privkeyFilename, subject, basicCon, keyUsage, ski);
    }

    private static void showUsage(String message) {
        System.out.println(message);
        showUsage();
    }

    private static void showUsage() {
        System.out.println(USAGE);
    }
}
