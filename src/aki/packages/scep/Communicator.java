package aki.packages.scep;

import aki.packages.tools.BashReader;
import aki.packages.tools.MyFileReader;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.util.*;

/**
 * Created by aakintol on 30/06/16.
 */
/**
 * This class is used to sign data data from a file, create PKCS7 signed data, creating a certificate request,
 * or generating a certificate and it's private key.
 * Run the main method without any arguments to see the available options.
 * */
public final class Communicator {

    /**
     * Usage string. Printed out when no or wrong arguments are passed in the main method of this class.
     * */
    private static String USAGE;

    static {
        try {
            USAGE = BashReader.toSingleString(true, MyFileReader.getLinesAndThrow("usage.txt"));
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

    /**
     * All of the primary options available for using this class.
     *
     * */
    public final static String[] PRIMARY_OPTIONS = {
            "sign2",
            "req",
            "cmp-ecdsa-gen"
    };

    /**
     * Sub-options used for primary option 'sign2'. Create PKCS7 signed data for a SCEP response!
     *
     * MANDATORY:
     * -signer: The certificate file PEM (base64 with headers and footers) encoded. (needs to exist)
     * -inkey: The certificate's private key DER (ANS1) encoded. (needs to exist)
     * -status: The SCEP status
     * -transid: The SCEP request's transaction ID
     * -recnonce: The SCEP recipient nonce
     * -sendnonce: The SCEP sender nonce
     * -failinfo: The SCEP fail info (optional, but needed for failure responses)
     * -reccert: The SCEP recipient certificate (needs to exist)
     * -cert: The SCEP client certificate (needs to exist)
     * -out: The result's file
     *
     * @see ResponseStatus
     * @see FailInfo
     * */
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

    /**
     * Sub-options that are expected from the primary option 'sign2'.
     * */
    public final static String[] SIGN2_MANDATORY_OPTIONS = {
            "-signer",
            "-inkey",
            "-status",
            "-out",
            "-ca"
    };

    /**
     * Sub-options used for primary option 'req'. Generate a certificate request, 'request.out'!
     *
     * Do not use this method, it is deprecated. Use openssl or pyopenssl if possible.
     * */
    @Deprecated
    public final static String[] REQ_OPTIONS = {
            "-public",
            "-private",
            "-subject",
            "-basic_con",
            "-key_usage",
            "-ski"
    };

    /**
     * Sub-options for primary option 'cmp-ecdsa-gen'.
     * */
    public final static String[] CPM_ECDSA_OPTIONS = {
            "-privout",
            "-pubout",
            "-curve"
    };

    /**
     * Sub-options for primary option 'cmp-ecdsa-gen'.
     * */
    public final static String[] CPM_MANDATORY_ECDSA_OPTIONS = {
            "-privout"
    };

    private Communicator() {}

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
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

        if (primary.equalsIgnoreCase("sign2")) {
            int exec = execSign2(args);
            System.exit(exec);
        }

        if (primary.equalsIgnoreCase("req")) {
            int exec = execReq(args);
            System.exit(exec);
        }

        if (primary.equalsIgnoreCase("cmp-ecdsa-gen")) {
            System.exit(execCMPECDSA(args));
        }
    }

    /**
     * Check if any sub-options from the specified primary option are missing.
     *
     * @return The array of missing sub-options.
     * */
    private static ArrayList<String> checkForMissingSuboption(String primaryOption, String[] _args) {
        List<String> args = Arrays.asList(_args);
        ArrayList<String> missing = new ArrayList<>();
        switch (primaryOption.toLowerCase()) {
            case "sign2":
                for (String s : SIGN2_MANDATORY_OPTIONS) {
                    if (!args.contains(s)) missing.add(s);
                }
                break;
            case "req":
                for (String s : REQ_OPTIONS) {
                    if (!args.contains(s)) missing.add(s);
                }
            case "cmp-ecdsa-gen":
                for (String s : CPM_MANDATORY_ECDSA_OPTIONS) {
                    if (!args.contains(s)) missing.add(s);
                }
        }
        return missing;
    }

    /**
     * Check whether or not the specified option is a primary option.
     *
     * @return whether or not the specified option is a primary option.
     * */
    private static boolean isPrimaryOption(String option) {
        for (String o : PRIMARY_OPTIONS) {
            if (o.equalsIgnoreCase(option)) return true;
        }
        return false;
    }

    /**
     * Check if all specified filenames exist or not. System.exit with exit status 1 is called if one of the filenames
     * does not exist.
     * */
    private static void catchNonExistingFiles(String... filenames) {
        for (String filename : filenames) {
            if (!new File(filename).exists()) {
                showUsage(filename+ " does not exist.");
                System.exit(1);
            }
        }
    }


    /**
     * Executes the primary option 'sign2'
     *
     * @return the exit status code
     * */
    private static int execSign2(String[] _args) {
        // Get any missing sub-options and exit with status 1 if a file is missing.
        List<String> missingSuboptions = checkForMissingSuboption("sign2", _args);
        if (!missingSuboptions.isEmpty()) {
            showUsage("Missing option(s) for sign2: "+missingSuboptions);
            System.exit(1);
        }

        // Check to see if there is a reasonable number of arguments and exit with status 1 if not.
        // Why 10? There are 5 mandatory arguments, so having a reasonable amount of arguments means
        // that there needs to be 5 pairs arguments, so 10 arguments.
        if (_args.length < 10) {
            showUsage("Impossible use of commands.");
            System.exit(1);
        }

        // Get the required arguments
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

        // Check if a -failinfo argument is passed in but no actual info is passed in
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

        // Check if the certificate signer and it's private key files exist.
        catchNonExistingFiles(signer);

        // Create our SCEP object.
        SCEP scep = new SCEP();

        // Set the certificate signer and private key
        int res = scep.setSignerCertFromFile(signer);
        if (res != 0) {
            return res;
        }
        byte[] decoded = base64URLDecode(inkey);
        res = scep.setPrivateKeyFromBuff(decoded);
        if (res != 0) {
            return res;
        }

        // Try to parse the status as an integer
        try {
            Integer.parseInt(status);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid status: "+status+". Expected 0 (success), 1 (failure) or 2 (pending).");
        }

        // Check if the status, or interrupt the programme
        switch (status) {
            case "0": scep.setSuccess(); break;
            case "1": scep.setFailure(); break;
            case "2": scep.setPending(); break;
            default: throw new IllegalArgumentException("Invalid status: "+status+". Expected 0 (success), 1 (failure) or 2 (pending).");
        }

        if (scep.isSuccess()) {
            // Make sure the recipient certificate and the client certificate have been provided.
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

            String clientCert;
            if (args.contains("-cert")) {
                try {
                    clientCert = args.get(args.indexOf("-cert")+1);
                } catch (Exception e) {
                    clientCert = null;
                }
            } else {
                clientCert = null;
            }
            res = scep.setCertFromFile(clientCert);
            if (res != 0) {
                throw new IllegalArgumentException("You need to set a VALID certificate for the success response.");
            }
        }

        // Finalize the data initialization
        scep.setCaCertFromFile(ca);
        scep.setFailInfo(failInfo);
        scep.setTransactionId(transactionID);
        scep.setSenderNonce(senderNonce);
        scep.setRecipientNonce(recipientNonce);

        // Finish by signing the data
        return scep.signData(scep.getStatus(), out);
    }


    /**
     * Executes the primary option 'req'
     *
     * @return the exit status code
     * */
    @Deprecated
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

    /**
     * Executes the primary option 'cmp-ecdsa-gen'
     *
     * @return the exit status code
     * */
    private static int execCMPECDSA(String[] _args) {
        List<String> args = Arrays.asList(_args);

        List<String> missingSuboptions = checkForMissingSuboption("cmp-ecdsa-gen", _args);
        if (!missingSuboptions.isEmpty()) {
            showUsage("Missing option(s) for cmp-ecdsa-gen: "+missingSuboptions);
            System.exit(1);
        }

        if (_args.length < CPM_MANDATORY_ECDSA_OPTIONS.length * 2) {
            showUsage("Impossible use of commands.");
            System.exit(1);
        }

        HashMap<String, String> fileOut = new HashMap<>(); String curveName = null;
        fileOut.put("priv", args.get(args.indexOf("-privout") + 1));
        if (args.contains("-pubout")) {
            fileOut.put("pub", args.get(args.indexOf("-pubout") + 1));
        }
        if (args.contains("-curve")) {
            curveName = args.get(args.indexOf("-curve") + 1);
        }

        // Select which method to run.
        int result;
        if (curveName == null) {
            result = ECDSA.generateECDSAKey(fileOut);
        } else {
            result = ECDSA.generateECDSAKey(fileOut, curveName);
        }

        return result;
    }

    private static byte[] base64URLDecode(String encoded) {
        org.apache.commons.codec.binary.Base64 base64 = new org.apache.commons.codec.binary.Base64();
        return base64.decode(encoded.getBytes());

//        System.out.println(encoded.length());
//
//        Base64.Decoder decoder = Base64.getMimeDecoder();
//        return decoder.decode(encoded);
//        return Base64.getUrlDecoder().decode(encoded.getBytes());
    }

    private static void showUsage(String message) {
        System.out.println(message);
        showUsage();
    }

    private static void showUsage() {
        System.out.println(USAGE);
    }
}
