package scep;

import tools.BashReader;
import tools.FileReader;

import java.io.File;

/**
 * Created by aakintol on 30/06/16.
 */
public final class Communicator {

    private Communicator() {}

    public static void main(String[] args) {
        if (args.length < 7) {
            // print usage
            System.exit(0);
        }

        String cert = args[0];
        String pkey = args[1];
        String message = args[2];
        String ip = args[3];
        String output = args[4];
        String failOutput = args[5];
        String pendingOutput = args[6];
        String successOutput = args[7];

        File file = new File(cert);
        if (file.exists()) {
            cert = BashReader.toSingleString(FileReader.getLines(file));
        }
        file = new File(pkey);
        if (file.exists()) {
            pkey = BashReader.toSingleString(FileReader.getLines(file));
        }

        int code = SCEPResponse.loadSCEPResponse(cert, pkey, message, ip, output, failOutput, pendingOutput, successOutput);
        System.exit(code);
    }

}
