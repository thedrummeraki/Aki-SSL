package ui.main_panels.pkcs7;

import pkcs7.PKCS7;
import pkcs7.PKCS7Exception;
import tools.BashReader;
import tools.FileReader;
import ui.HostPanel;
import x509.Certificate;
import x509.CertificateException;
import x509.PrivateKey;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

/**
 * Created by aakintol on 29/06/16.
 */
public class PKCS7Form implements HostPanel {
    private JPanel panel1;
    private JButton importCertButton;
    private JButton importKeyButton;
    private JButton signButton;
    private JButton resetButton;
    private JTextArea textArea1;
    private JTextArea textArea2;
    private JLabel certPath;
    private JLabel keyPath;
    private JLabel pkcs7Path;
    private JButton importPKCS7Button;
    private JButton saveResultsButton;
    private JFrame parent;

    private File certFile, keyFile, pkcs7File;
    private static PKCS7Form form;

    // In order to sign a PKCS7, we need a certificate and it's private key.
    private void addListeners() {
        importCertButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent actionEvent) {
                JFileChooser fileChooser = new JFileChooser(System.getProperty("user.dir"));
                int n = fileChooser.showDialog(parent, "Choose a certificate signer");
                if (n == JFileChooser.APPROVE_OPTION) {
                    certFile = fileChooser.getSelectedFile();
                    certPath.setText("../"+certFile.getParentFile().getName()+"/"+certFile.getName());
                }
            }
        });

        importKeyButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent actionEvent) {
                JFileChooser fileChooser = new JFileChooser(System.getProperty("user.dir"));
                int n = fileChooser.showDialog(parent, "Choose this signer's private key");
                if (n == JFileChooser.APPROVE_OPTION) {
                    keyFile = fileChooser.getSelectedFile();
                    keyPath.setText("../"+keyFile.getParentFile().getName()+"/"+keyFile.getName());
                }
            }
        });

        importPKCS7Button.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent actionEvent) {
                JFileChooser fileChooser = new JFileChooser(System.getProperty("user.dir"));
                int n = fileChooser.showDialog(parent, "Choose your PKCS7 file");
                if (n == JFileChooser.APPROVE_OPTION) {
                    pkcs7File = fileChooser.getSelectedFile();
                    pkcs7Path.setText("../"+pkcs7File.getParentFile().getName()+"/"+pkcs7File.getName());
                    textArea1.setText(BashReader.toSingleString(FileReader.getLines(pkcs7File)));
                }
            }
        });

        signButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent actionEvent) {
                String errorMessage = "<html>You are missing the following:<br><ul>";
                boolean hasErrors = false;
                if (pkcs7File == null) {
                    errorMessage += "<li>A PKCS7 file</li>";
                }
                if (certFile == null) {
                    errorMessage += "<li>Your certificate signer file</li>";
                }
                if (keyFile == null) {
                    errorMessage += "<li>Your signer's private key file</li>";
                }
                hasErrors = pkcs7File == null || certFile == null || keyFile == null;
                errorMessage += "</ul></html>";
                if (hasErrors) {
                    JOptionPane.showMessageDialog(parent, errorMessage, "Error while signing the PKCS7 message.", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                PKCS7 pkcs7 = new PKCS7(BashReader.toSingleString(FileReader.getLines(pkcs7File)), false);
                Certificate signer;
                try {
                    signer = Certificate.loadCertificateFromFile(certFile);
                } catch (CertificateException e) {
                    e.printStackTrace();
                    JOptionPane.showMessageDialog(parent, "Your certificate signer is not valid.", "Error while signing the PKCS7 message.", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                pkcs7.setCertSigner(signer);
                try {
                    PrivateKey privateKey = PrivateKey.loadPrivateKey(keyFile);
                    pkcs7.setPrivateKeySigner(privateKey);
                    pkcs7.sign();
                } catch (PKCS7Exception e) {
                    e.printStackTrace();
                    JOptionPane.showMessageDialog(parent, "The signature has failed: "+e, "Error while signing the PKCS7 message.", JOptionPane.ERROR_MESSAGE);
                    return;
                } catch (CertificateException e) {
                    e.printStackTrace();
                    JOptionPane.showMessageDialog(parent, "The your private key is invalid.", "Error while signing the PKCS7 message.", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                JOptionPane.showMessageDialog(parent, "The sign was complete! You can view the results on the right pane.");
                textArea2.setText(pkcs7.getSignedDataAsString());
            }
        });
    }

    private PKCS7Form(JFrame p) {
        this.parent = p;
        parent.setContentPane(panel1);
        parent.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        parent.setSize(700, 550);
        parent.setVisible(true);

        addListeners();
    }

    @Override
    public void updateInParent() {
        this.parent.setContentPane(panel1);
        this.parent.revalidate();

        this.parent.setTitle("Sign a PKCS7...");
        JMenuBar jMenuBar = this.parent.getJMenuBar();
        JMenuBar newBar = new JMenuBar();
        for (int i = 0; i<jMenuBar.getMenuCount(); i++) {
            newBar.add(jMenuBar.getMenu(i));
        }
        newBar.add(new JMenu("Test"));
        this.parent.setJMenuBar(newBar);
    }

    public static void loadForm(JFrame parent) {
        form = new PKCS7Form(parent);
        form.updateInParent();
    }

    private void createUIComponents() {
        // TODO: place custom component creation code here
        certPath = new JLabel();
        keyPath = new JLabel();
        pkcs7Path = new JLabel();
    }

    public static Container panel() {
        return form.panel1;
    }
}
