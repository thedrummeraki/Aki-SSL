package ui.main_panels;

import aki.packages.tools.BashReader;
import aki.packages.tools.FileReader;
import aki.packages.tools.FileWriter;
import aki.packages.tools.Logger;
import aki.packages.x509.Certificate;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

/**
 * Created by aakintol on 29/06/16.
 */
public class CertForm implements HostPanel {
    private JPanel panel1;
    private JButton importFromFileButton;
    private JButton cancelButton;
    private JButton convertButton;
    private JTextArea textArea1;
    private JTextArea textArea2;
    private JFrame parent;
    private static CertForm form;

    private void addListeners() {
        importFromFileButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent actionEvent) {
                String filename = BashReader.toSingleString(FileReader.getLines(".saved.txt")).trim();
                if (filename.isEmpty()) {
                    filename = System.getProperty("user.dir");
                }
                JFileChooser fileChooser = new JFileChooser(filename);
                int n = fileChooser.showDialog(parent, "Choose");
                if (n == JFileChooser.APPROVE_OPTION) {
                    File file = fileChooser.getSelectedFile();
                    FileWriter.write(file.getParentFile().getAbsolutePath(), ".saved.txt", false);
                    String lines = BashReader.toSingleString(FileReader.getLines(file.getPath()));
                    textArea1.setText("");
                    textArea1.append(lines);
                }
            }
        });

        convertButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent actionEvent) {
                String contents = textArea1.getText();
                if (contents == null || contents.trim().isEmpty()) {
                    JOptionPane.showMessageDialog(parent, "The certificate should not be empty.");
                }
                try {
                    File tempFile = new File("tmp/temp-impcert.pem");
                    FileWriter.write(contents, tempFile.getPath());
                    Certificate certificate = Certificate.loadCertificateFromFile(tempFile);
                    if (certificate != null) {
                        if (textArea2.getText().trim().equals("--- Invalid certificate ---")) {
                            textArea2.setText("");
                        }
                        textArea2.append(!textArea2.getText().trim().isEmpty() ? "\n-----\n" : "");
                        textArea2.append(certificate.getSubject().getPrettyString());
                    }
                    else {
                        textArea2.setText("--- Invalid certificate ---");
                        JOptionPane.showMessageDialog(parent, "This certificate is not valid.");
                    }
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(parent, e.toString());
                }
            }
        });
    }

    public JPanel getPanel() {
        return panel1;
    }

    private CertForm(JFrame parent) {
        this.parent = parent;
        Border empty = BorderFactory.createEmptyBorder(5,5,5,5);

        panel1.setBorder(empty);

        textArea2.setEnabled(false);
        textArea2.setEditable(false);

        Logger.debug("OK");
        addListeners();
        this.parent.setTitle("Decoding an X509 certificate");
    }

    public static void loadForm(JFrame parent) {
        form = new CertForm(parent);
        form.updateInParent();
    }

    @Override
    public void updateInParent() {
        this.parent.setContentPane(panel1);
        this.parent.revalidate();
    }

    public static Container panel() {
        return form.panel1;
    }
}
