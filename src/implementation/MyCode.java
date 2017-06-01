package implementation;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;


import code.GuiException;
import implementation.Beans.CertificateSubject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import x509.v3.CodeV3;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class MyCode extends CodeV3 {

    KeyStore keyStore;
    private static final String keyStoreName = "keyStore.p12";
    private static final String keyStoreInstanceName = "PKCS12";
    private static final String keyStorePassword = "sifra";

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf)
            throws GuiException {
        super(algorithm_conf, extensions_conf);
        // TODO Auto-generated constructor stub
    }

    public void saveLocalKeyStore(){
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(keyStoreName);
            keyStore.store(fos, keyStorePassword.toCharArray());
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }finally {
            if (fos != null)
                try {fos.close();}
                catch (IOException e) {e.printStackTrace();}
        }
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        FileInputStream fis = null;
        try {
            keyStore = KeyStore.getInstance(keyStoreInstanceName, new BouncyCastleProvider());

            if(!(new File(keyStoreName).exists())){
                keyStore.load(null,null);
            } else {
                fis = new FileInputStream(keyStoreName);
                keyStore.load(fis,keyStorePassword.toCharArray());
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e){
            e.printStackTrace(); //TODO: kreirati fajl ako ne postoji
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (fis != null){
                try { fis.close(); }
                catch (IOException e) { e.printStackTrace(); }
            }
        }
        return null;
    }

    @Override
    public void resetLocalKeystore() {
        // TODO Auto-generated method stub

    }

    @Override
    public boolean exportKeypair(String name, String file, String password) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean importKeypair(String keypair_name, String file, String password) {
        try { //TODO import keypair!
            FileInputStream fis = new FileInputStream(file);
            KeyStore tmpKeyStore = KeyStore.getInstance(keyStoreInstanceName, new BouncyCastleProvider());


            KeyStore keyStore = KeyStore.getInstance(keyStoreInstanceName);
            keyStore.load(fis, password.toCharArray());

            fis.close();
            Enumeration<String> aliases = keyStore.aliases();
            String selectedAlias = aliases.nextElement();


            Key key = keyStore.getKey(selectedAlias, password.toCharArray());
            Certificate[] chain = keyStore.getCertificateChain(selectedAlias);

            //sad dialozi
            //KeyStore ks = KeyPairsStore.getInstance();

            //nova sifra?
            keyStore.setKeyEntry(selectedAlias, key, password.toCharArray(), chain);
            //KeyPairsStore.save();

            saveLocalKeyStore();

            access.addKeypair(keypair_name);


        } catch (UnrecoverableKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }


        return false;
    }

    @Override
    public boolean removeKeypair(String keypair_name) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public int loadKeypair(String keypair_name) {
        try {
            Key key = keyStore.getKey(keypair_name, keyStorePassword.toCharArray());
            Enumeration<String> aliases = keyStore.aliases();
            String selectedAlias = aliases.nextElement();
            Certificate[] chain = keyStore.getCertificateChain(selectedAlias);
            X509Certificate certificate = (X509Certificate) chain[0];
            setCertificateSubjectDataFromKeyStore(certificate);

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (CertificateParsingException e) {
            e.printStackTrace();
        }

        return 0;
    }

    private void setCertificateSubjectDataFromKeyStore(X509Certificate certificate)
            throws CertificateParsingException {

        //TODO: popuniti GUI iz certificate
        access.setSubjectCountry();
        access.setSubjectState();
        access.setSubjectLocality();
        access.setSubjectOrganization();
        access.setSubjectOrganizationUnit();
        access.setSubjectCommonName();
        access.setSubjectSignatureAlgorithm();
        access.setPublicKeySignatureAlgorithm(); //treba?

        access.setSerialNumber(String.valueOf(certificate.getSerialNumber()));
        access.setPublicKeyParameter();
        access.setNotBefore();
        access.setNotAfter();
        access.setKeyUsage();

        String altNames;
        Collection<List<?>> list = certificate.getSubjectAlternativeNames();
        for (List<?> name : list) {
            //TODO: kako se cita ova lista?!
        }
        access.setAlternativeName(6,altNames); //2 keyUsage, 6 altName, 13 issuerinhibit
        access.setInhibitAnyPolicy();

        //TODO: one 3 ekstenzije
    }

    @Override
    public boolean saveKeypair(String keypair_name) {
        CertificateSubject bean = getCertificateSubjectDataFromGUI();
        KeyPair keyPair = null;
        try {
            keyPair = Functions.createKeyPair("RSA", Integer.parseInt(bean.getKeyLength()));
            PublicKey PUa = keyPair.getPublic();
            PrivateKey PRa = keyPair.getPrivate();
            X509Certificate certificate = Functions.createCertificate(PUa, PRa, bean);

            //TODO: CREATE KEY STORE IMPLEMENTATION
            //KeyStore ks = KeyPairsStore.getInstance();

            Certificate[] chain = new Certificate[1];
            chain[0] = certificate;

            //TODO: password?
            keyStore.setKeyEntry(keypair_name, PRa, keyStorePassword.toCharArray(), chain);

            //TODO:
            //KeyPairsStore.save();
            saveLocalKeyStore();
            access.addKeypair(keypair_name);

        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private CertificateSubject getCertificateSubjectDataFromGUI() {
        CertificateSubject ret = new CertificateSubject(
                access.getSubjectCountry(),
                access.getSubjectState(),
                access.getSubjectLocality(),
                access.getSubjectOrganization(),
                access.getSubjectOrganizationUnit(),
                access.getSubjectCommonName(),
                access.getPublicKeySignatureAlgorithm(),
                access.getSerialNumber(),
                access.getPublicKeyParameter(),
                access.getNotBefore(),
                access.getNotAfter(),
                access.getKeyUsage(),
                access.getAlternativeName(6), //2 keyUsage, 6 altName, 13 issuerinhibit
                access.getInhibitAnyPolicy()
        );

        ret.setIssuerAlternativeNameCritical(
                access.isCritical(6) //2 keyUsage, 6 altName, 13 issuerinhibit
        );

        ret.setKeyUsageCritical(
                access.isCritical(2) //2 keyUsage, 6 altName, 13 issuerinhibit
        );

        ret.setInhibitAndPolicyCritical(
                access.isCritical(13) //2 keyUsage, 6 altName, 13 issuerinhibit
        );
        return ret;
    }

    @Override
    public boolean exportCertificate(File file, int encoding) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean generateCSR(String keypair_name) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public String getIssuer(String arkeypair_nameg0) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getIssuerPublicKeyAlgorithm(String keypair_name) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<String> getIssuers(String keypair_name) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public int getRSAKeyLength(String keypair_name) {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public boolean importCertificate(File file, String keypair_name) {
        // TODO Auto-generated method stub
        return false;
    }


    @Override
    public boolean signCertificate(String issuer, String algorithm) {
        // TODO Auto-generated method stub
        return false;
    }

}
