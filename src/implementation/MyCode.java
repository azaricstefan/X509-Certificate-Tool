package implementation;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.cert.Extension;
import java.util.*;


import code.GuiException;
import implementation.Beans.CertificateSubject;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jcajce.provider.keystore.bc.BcKeyStoreSpi.BouncyCastleStore;
import org.bouncycastle.jcajce.provider.keystore.pkcs12.PKCS12KeyStoreSpi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.security.x509.InhibitAnyPolicyExtension;
import x509.v3.CodeV3;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;

public class MyCode extends CodeV3 {

    //KeyStore keyStore;
    BouncyCastleStore keyStore; //Da li njega koristiti?
    private static final String keyStoreName = "keyStore.p12";
    private static final String keyStoreInstanceName = "PKCS12";
    private static final String keyStorePassword = "sifra";

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf)
            throws GuiException {
        super(algorithm_conf, extensions_conf);
        // TODO Auto-generated constructor stub
    }

    public void saveLocalKeyStore() {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(keyStoreName);
            keyStore.engineStore(fos, keyStorePassword.toCharArray());
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (fos != null)
                try {
                    fos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
        }
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        FileInputStream fis = null;
        try {
            keyStore = new BouncyCastleStore();

            if (!(new File(keyStoreName).exists())) {
                keyStore.engineLoad(null, null);
            } else {
                fis = new FileInputStream(keyStoreName);
                keyStore.engineLoad(fis, keyStorePassword.toCharArray());
                return keyStore.engineAliases();
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return null;
    }

    @Override
    public void resetLocalKeystore() {
        Enumeration aliases = keyStore.engineAliases();
        while (aliases.hasMoreElements()) {
            String entry = (String) aliases.nextElement();
            try {
                keyStore.engineDeleteEntry(entry);
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
        }
        File file = new File(keyStoreName);
        if (file.exists()) {
            if (!file.delete()) {
                try {
                    throw new Exception("UNABLE TO DELETE KEY STORE!");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * Tреба да постојећи
     * пар кључева који је у локалном keystore-у сачуван под алиасом keypair_name извезе у фајл
     * са путањом file у PKCS#12 формату и заштити лозинком. Повратна вредност методе
     * означава успешност операције, false у случају грешке.
     * @param name
     * @param file
     * @param password
     * @return
     */
    @Override
    public boolean exportKeypair(String keypair_name, String file, String password) {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(file+".p12");
            KeyStore tmpKS = KeyStore.getInstance(keyStoreInstanceName, new BouncyCastleProvider());

            Key key = keyStore.engineGetKey(keypair_name, keyStorePassword.toCharArray());
            Certificate[] chain = keyStore.engineGetCertificateChain(keypair_name);

            tmpKS.load(null,null); //initalize ...
            tmpKS.setKeyEntry(keypair_name, key, password.toCharArray(), chain);
            tmpKS.store(fos, password.toCharArray());
            return true;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } finally {
            if (fos != null)
                try {
                    fos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
        }
        return false;
    }

    @Override
    public boolean importKeypair(String keypair_name, String file, String password) {
        try {
            //TODO import keypair!
            FileInputStream fis = new FileInputStream(file);

            KeyStore tmpKeyStore = KeyStore.getInstance(keyStoreInstanceName, new BouncyCastleProvider());

            tmpKeyStore.load(fis, password.toCharArray()); //ucitaj u privremeni

            fis.close();
            Enumeration<String> aliases = tmpKeyStore.aliases();
            String selectedAlias = aliases.nextElement(); //get alias of new keypair

            Key key = tmpKeyStore.getKey(selectedAlias, password.toCharArray()); //get key
            Certificate[] chain = tmpKeyStore.getCertificateChain(selectedAlias); //get chain

            keyStore.engineSetKeyEntry(keypair_name, key, keyStorePassword.toCharArray(), chain);

            saveLocalKeyStore();
            return true;

        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return false;
    }

    @Override
    public boolean removeKeypair(String keypair_name) {
        // TODO Auto-generated method stub
        try {
            keyStore.engineDeleteEntry(keypair_name);
            saveLocalKeyStore();
            loadLocalKeystore();
            return true;
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * Метода враћа -1 у случају
     * грешке, 0 у случају да сертификат сачуван под тим алиасом није потписан, 1 у случају да је
     * потписан, 2 у случају да је у питању увезени trusted сертификат.
     * @param keypair_name
     * @return -1 if error; 0 if not signed under that alias, 1 if signed, 2 imported trusted certificate
     */
    @Override
    public int loadKeypair(String keypair_name) {
        int ret = -1;
        try {
            Key key = keyStore.engineGetKey(keypair_name, keyStorePassword.toCharArray());
            Enumeration<String> aliases = keyStore.engineAliases();
            while(true) {
                String selectedAlias = aliases.nextElement();
                if (selectedAlias.equals(keypair_name)) {
                    Certificate[] chain = keyStore.engineGetCertificateChain(selectedAlias);
                    X509Certificate certificate = (X509Certificate) chain[0];
                    setCertificateSubjectDataFromKeyStore(certificate);
                    ret = 0; //TODO: check return values?
                    break;
                }
            }

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (CertificateParsingException e) {
            e.printStackTrace();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        return ret;
    }

    private void setCertificateSubjectDataFromKeyStore(X509Certificate certificate)
            throws CertificateParsingException, CertificateEncodingException {

        System.out.println("READING: " + certificate); //DEBUG

        JcaX509CertificateHolder certHolder = new JcaX509CertificateHolder((X509Certificate) certificate);
        X500Name name = certHolder.getSubject();

        access.setVersion(certHolder.getVersionNumber() - 1); //because index of buttons[] should be -1

        //populate GUI from certificate
        if (name.getRDNs(BCStyle.C).length > 0)
            access.setSubjectCountry(IETFUtils.valueToString(name.getRDNs(BCStyle.C)[0].getFirst().getValue()));
        if (name.getRDNs(BCStyle.ST).length > 0)
            access.setSubjectState(IETFUtils.valueToString(name.getRDNs(BCStyle.ST)[0].getFirst().getValue()));
        if (name.getRDNs(BCStyle.L).length > 0)
            access.setSubjectLocality(IETFUtils.valueToString(name.getRDNs(BCStyle.L)[0].getFirst().getValue()));
        if (name.getRDNs(BCStyle.O).length > 0)
            access.setSubjectOrganization(IETFUtils.valueToString(name.getRDNs(BCStyle.O)[0].getFirst().getValue()));
        if (name.getRDNs(BCStyle.OU).length > 0)
            access.setSubjectOrganizationUnit(IETFUtils.valueToString(name.getRDNs(BCStyle.OU)[0].getFirst().getValue()));
        if (name.getRDNs(BCStyle.CN).length > 0)
            access.setSubjectCommonName(IETFUtils.valueToString(name.getRDNs(BCStyle.CN)[0].getFirst().getValue()));
        access.setSubjectSignatureAlgorithm(certificate.getSigAlgName());
        access.setPublicKeySignatureAlgorithm(certificate.getSigAlgName());

        access.setSerialNumber(String.valueOf(certificate.getSerialNumber()));
        access.setPublicKeyParameter(certificate.getPublicKey().toString()); //TODO check if ok toString
        access.setNotBefore(certificate.getNotBefore());
        access.setNotAfter(certificate.getNotAfter());

        //=========GET KEY USAGE=================
        if (certificate.getKeyUsage() != null && certificate.getKeyUsage().length != 0)
            access.setKeyUsage(certificate.getKeyUsage());

        //=========GET ALTERNATIVE NAMES=========
        String issuerAltNames = getAlternativeNames(certificate, 0);
        if (issuerAltNames != null) {
            access.setAlternativeName(6, issuerAltNames); //5 subject AltName,6 issuerAltName, 2 keyUsage,13 issuerinhibit
        }
        String subjectAltNames = getAlternativeNames(certificate, 1);
        if (subjectAltNames != null) {
            access.setAlternativeName(5, subjectAltNames);
        }


        //========GET INHIBIT ANY POLICY=========
        ASN1Primitive prim = null;
        String decoded = null;
        byte[] tt = certificate.getExtensionValue("2.5.29.54");
        if (tt != null) {
            try {
                prim = JcaX509ExtensionUtils.parseExtensionValue(tt);
                decoded = prim.toString();
            } catch (IOException e) {
                e.printStackTrace();
            }
            access.setSkipCerts(decoded);
            access.setInhibitAnyPolicy(true);
        }
    }

    /**
     * @param certificate take the info from
     * @param what        Issuer 0, Subject 1
     * @return {@link String} allNames
     * @throws CertificateParsingException
     */
    private String getAlternativeNames(X509Certificate certificate, int what)
            throws CertificateParsingException {
        Collection<List<?>> allNames;
        if (what == 0)
            allNames = certificate.getIssuerAlternativeNames();
        else
            allNames = certificate.getSubjectAlternativeNames();
        String altNames;
        //citanje imena
        if (allNames != null) {
            Iterator<List<?>> it = allNames.iterator();
            StringBuilder stringBuilder = new StringBuilder();
            while (it.hasNext()) {
                List<?> list = it.next();
                stringBuilder.append(list.get(1));
            }
            altNames = stringBuilder.toString();
            return altNames;
        }
        return null;
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


            Certificate[] chain = new Certificate[1];
            chain[0] = certificate;

            keyStore.engineSetKeyEntry(keypair_name, PRa, keyStorePassword.toCharArray(), chain);

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
                access.getInhibitAnyPolicy(),
                access.getVersion()
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
        ret.setInhibitAndPolicy(access.getInhibitAnyPolicy());
        ret.setInhibitAnyPolicySkipCerts(access.getSkipCerts());
        return ret;
    }

    /**
     * Tреба да у фајл file (екстензије .cer) извезе
     * постојећи сертификат тренутно селектован на графичком корисничком интерфејсу и
     * кодира га на начин назначен вредношћу параметра encoding (0 за DER, 1 за PEM).
     * Повратна вредност методе означава успешност операције, false у случају грешке.
     * @param file
     * @param encoding 0 => DER; 1 => PEM
     * @return Success of the operation
     */
    @Override
    public boolean exportCertificate(File file, int encoding) {
        X509Certificate cert;
        access.getSubject();
        //cert = (X509Certificate) keyStore.engineGetCertificate(file);
        String encoded;
        //TODO: EXPORT CERTIFICATE
        switch(encoding) {
            case 0: //DER - binary form of the certificate
                //encoded = Functions.Base64Encode(cert);
            case 1: //PEM - base64 and encrypted form of the certificate
          //      encoded = Functions.PemEncode(cert);
        }
        //return Functions.writeCertificateToFile(file, encoded, encoding);
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
