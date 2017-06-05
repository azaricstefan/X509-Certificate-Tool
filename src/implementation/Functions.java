package implementation;

import implementation.Beans.CertificateSubject;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import sun.security.x509.InhibitAnyPolicyExtension;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;

/**
 * Project name: zp-projekat
 * Created by staz on 1.6.2017. 11:43
 */
public class Functions {

    public static KeyPair createKeyPair(String encryptType, int bitCount)
            throws NoSuchProviderException, NoSuchAlgorithmException {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(encryptType);
        kpg.initialize(bitCount);
        return kpg.genKeyPair();
    }

    public static X509Certificate createCertificate(PublicKey publicKey, PrivateKey privateKey,
                                                    CertificateSubject bean) throws Exception {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, bean.getCN());
        builder.addRDN(BCStyle.O, bean.getO());
        builder.addRDN(BCStyle.OU, bean.getOU());
        builder.addRDN(BCStyle.L, bean.getL());
        builder.addRDN(BCStyle.ST, bean.getST());
        builder.addRDN(BCStyle.C, bean.getC());

        String signatureAlgorithm = bean.getSA();
        ContentSigner sigGen = new JcaContentSignerBuilder(signatureAlgorithm).build(privateKey);

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builder.build(),
                new BigInteger(bean.getSN()), bean.getValidNotBefore(), bean.getValidNotAfter(), builder.build(),
                publicKey);

        // Adding keyusage extension
        int keyUsage = 0;
        boolean criticalKeyUsage = bean.isKeyUsageCritical();

        if (bean.isEnabled(CertificateSubject.KeyUsageBox.CERTIFICATE_SIGNING))
            keyUsage |= X509KeyUsage.keyCertSign;
        if (bean.isEnabled(CertificateSubject.KeyUsageBox.CRL_SIGNING))
            keyUsage |= X509KeyUsage.cRLSign;
        if (bean.isEnabled(CertificateSubject.KeyUsageBox.DATA_ENCIPHERMENT))
            keyUsage |= X509KeyUsage.dataEncipherment;
        if (bean.isEnabled(CertificateSubject.KeyUsageBox.DECIPHER_ONLY))
            keyUsage |= X509KeyUsage.decipherOnly;
        if (bean.isEnabled(CertificateSubject.KeyUsageBox.DIGITAL_SIGNATURE))
            keyUsage |= X509KeyUsage.digitalSignature;
        if (bean.isEnabled(CertificateSubject.KeyUsageBox.ENCIPHER_ONLY))
            keyUsage |= X509KeyUsage.encipherOnly;
        if (bean.isEnabled(CertificateSubject.KeyUsageBox.KEY_AGREEMENT))
            keyUsage |= X509KeyUsage.keyAgreement;
        if (bean.isEnabled(CertificateSubject.KeyUsageBox.KEY_ENCIPHERMENT))
            keyUsage |= X509KeyUsage.keyEncipherment;
        if(bean.isEnabled(CertificateSubject.KeyUsageBox.CONTENT_COMMITMENT)) //same as nonRepudiation
            keyUsage |= X509KeyUsage.nonRepudiation;


        if (keyUsage != 0) {
            X509KeyUsage keyuse = new X509KeyUsage(keyUsage);
            certGen.addExtension(Extension.keyUsage, criticalKeyUsage, keyuse.getEncoded());
        }

        //===========Issuer alternative names===========

        boolean criticalIAN = bean.isIssuerAlternativeNameCritical();
        if (bean.getIssuerAlternativeNames().length > 0) {
            GeneralName[] all = new GeneralName[bean.getIssuerAlternativeNames().length];
            int i = 0;
            for (String it : bean.getIssuerAlternativeNames()) {
                //all[i++] = new GeneralName(new X500Name(it));
                all[i++] = new GeneralName(GeneralName.rfc822Name,it);
            }
            GeneralNames names = new GeneralNames(all);
            certGen.addExtension(Extension.issuerAlternativeName, criticalIAN, names);
        }

        //===========Inhibit any Policy===========

        boolean criticalIAP = bean.isInhibitAndPolicyCritical();
        if (bean.isInhibitAndPolicy()){
            //GET skipCert
            String skipCerts = bean.getInhibitAnyPolicySkipCerts();
            InhibitAnyPolicyExtension i = new InhibitAnyPolicyExtension(Integer.parseInt(skipCerts));
            criticalIAP = true; //MUST BE!
            certGen.addExtension(Extension.inhibitAnyPolicy, criticalIAP, i.getExtensionValue());
            //2nd way
            //InhibitAnyPolicy iap = new InhibitAnyPolicy(new BigInteger(skipCerts));
            //certGen.addExtension(Extension.inhibitAnyPolicy, criticalIAP, iap);
        }
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certGen.build(sigGen));

        System.out.println("CREATION: "+ cert); //DEBUG
        return cert;
    }
}
