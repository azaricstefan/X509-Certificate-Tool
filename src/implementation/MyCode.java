package implementation;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.util.Enumeration;
import java.util.List;


import code.GuiException;
import x509.v3.CodeV3;

import org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyPairGeneratorSpi;
import org.bouncycastle.jce.provider.X509CertificateObject;

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class MyCode extends CodeV3 {

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf)
			throws GuiException {
		super(algorithm_conf, extensions_conf);
		// TODO Auto-generated constructor stub
	}

	@Override
	public boolean importKeypair(String keypair_name, String file, String password) {
		try {
		FileInputStream fis = new FileInputStream(file);
		KeyStore keyStore = KeyStore.getInstance("PKCS12");    
		keyStore.load(fis, password.toCharArray());

		fis.close();

		Enumeration<String> aliases = keyStore.aliases();
		String selectedAlias = aliases.nextElement();

		
			Key key = keyStore.getKey(selectedAlias, password.toCharArray());
			Certificate[] chain = keyStore.getCertificateChain(selectedAlias);
			//KeyStore ks = KeyPairsStore.getInstance();
			
			
			String passForNewProtection = "";
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
	public boolean exportCertificate(File arg0, int arg1) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean exportKeypair(String arg0, String arg1, String arg2) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean generateCSR(String arg0) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String getIssuer(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getIssuerPublicKeyAlgorithm(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<String> getIssuers(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public int getRSAKeyLength(String arg0) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public boolean importCertificate(File arg0, String arg1) {
		// TODO Auto-generated method stub
		return false;
	}


	@Override
	public int loadKeypair(String arg0) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public Enumeration<String> loadLocalKeystore() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean removeKeypair(String arg0) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void resetLocalKeystore() {
		// TODO Auto-generated method stub

	}

	@Override
	public boolean saveKeypair(String arg0) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean signCertificate(String arg0, String arg1) {
		// TODO Auto-generated method stub
		return false;
	}

}
