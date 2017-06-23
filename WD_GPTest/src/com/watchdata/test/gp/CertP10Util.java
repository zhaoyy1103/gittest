package com.watchdata.test.gp;

import java.io.ByteArrayInputStream;  
import java.io.FileInputStream;  
import java.io.FileOutputStream;  
import java.io.FileWriter;  
import java.io.IOException;  
import java.io.InputStream;  
import java.io.InputStreamReader;  
import java.math.BigInteger;  
import java.security.InvalidKeyException;  
import java.security.KeyFactory;  
import java.security.KeyPair;  
import java.security.KeyPairGenerator;  
import java.security.KeyStore;  
import java.security.NoSuchAlgorithmException;  
import java.security.NoSuchProviderException;  
import java.security.PrivateKey;  
import java.security.PublicKey;  
import java.security.SecureRandom;  
import java.security.Security;  
import java.security.SignatureException;  
import java.security.cert.CertificateEncodingException;  
import java.security.cert.CertificateException;  
import java.security.cert.CertificateParsingException;  
import java.security.cert.X509Certificate;  
import java.security.spec.RSAPublicKeySpec;  
import java.util.Collection;  
import java.util.Date;  
import java.util.Iterator;  
  
import javax.security.auth.x500.X500Principal;  
  
import org.bouncycastle.asn1.ASN1Sequence;  
import org.bouncycastle.asn1.DERBitString;  
import org.bouncycastle.asn1.DEROutputStream;  
import org.bouncycastle.asn1.DERSet;  
import org.bouncycastle.asn1.pkcs.CertificationRequest;  
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;  
import org.bouncycastle.asn1.x500.X500Name;  
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;  
import org.bouncycastle.asn1.x509.Certificate;  
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;  
import org.bouncycastle.asn1.x509.X509CertificateStructure;  
import org.bouncycastle.asn1.x509.X509Extensions;  
import org.bouncycastle.asn1.x509.X509Name;  
import org.bouncycastle.cert.X509CertificateHolder;  
import org.bouncycastle.cert.X509v3CertificateBuilder;  
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;  
import org.bouncycastle.crypto.params.RSAKeyParameters;  
import org.bouncycastle.crypto.util.PrivateKeyFactory;  
import org.bouncycastle.crypto.util.PublicKeyFactory;  
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;  
import org.bouncycastle.jce.provider.BouncyCastleProvider;  
//import org.bouncycastle.openssl.PEMReader;  
import org.bouncycastle.openssl.PEMWriter;  
import org.bouncycastle.openssl.PasswordFinder;  
import org.bouncycastle.operator.ContentSigner;  
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;  
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;  
import org.bouncycastle.operator.OperatorCreationException;  
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;  
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;  
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;  
import org.bouncycastle.x509.X509V1CertificateGenerator;  
import org.bouncycastle.x509.X509V3CertificateGenerator;  
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;  

//import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;  

public class CertP10Util {
	  	
		public CertP10Util() {  
			Security.addProvider(new BouncyCastleProvider());  
		}  

		public static String getSubjectDN(byte[] der) {  
			String dn = "";  
			try {  
				ByteArrayInputStream bIn = new ByteArrayInputStream(der);  
				// BouncyCastleProvider provider = new BouncyCastleProvider();  
				// CertificateFactory cf = CertificateFactory.getInstance("X509",  
				// provider);  
				CertificateFactory cf = new CertificateFactory();  
				X509Certificate cert = (X509Certificate) cf  
						.engineGenerateCertificate(bIn);  
				dn = cert.getSubjectDN().getName();  
				bIn.close();  
			} catch (CertificateException e) {  
				e.printStackTrace();  
			} catch (IOException e) {  
				e.printStackTrace();  
			}  
			return dn;  
		}  

		public static String parseCertDN(String dn, String type) {  
			type = type + "=";  
			String[] split = dn.split(",");  
			for (String x : split) {  
				if (x.contains(type)) {  
					x = x.trim();  
					return x.substring(type.length());  
				}  
			}  
			return null;  
		}  

		public String genCSR(String subject, String pemPath, String pemPassword)  
				throws InvalidKeyException, NoSuchAlgorithmException,  
				NoSuchProviderException, SignatureException {  
			try {  
				X509Name dn = new X509Name(subject);  
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");  
				keyGen.initialize(1024);  
				KeyPair kp = keyGen.generateKeyPair();  
//				PKCS10 p10 = new PKCS10CSR("SHA1WithRSA", dn, kp.getPublic(),  
//						new DERSet(), kp.getPrivate());  
//				PKCS10CertificationRequest p10 = new PKCS10CertificationRequest(kp.getPublic().getEncoded());
				// PKCS10CertificationRequest p10 = new  
				// PKCS10CertificationRequest("SHA1WithRSA", dn, kp.getPublic(),  
				// null,  
				// kp.getPrivate());  
				// PKCS10CertificationRequest p10 = new  
				// PKCS10CertificationRequest("SHA1WithRSA", dn, kp.getPublic(), new  
				// DERSet(),  
				// kp.getPrivate());  
//				byte[] der = p10.getEncoded();  
				String code = "-----BEGIN CERTIFICATE REQUEST-----\n";  
//				code += new String(Base64.encode(der));  
				code += "\n-----END CERTIFICATE REQUEST-----\n";  
//				CertificationRequestInfo csrinfo = p10  
//						.getCertificationRequestInfo();  

				savePEM(kp.getPrivate(), pemPassword, pemPath);  

				return code;  
			} catch (Exception e) {  
				// TODO Auto-generated catch block  
				e.printStackTrace();  
			}  
			return null;  
		}  

		public static void saveX509Certificate(X509Certificate certificate,  
				String caCertPath) throws Exception {  
			FileOutputStream stream = new FileOutputStream(caCertPath);  
			stream.write(certificate.getEncoded());  
			stream.close();  
		}  

		public static void savePEM(PrivateKey key, String pemPassword,  
				String pemPath) throws Exception {  
//			PEMWriter writer = new PEMWriter(new FileWriter(pemPath));  
//			writer.writeObject(key, "DES-EDE3-CBC", pemPassword.toCharArray(),  
//					new SecureRandom());  
//			writer.close();  
		}  

		public static KeyPair getPrivateKey(String pemPath, final String pemPassword)  
				throws Exception {  
//			PEMReader reader = new PEMReader(new InputStreamReader(  
//					new FileInputStream(pemPath)), new PasswordFinder() {  
//				public char[] getPassword() {  
//					// TODO Auto-generated method stub  
//					return pemPassword.toCharArray();  
//				}  
//			});  
//			KeyPair key = (KeyPair) reader.readObject();  
//			return key;  
			return null;
		}  

		public static X509Certificate getCertificate(String caCertPath)  
				throws Exception {  
			CertificateFactory factory = new CertificateFactory();  
			FileInputStream inputStream = new FileInputStream(caCertPath);  
			X509Certificate certificate = (X509Certificate) factory  
					.engineGenerateCertificate(inputStream);  
			return certificate;  
		}  

		public byte[] createRootCert(String dn, String snStr, int validate,  
				String caCertPath, String caPemPath, String caPemPassword)  
						throws Exception {  
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");  
			keyGen.initialize(2048);  
			KeyPair kp = keyGen.generateKeyPair();  
			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();  
			certGen.setSerialNumber(new BigInteger(snStr));  
			certGen.setNotBefore(new Date(System.currentTimeMillis()));  
			certGen.setNotAfter(new Date(System.currentTimeMillis() + validate * 24  
					* 60 * 60 * 1000L));  
			certGen.setSubjectDN(new X500Principal(dn));  
			certGen.setPublicKey(kp.getPublic());  
			certGen.setIssuerDN(new X500Principal(dn));  
			certGen.setSignatureAlgorithm("SHA1WithRSA");  
			X509Certificate certificate = certGen.generate(kp.getPrivate());  
			saveX509Certificate(certificate, caCertPath);  
			savePEM(kp.getPrivate(), caPemPassword, caPemPath);  
			return certificate.getEncoded();  
		}  

		@SuppressWarnings("deprecation")  
		public int createUserCert(String dn, String serialNumber, int validate,  
				String userCertPath, String userPemPath, String userPemPassword,  
				String caCertPath, String caPemPath, String caPemPassword) {  

			try {  
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");  
				keyGen.initialize(1024);  
				KeyPair keyPair = keyGen.generateKeyPair();  

				X509Certificate caCert = getCertificate(caCertPath);  

				KeyPair caKey = getPrivateKey(caPemPath, caPemPassword);  

				X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();  
				X500Principal subjectName = new X500Principal(dn);  
				certGen.setSerialNumber(new BigInteger(serialNumber));  
				certGen.setIssuerDN(caCert.getSubjectX500Principal());  
				certGen.setNotBefore(new Date(System.currentTimeMillis()));  
				certGen.setNotAfter(new Date(System.currentTimeMillis() + validate  
						* 24 * 60 * 60 * 1000L));  
				certGen.setSubjectDN(subjectName);  
				certGen.setPublicKey(keyPair.getPublic());  
				certGen.setSignatureAlgorithm("SHA1WithRSA");  

				certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,  
						new AuthorityKeyIdentifierStructure(caCert));  

//				certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,  
//						new SubjectKeyIdentifierStructure(keyPair.getPublic()));  

				X509Certificate cert = certGen.generate(caKey.getPrivate(), "BC");  
				saveX509Certificate(cert, userCertPath);  
				savePEM(keyPair.getPrivate(), userPemPassword, userPemPath);  
			} catch (CertificateParsingException e) {  
				// TODO Auto-generated catch block  
				e.printStackTrace();  
			} catch (InvalidKeyException e) {  
				// TODO Auto-generated catch block  
				e.printStackTrace();  
			} catch (CertificateEncodingException e) {  
				// TODO Auto-generated catch block  
				e.printStackTrace();  
			} catch (IllegalStateException e) {  
				// TODO Auto-generated catch block  
				e.printStackTrace();  
			} catch (NoSuchProviderException e) {  
				// TODO Auto-generated catch block  
				e.printStackTrace();  
			} catch (NoSuchAlgorithmException e) {  
				// TODO Auto-generated catch block  
				e.printStackTrace();  
			} catch (SignatureException e) {  
				// TODO Auto-generated catch block  
				e.printStackTrace();  
			} catch (Exception e) {  
				// TODO Auto-generated catch block  
				e.printStackTrace();  
			}  
			return 0;  
		}  

		public static X509Certificate signCert(String csrStr, String userCertPath,  
				String caCertPath, String caPemPath, String caPemPassword)  
						throws InvalidKeyException, NoSuchAlgorithmException,  
						NoSuchProviderException, SignatureException, IOException,  
						OperatorCreationException, CertificateException {  

			try {  
				csrStr = csrStr.replaceAll("-----BEGIN CERTIFICATE REQUEST-----\n",  
						"");  
				csrStr = csrStr.replaceAll("\n-----END CERTIFICATE REQUEST-----\n",  
						"");  
				byte[] der = Base64.decode(csrStr);  

				KeyPair caPair;  

				caPair = getPrivateKey(caPemPath, caPemPassword);  

				X509Certificate caCert = getCertificate(caCertPath);  
				// X500Principal subjectName = new  
				// X500Principal(p10.getSubject().toString());  
				PKCS10CertificationRequest p10CSR = new PKCS10CertificationRequest(  
						der);  

				AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()  
				.find("SHA1withRSA");  
				AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()  
				.find(sigAlgId);  

				AsymmetricKeyParameter foo = PrivateKeyFactory.createKey(caPair  
						.getPrivate().getEncoded());  

				SubjectPublicKeyInfo pkInfo = p10CSR.getSubjectPublicKeyInfo();  
				RSAKeyParameters rsa = (RSAKeyParameters) PublicKeyFactory  
						.createKey(pkInfo);  
				RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(rsa.getModulus(),  
						rsa.getExponent());  
				KeyFactory kf = KeyFactory.getInstance("RSA");  
				PublicKey rsaPub = kf.generatePublic(rsaSpec);  

				SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo(  
						ASN1Sequence.getInstance(rsaPub.getEncoded()));  
				X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(  
						new X500Name(caCert.getIssuerDN().getName()),  
						new BigInteger("1"), new Date(System.currentTimeMillis()),  
						new Date(System.currentTimeMillis() + 30 * 365 * 24 * 60  
								* 60 * 1000), p10CSR.getSubject(), keyInfo);  

				ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId,  
						digAlgId).build(foo);  

				X509CertificateHolder holder = myCertificateGenerator.build(sigGen);  

				Certificate eeX509CertificateStructure = holder.toASN1Structure();  

				CertificateFactory cf = new CertificateFactory();  

				// Read Certificate  
				InputStream is1 = new ByteArrayInputStream(  
						eeX509CertificateStructure.getEncoded());  
				X509Certificate theCert = (X509Certificate) cf  
						.engineGenerateCertificate(is1);  
				is1.close();  
				saveX509Certificate(theCert, userCertPath);  
				return theCert;  
			} catch (Exception e) {  
				// TODO Auto-generated catch block  
				e.printStackTrace();  
			}  

			return null;  
		}  

		@SuppressWarnings("deprecation")  
		public int createUserCertEx(String p10CSR, String serialNumber,  
				int validate, String userCertPath, String caCertPath,  
				String caPemPath, String caPemPassword) {  
			try {  
				p10CSR = p10CSR.replaceAll("-----BEGIN CERTIFICATE REQUEST-----\n",  
						"");  
				p10CSR = p10CSR.replaceAll("\n-----END CERTIFICATE REQUEST-----\n",  
						"");  
				byte[] der = Base64.decode(p10CSR);  
				PKCS10CertificationRequest p10 = new PKCS10CertificationRequest(der);  
				X509Certificate caCert = getCertificate(caCertPath);  

				KeyPair caKey = getPrivateKey(caPemPath, caPemPassword);  


				SubjectPublicKeyInfo pkInfo = p10.getSubjectPublicKeyInfo();  
				RSAKeyParameters rsa = (RSAKeyParameters) PublicKeyFactory  
						.createKey(pkInfo);  
				RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(rsa.getModulus(),  
						rsa.getExponent());  
				KeyFactory kf = KeyFactory.getInstance("RSA");  
				PublicKey rsaPub = kf.generatePublic(rsaSpec);  


				X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();  
				X500Principal subjectName = new X500Principal(p10.getSubject()  
						.toString());  
				certGen.setSerialNumber(new BigInteger(serialNumber));  
				certGen.setIssuerDN(caCert.getSubjectX500Principal());  
				certGen.setNotBefore(new Date(System.currentTimeMillis()));  
				certGen.setNotAfter(new Date(System.currentTimeMillis() + validate  
						* 24 * 60 * 60 * 1000L));  
				certGen.setSubjectDN(subjectName);  
				// certGen.setPublicKey(p10.getSubjectPublicKeyInfo().getPublicKey().getEncoded());  
				certGen.setSignatureAlgorithm("SHA1WithRSA");  

				certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,  
						new AuthorityKeyIdentifierStructure(caCert));  

//				certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,  
//						new SubjectKeyIdentifierStructure(rsaPub.getEncoded()));  

				X509Certificate cert = certGen.generate(caKey.getPrivate(), "BC");  
				saveX509Certificate(cert, userCertPath);  
			} catch (CertificateParsingException e) {  
				// TODO Auto-generated catch block  
				e.printStackTrace();  
			} catch (InvalidKeyException e) {  
				// TODO Auto-generated catch block  
				e.printStackTrace();  
			} catch (CertificateEncodingException e) {  
				// TODO Auto-generated catch block  
				e.printStackTrace();  
			} catch (IllegalStateException e) {  
				// TODO Auto-generated catch block  
				e.printStackTrace();  
			} catch (NoSuchProviderException e) {  
				// TODO Auto-generated catch block  
				e.printStackTrace();  
			} catch (NoSuchAlgorithmException e) {  
				// TODO Auto-generated catch block  
				e.printStackTrace();  
			} catch (SignatureException e) {  
				// TODO Auto-generated catch block  
				e.printStackTrace();  
			} catch (Exception e) {  
				// TODO Auto-generated catch block  
				e.printStackTrace();  
			}  
			return 0;  
		}  

		// public static void createUserCert(String subjectDN, String snStr,  
		// int validate, String caCertPath, String caPemPath,  
		// String caPemPassword, String userCertPath, String userPemPath,  
		// String userPenPassword) throws Exception {  
		// X509Certificate CA = getCertificate(caCertPath);  
		// KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");  
		// keyGen.initialize(1024);  
		// KeyPair pair = keyGen.generateKeyPair();  
		//  
		// X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();  
		// certGen.setSerialNumber(new BigInteger(snStr));  
		// certGen.setNotBefore(new Date(System.currentTimeMillis()));  
		// certGen.setNotAfter(new Date(System.currentTimeMillis() + validate * 24  
		// * 60 * 60 * 1000L));  
		// certGen.setSubjectDN(new X500Principal(subjectDN));  
		// certGen.setPublicKey(pair.getPublic());  
		// certGen.setIssuerDN(CA.getIssuerX500Principal());  
		// certGen.setSignatureAlgorithm("SHA1WithRSA");  
		//  
		// X509Certificate certificate = certGen.generate(pair.getPrivate());  
		// byte[] src = certificate.getEncoded();  
		// KeyPair key = getPrivateKey(caPemPath, caPemPassword);  
		// // byte[] b = HongAnUtils.RSASign(key.getPrivate(), src);  
		// X509CertImpl newcert = new X509CertImpl(src);  
		// X509CertInfo info = (X509CertInfo) newcert.get(newcert.getName() + "."  
		// + newcert.INFO);  
		// X509CertImpl export = new X509CertImpl(info);  
		// export.sign(key.getPrivate(), "SHA1WithRSA");  
		// savePEM(pair.getPrivate(), userPenPassword, userPemPath);  
		// DEROutputStream stream = new DEROutputStream(new FileOutputStream(  
		// userCertPath));  
		// stream.write(export.getEncoded());  
		// stream.close();  
		// }  

		public java.security.cert.Certificate certToX509Cert(X509Certificate cert) {  
			try {  
				CertificateFactory cf = new CertificateFactory();  
				InputStream is = new ByteArrayInputStream(cert.getEncoded());  
				Collection coll = cf.engineGenerateCertificates(is);  
				java.security.cert.Certificate jcrt = null;  
				Iterator it = coll.iterator();   
				if (it.hasNext()) {  
					jcrt = (java.security.cert.Certificate) it.next();   
					return jcrt;  
				}  
			} catch (CertificateEncodingException e) {  
				// TODO Auto-generated catch block  
				e.printStackTrace();  
			} catch (CertificateException e) {  
				// TODO Auto-generated catch block  
				e.printStackTrace();  
			}  
			return null;  
		}  

		public int storeP12(String caCertPath, String certPath, String pemPath, String pemPassword,  
				String p12Path, String p12Password) {  
			KeyPair kp;  
			try {  
				kp = getPrivateKey(pemPath, pemPassword);  
				X509Certificate caCert = getCertificate(caCertPath);  
				X509Certificate cert = getCertificate(certPath);  
				java.security.cert.Certificate[] chain = new java.security.cert.Certificate[2];  
				chain[0] = certToX509Cert(cert);  
				chain[1] = certToX509Cert(caCert);  
				KeyStore ks = KeyStore.getInstance("PKCS12", "BC");  
				ks.load(null, null);  
				ks.setKeyEntry(parseCertDN(cert.getSubjectDN().getName(), "CN"),  
						kp.getPrivate(), null, chain);  
				FileOutputStream fOut = new FileOutputStream(p12Path);  
				ks.store(fOut, p12Password.toCharArray());  
			} catch (Exception e) {  
				// TODO Auto-generated catch block  
				e.printStackTrace();  
			}  
			return 0;  
		}  
		

		public static String genCSR2(String subject, String alg,String provider)
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException, OperatorCreationException {
			String signalg="";
			int alglength=0;
			String keyAlg="";
			if(alg.toUpperCase().equals("RSA1024")){
				signalg="SHA1WithRSA";
				alglength=1024;
				keyAlg="RSA";
			}else if(alg.toUpperCase().equals("RSA2048")){
				signalg="SHA1WithRSA";
				alglength=2048;
				keyAlg="RSA";
			}else if(alg.toUpperCase().equals("SM2")){
				signalg="SM3withSM2";
				alglength=256;
				keyAlg="SM2";
			}
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlg);
			keyGen.initialize(alglength);
			KeyPair kp = keyGen.generateKeyPair();
			PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(new X500Name(subject),SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded()));
			JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(signalg);
			jcaContentSignerBuilder.setProvider(provider);
			ContentSigner contentSigner = jcaContentSignerBuilder.build(kp.getPrivate());
			PKCS10CertificationRequest p10req = builder.build(contentSigner);
			try {
				byte[] bytes = p10req.getEncoded();
				//return Convert.bytesToHexString(bytes);
				return Base64Decode.encode(bytes);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return null;
		}
		
		public static void main(String[] args) {  
			// TODO Auto-generated method stub  
			Security.addProvider(new BouncyCastleProvider());
			try {
				System.out.println(genCSR2("CN=country,ST=state,L=Locality,OU=OrganizationUnit,O=Organization", "RSA2048", "BC"));
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (SignatureException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (OperatorCreationException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}  

}
