package com.watchdata.test.gp;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;


import sun.security.pkcs.PKCS7;

public class CertP7AndP10Util {
	
	/**
	 * 向CA机构申请，生成用户证�?
	 */
	public String generateCertFromCA(String certDN, String pubKeyHex, String signHex)
	{
		try{
			String p10CertReq = generateP10(certDN, pubKeyHex, signHex);
			String p7CertHexString = generateP7FromCA(p10CertReq);
			String userCertHex = saxCertFromP7(p7CertHexString);
			return userCertHex;
		}catch(Exception e)
		{
			return null;
		}		
	}
	
	/**
	 * 向CA机构申请证书，提交P10请求，返回P7
	 */
	public String generateP7FromCA(String p10Cert)
	{
		byte[] bP10 = WDCommInterface.stringToHexBytes(p10Cert);
		String p10Base64 = Base64Decode.encode(bP10);
		return requestCertToCA(p10Base64);
	}
	
	/**
	 * 解析P7，返回用户证�?
	 */
	public String saxCertFromP7(String p7CertHexString)
	{
		try {
			PKCS7 pkcs7 = new PKCS7(WDCommInterface.stringToHexBytes(p7CertHexString));
			X509Certificate[] certificates = pkcs7.getCertificates();
			X509Certificate userCert = certificates[1];
			byte[] uCertData = userCert.getEncoded();
			
			return WDCommInterface.printHexStringlen(uCertData,uCertData.length);
		}catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * 生成�?��签名的原始信�?
	 */
	public String generateCertReqToBeSigned(String certDN, String pubKeyHex)
	{
		try {
			int certKeyLen = 1024;
			if(pubKeyHex.length() >= 512)
			{
				certKeyLen = 2048;
			}
            byte[] realPubKey = WDCommInterface.stringToHexBytes(pubKeyHex);
			byte[] certReqToBeSigned = WDDerCode.CreateP10(certDN,certKeyLen,4,realPubKey,null);
			
			return WDCommInterface.printHexStringlen(certReqToBeSigned,certReqToBeSigned.length);
		}catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * 生成P10请求
	 */
	public String generateP10(String certDN, String pubKeyHex, String signHex)
	{
		try {
			int certKeyLen = 1024;
			if(pubKeyHex.length() >= 512)
			{
				certKeyLen = 2048;
			}
            byte[] realPubKey = WDCommInterface.stringToHexBytes(pubKeyHex);
            byte[] sig = WDCommInterface.stringToHexBytes(signHex);
            
			byte[] certReq = WDDerCode.CreateP10(certDN,certKeyLen,4,realPubKey,sig);
			
			return WDCommInterface.printHexStringlen(certReq,certReq.length);
		}catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * 计算hash SHA1算法
	 */
	public String Hash_SHA1(String dataHex)
	{
		try {
			byte[] data = WDCommInterface.stringToHexBytes(dataHex);
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			md.update(data);
			byte[] hash = md.digest();	
			
			return WDCommInterface.printHexStringlen(hash, hash.length);
		}catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * 获取公钥
	 */
	public static PublicKey getPublicKey(String hexPublic) throws Exception
    {    	
    	byte[] keyBytes = Convert.stringToHexBytes(hexPublic);
    	KeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = factory.generatePublic(keySpec);
        
        return publicKey;

    }
	
	/**
	 * 向CA机构发�? P10 base64证书请求，获取P7响应数据
	 */
	public String requestCertToCA(String p10Base64Str)
	{
		String CERT_ATTRIB = "UserAgent:Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; InfoPath.2; .NET CLR 2.0.50727; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022; .NET4.0C; .NET4.0E)";
		String strMode = "Mode=newreq";
		String strReq = "CertRequest=";                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        
		String strCertAttrib = "CertAttrib=";
		String strFriendlyType = "FriendlyType=";
		String strTmp;
		String strTargetStoreFlags = "TargetStoreFlags=0";
	    String strSaveCert = "SaveCert=no";
	    String strCertP10 = p10Base64Str;
	    
		StringBuffer req = new StringBuffer();
		StringBuilder sBuilder = new StringBuilder();
		
		PrintWriter pwPrintWriter = null;
     	BufferedReader bReader = null;
		int FormIndex;
		int endIndex;
		
		
		try {
			URL url = new URL("http://10.0.75.3/certsrv/certfnsh.asp");
			URLConnection urlConnection = url.openConnection();
			urlConnection.setRequestProperty("accept", "*/*");
			urlConnection.setRequestProperty("connection", "Keep-Alive");
			urlConnection.setRequestProperty("user-agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Maxthon; .NET CLR 1.1.4322; .NET CLR 2.0.50727)");
			urlConnection.setDoInput(true);
			urlConnection.setDoOutput(true);
			
			sBuilder.append(strMode);
			sBuilder.append("&");
			sBuilder.append(strReq);
			sBuilder.append(URLEncoder.encode(strCertP10,"UTF-8"));
			sBuilder.append("&");
			sBuilder.append(strCertAttrib);
			sBuilder.append(URLEncoder.encode(CERT_ATTRIB,"UTF-8"));
			sBuilder.append("&");
			sBuilder.append(strTargetStoreFlags);
			sBuilder.append("&");
			sBuilder.append(strSaveCert);
			
			
			pwPrintWriter = new PrintWriter(urlConnection.getOutputStream());
			pwPrintWriter.print(sBuilder.toString());
			pwPrintWriter.flush();
			
			bReader = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
			String line;
			while ((line = bReader.readLine()) != null) {
				req.append(line);	
			}
			FormIndex = req.indexOf("sPKCS7=sPKCS7");
			endIndex = req.lastIndexOf("sPKCS7=sPKCS7");
			req.delete(endIndex+128, req.length());
			req.delete(0, FormIndex);
			endIndex = req.lastIndexOf("& vbNewLine");
			req.delete(endIndex, req.length());
			strTmp = req.toString();
			strTmp = strTmp.replace("sPKCS7=sPKCS7", "");
			strTmp = strTmp.replace("vbNewLine", "");
			strTmp = strTmp.replace("&", "");
			strTmp = strTmp.replaceAll("\\s*","");
			strTmp = strTmp.replace("\"", "");
			//System.out.println(strTmp);
			
			byte[] p7Data = Base64Decode.decode(strTmp);
			
			return WDCommInterface.printHexStringlen(p7Data,p7Data.length);
			
		}catch(Exception e)
		{
			e.printStackTrace();
			return null;
		}finally{
			try {
				if (pwPrintWriter != null) {
					pwPrintWriter.close();
				}
				if (bReader != null) {
					bReader.close();
				}
				
			} catch (Exception e2) {
				// TODO: handle exception
				e2.printStackTrace();
			}
		}	
	}
	
	public static void main(String[] args) {
		
		CertP7AndP10Util certP7AndP10Util = new CertP7AndP10Util();
		
		try {
			KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
			keyGenerator.initialize(1024);
			KeyPair keyPair = keyGenerator.generateKeyPair();
			RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
			String tmp = publicKey.getFormat();
			System.out.println("publicKey.getFormat="+tmp);
			//byte[] pubKey = publicKey.getEncoded();
			BigInteger bigInteger = publicKey.getModulus();  
			byte[] pubKey = bigInteger.toByteArray();
			byte[] realPubKey = new byte[128];
			int pubLen =  128;
			int realLen = 0;
			if (pubKey[0] == 0) {

				System.arraycopy(pubKey, 1, realPubKey, 0, 128);
			}
			else {
				System.arraycopy(pubKey, 0, realPubKey, 0, 128);
			}

			String strPubKey = WDCommInterface.printHexStringlen(realPubKey,realPubKey.length);
			System.out.println("strPubKey="+strPubKey);
			
			String certDN = "CN=RSA1024T,OU=Personal Customer,O=BOC";
			String pubKeyHex = strPubKey;
			String certReqToBeSignedHexString = certP7AndP10Util.generateCertReqToBeSigned(certDN, pubKeyHex);
			byte[] certReqToBeSigned = WDCommInterface.stringToHexBytes(certReqToBeSignedHexString);
			
			java.security.Signature signature = java.security.Signature.getInstance("SHA1WithRSA");
            signature.initSign(keyPair.getPrivate());
            signature.update(certReqToBeSigned);
            byte[] sig = signature.sign();
            
            String signHex = WDCommInterface.printHexStringlen(sig,sig.length);
            
           String userCert = certP7AndP10Util.generateCertFromCA(certDN, pubKeyHex, signHex);
			
           System.out.println("userCert="+userCert);
           System.out.println("userCert Base64="+Base64Decode.encode(WDCommInterface.stringToHexBytes(userCert)));
           
		} catch (Exception e) {
			// TODO: handle exception
		}
	}
}
