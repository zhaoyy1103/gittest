package com.watchdata.test.gp;

import java.security.MessageDigest;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;

import org.bouncycastle.crypto.RuntimeCryptoException;

import com.watchdata.commons.crypto.WD3DesCryptoUtil;
import com.watchdata.commons.jce.JceBase.Padding;
import com.watchdata.commons.lang.WDStringUtil;

public class PersonalHandler {
	
	
	//公钥加密密钥，每个设备均不同，根据指定算法进行分�?
	private String pubkEncKey = "202122232425262728292a2b2c2d2e2f";
	
	//解锁密钥，每个设备均不同，根据指定算法进行分散，初始默认88888888
	private String unlockKey = "3838383838383838FFFFFFFFFFFFFFFF";
	
	//序列号，每个设备均不�?
	private String SN = "31323334353637383938373635343332";
	
	//初始用户PIN
	private String PIN = "123456FFFFFFFFFF";
	
	private String pubKeyString = "";
	
	private String signString = "";
	
	private CertP7AndP10Util certP7AndP10Util = new CertP7AndP10Util();
	
	public String intToHexString(int i)
	{		
		String result = Integer.toHexString(i);
		if(result.length() % 2 == 1)
		{
			result = "0" + result;
		}
		return result;		
	}

	public String getRandom() {
		return WDStringUtil.getRandomNumString(16);// 生成随机
	}
	
	public List<String> GP_StoreData()
	{
		List<String> apdus = new ArrayList<String>();
		// 创建�?��文件（只可执行一次，且必须在安全通道中执行）
	    // 创建公钥文件       �?A文件，公钥类型文件，安全通道下读、不可写，在产生公私钥对指令时，由证书应用内部写入）
		apdus.add("80E2000407EF2102040A0300");
		// 创建私钥文件        �?B文件，私钥类型文件，不可读�?不可写，在产生公私钥对指令时，由证书应用内部写入�?
		apdus.add("80E2000407EF2204040B0600");
		// 创建用户信息文件    �?C文件，二进制文件，任意读、安全�?道下验PIN写）
		apdus.add("80E2000007000400030C001E");
		// 创建文件PKCS7文件   �?D文件，二进制文件，任意读、安全�?道下验PIN写）
		//特殊说明：原始个人化空间�?x1000，因卡片空间不足，修改为0x0100
		apdus.add("80E2000007000100030D0800");
		// 创建公钥加密密钥文件�?E文件，二进制文件，长�?6字节，不可读、安全�?道下验PIN写）
		apdus.add("80E2000007EF2304030E0010");
		// 创建解锁密钥文件    �?F文件，二进制文件，长�?6字节，不可读、安全�?道下验PIN写）
		apdus.add("80E2000007EF2604030F0010");
		 // 创建序列号文�?     �?0文件，二进制文件，长�?6字节，可任意读�?安全通道下验PIN写）
		apdus.add("80E2000007EF240003100010");
		// 创建状�?文件        �?1文件，二进制文件，长�?字节，可任意读�?安全通道下验PIN写）
		apdus.add("80E2000007EF250000110004");
		
		return apdus;
	}
	
	/**
	 * 设置PIN
	 * @param pin
	 * @return
	 */
	public String GP_LoadPIN(String pin)
	{
		if(pin == null || "".equals(pin))
		{
			return null;
		}
		
		StringBuffer apduBuf = new StringBuffer();
		apduBuf.append("80F40000");
		apduBuf.append(intToHexString(pin.length()/2+2));
		apduBuf.append("0505");
		apduBuf.append(pin);		
		
		return apduBuf.toString();
	}
	
	public String GP_GetChallenge(int outlen)
	{
		StringBuffer apduBuf = new StringBuffer();
		apduBuf.append("00840000")
		.append(intToHexString(outlen));
		
		return apduBuf.toString();
	}
	
	public String GP_ExternalAuth(String pin, String challenge)
	{
		if(pin == null || "".equals(pin))
		{
			return null;
		}
		if(challenge == null || "".equals(challenge))
		{
			return null;
		}
		
		//TODO
		String encData = "";
		String key = "";
		key = SHA1(pin).substring(0, 32);
		//encData = encrypt3DesECB(padingData(challenge),key);
		
		encData = WD3DesCryptoUtil.ecb_encrypt(key, padingData(challenge),
				Padding.NoPadding);
		encData = encData.substring(0, 16);
		
		StringBuffer apduBuf = new StringBuffer();
		apduBuf.append("0082000008")
		.append(encData);
		
		return apduBuf.toString();
	}
	
	public List<String> GP_VerifyPIN()
	{
		//获取挑战值GP_GetChallenge
		//进行外部认证GP_ExternalAuth
		
		return null;
	}
	
	public List<String> GP_WriteData(String pubkEncKey, String SN, String unlockKey)
	{
		List<String> apdus = new ArrayList<String>();
		//写入0E文件  装载公钥加密密钥
		apdus.add("00D68E0010"+pubkEncKey);
		
		//写入0F文件进行个人�?  装载解锁密钥
		apdus.add("00D68F0010"+unlockKey);
		
		//写入10文件进行个人�?  装载序列�?
		apdus.add("00D6900010"+SN);
		
//		//写入11文件进行个人�?  更新状�?
//		apdus.add("00D691000400000101");
		
		return apdus;
	}
	
	public String GP_UpdateStatusData()
	{
		return "00D691000400000101";
	}
	
	public List<String> GP_WriteData()
	{
		List<String> apdus = new ArrayList<String>();
		//写入0E文件  装载公钥加密密钥
		apdus.add("00DC00500701450101000083");
		apdus.add("00DC0058070145010100014B");
		
		return apdus;
	}
	
	
	public String GP_GenerateKeys()
	{
		//生成公私�?
		return "00470001020800";
	}
	
	public String GP_SecurityEnvironmentManager()
	{
		//安全环境管理
		return "003382A606800101820112";
	}
	
	public String GP_CalcHash(String hash)
	{
		if(hash == null)
		{
			return null;
		}
		//安全环境管理
		return "002A90A0169114"+hash;
	}
	
	public String GP_CalcSignature()
	{
		//安全环境管理
		return "002A9E9A00";
	}
	
	public List<String> GP_GenerateCerts(String certFileDataHex)
	{
		List<String> temp = new ArrayList<String>();
		
		int certFileDataHexLen = certFileDataHex.length();
		int certFileDataLen = certFileDataHexLen/2;
		int packetMaxLen = 0xC8;
		//只有�?��数据直接组织返回
		if( certFileDataLen <=  packetMaxLen)
		{
			String loadCert = "00D68D00"+intToHexString(certFileDataLen)+certFileDataHex;
			temp.add(loadCert);
			return temp;
		}
		//分包下发
		String certFileDataTmp = certFileDataHex;
		int offset = 0;
		
		//分包第一包数�?	
		temp.add("00D68D00"+intToHexString(packetMaxLen)+certFileDataTmp.substring(0, packetMaxLen*2));
		certFileDataTmp = certFileDataTmp.substring(packetMaxLen*2);
		offset += packetMaxLen;
		//分包中间包和�?���?��
		
		while(certFileDataTmp.length() > 0)
		{
			if((certFileDataTmp.length()/2) <= packetMaxLen)
			{
				//�?���?��处理
				String offsetHex = Convert.bytesToHexString(Convert.intToBytes(offset, 2));
				String loadCert = "00D6"+offsetHex+intToHexString(certFileDataTmp.length()/2)+certFileDataTmp;
				certFileDataTmp = certFileDataTmp.substring(certFileDataTmp.length());
				offset += (certFileDataTmp.length()/2);
				temp.add(loadCert);
			}else
			{
				//中间包处�?
				String offsetHex = Convert.bytesToHexString(Convert.intToBytes(offset, 2));
				String loadCert = "00D6"+offsetHex+intToHexString(packetMaxLen)+certFileDataTmp.substring(0, packetMaxLen*2);
				certFileDataTmp = certFileDataTmp.substring(packetMaxLen*2);
				offset += packetMaxLen;
				temp.add(loadCert);
			}
		}
		
		return temp;
	}
	
	
	public String GP_WriteStatusFile()
	{
		//安全环境管理
		return "00D691000400000101";
	}
	
	
	
	public List<String> PersonalStep1(String respCmd)
	{
		List<String> temp = new ArrayList<String>();
		
		//加载初始PIN
		temp.add(GP_LoadPIN(PIN));
		//创建文件
		temp.addAll(GP_StoreData());
		//取随机数
		temp.add(GP_GetChallenge(8));
				
		return temp;
	}
	
	public List<String> PersonalStep2(String respCmd)
	{
		List<String> temp = new ArrayList<String>();
		String cardChallenge = "0000000000000000";
		if(respCmd != null && respCmd.length() >= 20)
		{
			cardChallenge = respCmd.substring(0,16);
		}
		//校验PIN 
		temp.add(GP_ExternalAuth(PIN, cardChallenge));
		
		return temp;
	}
	
	public List<String> PersonalStep3(String respCmd)
	{
		List<String> temp = new ArrayList<String>();
		//更新二进制文
		temp.addAll(GP_WriteData(pubkEncKey, SN, unlockKey));
		
		return temp;
	}
	
	public List<String> PersonalStep4(String respCmd)
	{
		List<String> temp = new ArrayList<String>();
		//更新记录文件 
		temp.addAll(GP_WriteData());
		//生成公私
		temp.add(GP_GenerateKeys());
		
		return temp;
	}
	
	public List<String> PersonalStep5(String respCmd)
	{
		List<String> temp = new ArrayList<String>();
		pubKeyString = "";
		//取公钥		
		if(respCmd != null && respCmd.endsWith("9000"))
		{
			pubKeyString += respCmd.substring(0, respCmd.length()-4);
			if(pubKeyString.length() > 130 && pubKeyString.length() < 512)
			{
				//1024长度的公钥被加密传输过了，需要解�?
				pubKeyString = decrypt3DesECB(pubKeyString,pubkEncKey);
				//pubKeyString = pubKeyString.substring(4);
			}
			//安全环境管理
			temp.add(GP_SecurityEnvironmentManager());
			
			//组织P10请求原始信息
			String certDN = "CN=RSA1024T,OU=Personal Customer,O=BOC";
			if(pubKeyString.length() >= 512)
			{
				certDN = "CN=RSA2048T,OU=Personal Customer,O=BOC";
			}
			String hashSrcData = certP7AndP10Util.generateCertReqToBeSigned(certDN, pubKeyString);
			String hash = certP7AndP10Util.Hash_SHA1(hashSrcData);
			
			if(hash == null)
			{
				throw new RuntimeCryptoException("Personalize get hash is null, pubkey(hex)="+pubKeyString);
			}
			//计算hash,外部计算hash值进行传�?
			temp.add(GP_CalcHash(hash));
			
			//签名计算，生成p10请求
			temp.add(GP_CalcSignature());
			
		}		
		return temp;
	}
	
	public List<String> PersonalStep6(String respCmd)
	{
		List<String> temp = new ArrayList<String>();
		//取公
		signString = "";
		if(respCmd != null && respCmd.endsWith("9000"))
		{
			signString += respCmd.substring(0, respCmd.length()-4);
			
			//TODO 生成p10证书请求，向CA请求并签发证�?
			String certDN = "CN=RSA1024T,OU=Personal Customer,O=BOC";
			if(pubKeyString.length() >= 512)
			{
				certDN = "CN=RSA2048T,OU=Personal Customer,O=BOC";
			}
			String userCert = certP7AndP10Util.generateCertFromCA(certDN, pubKeyString, signString);
			
			//更新二进制文件（写证书）
			temp.addAll(GP_GenerateCerts(userCert));
			
			//更新个人化状态文�?
			temp.add(GP_UpdateStatusData());
			
		}		
		return temp;
	}
	
	
	public List<String> GetData(String respCmd)
	{
		List<String> temp = new ArrayList<String>();
		//取公�?
		if(respCmd != null && (respCmd.startsWith("61") || respCmd.startsWith("63") || respCmd.toUpperCase().startsWith("6C")))
		{
			temp.add("00C00000"+respCmd.substring(2, 4));
			return temp;			
		}
		return null;
	}
	public String SHA1(String hex)
	{
		try {
			byte[] data = Convert.stringToHexBytes(hex);
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			md.update(data);
			byte[] hash = md.digest();	  
			
			return Convert.bytesToHexString(hash);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	     
	     return "";
	}
	
	public String encryptDesECB(String datahex, String keyhex)
	{
		try {
			byte[] data = Convert.stringToHexBytes(datahex);
			byte[] key = Convert.stringToHexBytes(keyhex);
	       
			KeySpec ks = new DESKeySpec(key);
	        SecretKeyFactory kf = SecretKeyFactory.getInstance("DES");
	        SecretKey ky = kf.generateSecret(ks);
	        Cipher cf = Cipher.getInstance("DES/ECB/NoPadding");
	        cf.init(Cipher.ENCRYPT_MODE,ky);
	        byte[] theCph = cf.doFinal(data);
			
			return Convert.bytesToHexString(theCph);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return "";
	}
	
	public String encrypt3DesECB(String datahex, String keyhex)
	{
		try {
			byte[] data = Convert.stringToHexBytes(datahex);
			byte[] key = Convert.stringToHexBytes(keyhex);
			
			byte[] newkey = new byte[24];
	        if (key.length < 24) {
	            System.arraycopy(key, 0, newkey, 0, 16);
	            System.arraycopy(key, 0, newkey, 16, 8);
	        } else {
	            System.arraycopy(key, 0, newkey, 0, 24);
	        }
			DESedeKeySpec spec = new DESedeKeySpec(newkey);
	        SecretKeyFactory kf = SecretKeyFactory.getInstance("desede");
	        SecretKey ky = kf.generateSecret(spec);
	        Cipher cf = Cipher.getInstance("desede/ECB/NoPadding");
	        cf.init(Cipher.ENCRYPT_MODE,ky);
	        byte[] theCph = cf.doFinal(data);
			
			return Convert.bytesToHexString(theCph);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return "";
	}
	
	public String decrypt3DesECB(String datahex, String keyhex)
	{
		try {
			byte[] data = Convert.stringToHexBytes(datahex);
			byte[] key = Convert.stringToHexBytes(keyhex);
			
			byte[] newkey = new byte[24];
	        if (key.length < 24) {
	            System.arraycopy(key, 0, newkey, 0, 16);
	            System.arraycopy(key, 0, newkey, 16, 8);
	        } else {
	            System.arraycopy(key, 0, newkey, 0, 24);
	        }
			DESedeKeySpec spec = new DESedeKeySpec(newkey);
	        SecretKeyFactory kf = SecretKeyFactory.getInstance("desede");
	        SecretKey ky = kf.generateSecret(spec);
	        Cipher cf = Cipher.getInstance("desede/ECB/NoPadding");
	        cf.init(Cipher.DECRYPT_MODE,ky);
	        byte[] theCph = cf.doFinal(data);
			
			return Convert.bytesToHexString(theCph);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return "";
	}

	private String padingData(String data) {
		StringBuffer sb = new StringBuffer();
		sb.append(data).append("80");
		while (sb.length() % 16 != 0) {
			sb.append("0");
		}

		return sb.toString();
	}
	

	public static void main(String[] args) {
		
		PersonalHandler han =  new PersonalHandler();
		String encData = "";
		String key = "";
		key = han.SHA1("3132333435363738").substring(0, 32);
		//encData = encrypt3DesECB(padingData(challenge),key);
		
		encData = WD3DesCryptoUtil.ecb_encrypt(key, han.padingData("898A639584C5CA8B"),
				Padding.NoPadding);
		encData = encData.substring(0, 16);
		
		System.out.println(encData);
		
	}
}
