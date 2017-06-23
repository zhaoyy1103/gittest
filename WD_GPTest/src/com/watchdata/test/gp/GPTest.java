package com.watchdata.test.gp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidParameterException;
import java.sql.Blob;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.watchdata.commons.lang.WDByteUtil;
import com.watchdata.gpep.factory.GPFactory;
import com.watchdata.gpep.gppack.GpInterface;
import com.watchdata.hsm.crypto.CryptTool;
import com.watchdata.tsm.security.crymachine.ICryptService;
import com.watchdata.tsm.security.crymachine.impl.SoftCryptServiceImpl;
import com.watchdata.tsm.security.service.Hsm;
import com.watchdata.tsm.security.service.impl.HsmImpl;

public class GPTest {
	
	/**
	 * 填充到8的整数倍，补0x80 0x00 0x00...
	 * @param data
	 * @return
	 */
	public static String padingData(String data) {
		StringBuffer sb = new StringBuffer();
		sb.append(data).append("80");
		while (sb.length() % 16 != 0) {
			sb.append("0");
		}

		return sb.toString();
	}
	
	public String ecrypt(AppBusinessT t, String keyFlag, String data)
	{
		Hsm hsm = new HsmImpl();
		CryptTool cryptTool = new CryptTool();
		ICryptService crytService = new SoftCryptServiceImpl();
		
		cryptTool.setCrytService(crytService);
		((HsmImpl)hsm).setCryptTool(cryptTool);
		
		
		DivData divData = new DivData(t.getKeyDivData());
		byte textData[] = WDByteUtil.HEX2Bytes(padingData(data));
		byte result[] = new byte[textData.length];
		// int flag = 0;
		hsm.encryptTripleDesCbcByMainKey(
				CommonTool.intToBytes2(Integer.parseInt(keyFlag, 16)),
				WDByteUtil.HEX2Bytes(divData.getDivKENC()),
				WDByteUtil.HEX2Bytes(divData.getDivSENC()), textData,
				CommonTool.intToBytes2(1),// 加密
				CommonTool.intToBytes2(1),// 3DES_CBC
				result);

		return WDByteUtil.bytes2HEX(result);
	}
	
	private int icvEncryptFlag(String mac) {
		if ("0000000000000000".equals(mac)) {
			return 1;// 不加密
		} else {
			return 2;// 加密
		}
	}
	
	public String cMac(AppBusinessT t, String keyFlag, String data)
	{
		Hsm hsm = new HsmImpl();
		CryptTool cryptTool = new CryptTool();
		ICryptService crytService = new SoftCryptServiceImpl();
		
		cryptTool.setCrytService(crytService);
		((HsmImpl)hsm).setCryptTool(cryptTool);
		
		
		DivData divData = new DivData(t.getKeyDivData());
		int flag = icvEncryptFlag(t.getCMac());
		byte result[] = new byte[8];
		// int resultflag = 0;

		hsm.generateMacByMainKey(
				CommonTool.intToBytes2(Integer.parseInt(keyFlag, 16)),
				WDByteUtil.HEX2Bytes(divData.getDivKMAC()),
				WDByteUtil.HEX2Bytes(divData.getDivSMAC()),
				WDByteUtil.HEX2Bytes(t.getCMac()),
				WDByteUtil.HEX2Bytes(padingData(data)),
				CommonTool.intToBytes2(2),// DES plus final3DES
				CommonTool.intToBytes2(flag),// 加密
				result);

		String cmac = WDByteUtil.bytes2HEX(result);
		if ("0000000000000000".equals(cmac)) {
			System.out.println("fail to computer CMAC!");
			throw new RuntimeException();
		}
		t.setCMac(cmac);

		return cmac;
	}
	
	public String GP_SelectApp(String aid, GpInterface gp) throws Exception
	{
		if(aid == null)
		{
			 return gp.selectSd("");
		}else{
			return gp.selectSd(aid);
		}
	}
	
	public String GP_InitalUpdate(String keyVersion, String hostChallenge, GpInterface gp)
	{
	 return gp.initalUpdate(keyVersion, "00", hostChallenge);
	}
	
	public String GP_ExternalAuth(String initUpdateResp, String securityLevel,
			AppBusinessT t) {
		if (initUpdateResp == null) {
			throw new InvalidParameterException("parameter initUpdateResp or hostChallenge invalid");
		}
		
		StringBuffer divData = new StringBuffer();
		String keyDiversificationData = initUpdateResp.substring(8, 20);
		String keyInformation = initUpdateResp.substring(20, 24);
		String sequenceCounter = initUpdateResp.substring(24, 28);
		String cardChallenge = initUpdateResp.substring(28, 40);
		String cardCryptoGram = initUpdateResp.substring(40, 56);
		
		// 记录密钥分散数据
		divData.append(keyDiversificationData).append(";");
		divData.append(sequenceCounter);
		t.setKeyDivData(divData.toString());

		
		// 封装指令
		String secureLevel = securityLevel;
		String apduHeard = "8482" + secureLevel + "0010";
		String macData = sequenceCounter + cardChallenge
				+ t.getChannelHostChanllenge();

		String keyFlag = "0001";
		// 加密数据
		String hostCryptogram = ecrypt(t, keyFlag, macData);
		hostCryptogram = hostCryptogram.substring(
				hostCryptogram.length() - 16, hostCryptogram.length());
		
		// 计算mac
		t.setCMac("0000000000000000");
		String apduTemp = apduHeard + hostCryptogram;
		String cMac = cMac(t, keyFlag, apduTemp);
		cMac = cMac.substring(cMac.length() - 16, cMac.length());
		t.setCMac(cMac);
		
		return apduHeard + hostCryptogram + cMac;
	}
	
	
	public static class DivData {

		public DivData(String divDatas) {
			String[] mes = divDatas.split(";");
			divKENC = mes[0] + "F001" + mes[0] + "0F01";
			divKMAC = mes[0] + "F002" + mes[0] + "0F02";
			divKDEK = mes[0] + "F003" + mes[0] + "0F03";
			divSENC = "0182" + mes[1] + "000000000000000000000000";
			divSMAC = "0101" + mes[1] + "000000000000000000000000";
			divSDEK = "0181" + mes[1] + "000000000000000000000000";
		}

		private String divKENC;
		private String divKMAC;
		private String divKDEK;

		private String divSENC;
		private String divSMAC;
		private String divSDEK;

		public String getDivKMAC() {
			return divKMAC;
		}

		public void setDivKMAC(String divKMAC) {
			this.divKMAC = divKMAC;
		}

		public String getDivKENC() {
			return divKENC;
		}

		public void setDivKENC(String divKENC) {
			this.divKENC = divKENC;
		}

		public String getDivKDEK() {
			return divKDEK;
		}

		public void setDivKDEK(String divKDEK) {
			this.divKDEK = divKDEK;
		}

		public String getDivSENC() {
			return divSENC;
		}

		public void setDivSENC(String divSENC) {
			this.divSENC = divSENC;
		}

		public String getDivSMAC() {
			return divSMAC;
		}

		public void setDivSMAC(String divSMAC) {
			this.divSMAC = divSMAC;
		}

		public String getDivSDEK() {
			return divSDEK;
		}

		public void setDivSDEK(String divSDEK) {
			this.divSDEK = divSDEK;
		}
	}

	public String blobToString(Blob blob) throws SQLException, IOException {

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		InputStream is = blob.getBinaryStream();
		byte data[] = new byte[1024];
		int len = 0;
		while ((len = is.read(data)) != -1) {

			bos.write(data, 0, len);
		}

		String result = WDByteUtil.bytes2HEX(bos.toByteArray());
		bos.close();
		is.close();

		return result;
	}
	
	public String InputStreamToString(InputStream in) throws IOException {

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		InputStream is = in;
		byte data[] = new byte[1024];
		int len = 0;
		while ((len = is.read(data)) != -1) {

			bos.write(data, 0, len);
		}

		String result = WDByteUtil.bytes2HEX(bos.toByteArray());
		bos.close();
		is.close();

		return result;
	}
	
	public void addArrayToList(String[] array, List<String> list) {
		if(null==array||0>=array.length) return ;
		if(null==list) return;
		for (int i = 0; i < array.length; i++) {
			list.add(array[i]);
		}
	}
	
	public List<String> genLoadCommand(AppBusinessT t, GpInterface gp) throws Exception
	{
		List<String> result = new ArrayList<String>();	
		String loadFileAID = "A000000333FE00000000000000081000";
		String sdAID = "A00000000353504200080807";
		int maxApduLen = 165;
		
//		Blob capFileBlob = null;//从数据库中获取cap文件内容
		String capFileContent = "";
//		capFileContent = blobToString(capFileBlob);
		
		String[] installForloadApdus = gp.installForLoad(loadFileAID, sdAID, null, null, "", maxApduLen);
		addArrayToList(installForloadApdus, result);
		
		String[] loadApdus = gp.load(capFileContent, maxApduLen);
		addArrayToList(loadApdus, result);
		
		String executableLoadFileAID = "A000000333FE00000000000000081000";
		String executableModuleAID = "A000000333FE00000000000000080001";
		String appAid = "A000000333FE00000000000000080001";
		String privileges = "00";
		String parameters = "C900";
		String token = "";
		
		String[] installForInstallApdus = gp.installForInstall(executableLoadFileAID, executableModuleAID,
				appAid, privileges, parameters, token, maxApduLen);
		addArrayToList(installForInstallApdus, result);
		
		//delete command
		//result.add(0, "80E40080124F10A000000333FE00000000000000081000");
		//result.add(0, "80E40000124F10A000000333FE00000000000000080001");
		//result.add(0, "80F22000124F10A000000333FE00000000000000081000");
		return result;
	}
	
	private String packApduForCmac(String apdu, String cmac) {
		return apdu + cmac;
	}

	private String parseApduForCmac(String apdu) {

		String lc = apdu.substring(8, 10);
		int len = Integer.parseInt(lc, 16) + 8;
		lc = Integer.toHexString(len);
		if (len <= 15) {

			lc = "0" + lc;
		}

		//String tempApdu = "84"+apdu.substring(2, 8) + lc + apdu.substring(10);
		//添加加密CLA修改,  add by jiajianming 20170601
		String cla = apdu.substring(0, 2);
		int icla = Integer.parseInt(cla, 16) ;
		icla =  ((icla | 0x04) & 0xFFFFFFFF);
		cla = Integer.toHexString(icla & 0xFFFFFFFF);
		if(icla <= 15)
		{
			cla = "0" + cla;
		}
		String tempApdu = cla  +apdu.substring(2, 8) + lc + apdu.substring(10);
		return tempApdu;
	}
	
	private String parseApduForEncrypt(String apdu) {

		return apdu.substring(10, apdu.length() - 16);
	}
	
	private String packApduForEncrypt(String apdu, String newData, int addLen) {

		String lc = apdu.substring(8, 10);
		int len = Integer.parseInt(lc, 16) + addLen;
		lc = Integer.toHexString(len);
		if (len < 15) {

			lc = "0" + lc;
		}

		String tempApdu = apdu.substring(0, 8) + lc + newData
				+ apdu.substring(apdu.length() - 16);
		return tempApdu;
	}
	
	private List<String> cmac(AppBusinessT t, String keyFlag, List<String> apduList)
	{
		List<String> result = new ArrayList<String>();
		for (int i = 0; i < apduList.size(); i++) {
			if(apduList.get(i).toUpperCase().startsWith("00C0")
					|| apduList.get(i).toUpperCase().startsWith("00A4")
					|| apduList.get(i).toUpperCase().startsWith("8050")
					|| apduList.get(i).toUpperCase().startsWith("8482")
					|| apduList.get(i).toUpperCase().startsWith("002A9E")
					|| apduList.get(i).toUpperCase().startsWith("002A91")
					|| apduList.get(i).toUpperCase().startsWith("0084")
					){
				//添加加密排除判断, add by jiajianming 20170601
				result.add(apduList.get(i));
			} else {
				String newApdu = parseApduForCmac(apduList.get(i));
				String cmac = cMac(t, keyFlag, newApdu);
				result.add(packApduForCmac(newApdu, cmac));
			}
		}
		return result;
	}
	
	private List<String> encrypt(AppBusinessT t, String keyFlag, List<String> apduList)
	{
		List<String> result = new ArrayList<String>();
		for (int i = 0; i < apduList.size(); i++) {
			if(apduList.get(i).toUpperCase().startsWith("00C0")
					|| apduList.get(i).toUpperCase().startsWith("00A4")
					|| apduList.get(i).toUpperCase().startsWith("8050")
					|| apduList.get(i).toUpperCase().startsWith("8482")
					|| apduList.get(i).toUpperCase().startsWith("002A9E")
					|| apduList.get(i).toUpperCase().startsWith("002A91")
					|| apduList.get(i).toUpperCase().startsWith("0084")
					){
				//添加加密排除判断, add by jiajianming 20170601
				result.add(apduList.get(i));
			}else {
				String data = parseApduForEncrypt(apduList.get(i));
				String newData = ecrypt(t, keyFlag, data);
				result.add(packApduForEncrypt(apduList.get(i), newData,
						(newData.length() - data.length()) / 2));
			}
		}
		return result;
	}
			
	public List<String> securityManageBySCP(AppBusinessT t,
			List<String> apduList) {
		// 无安全级
		if ("00".equals(t.getSecurityLevel())) {

			return apduList;
		}

		String keyFlag = "0001";
		// 01 cmac
		if ("01".equals(t.getSecurityLevel())) {
			List<String> result = cmac(t, keyFlag, apduList);
			return result;
		}

		// 03 encrypt and cmac
		if ("03".equals(t.getSecurityLevel())) {
			List<String> result = cmac(t, keyFlag, apduList);
			result = encrypt(t, keyFlag, result);
			return result;
		}
		
		throw new RuntimeException("unknow security level ["
				+ t.getSecurityLevel() + "] ...");
	}
	public static void main(String[] args) throws Exception {
		
		//
		String apdu;
		String ssdAID = "A00000000353504200080807";
		String securityLevel = "03"; //00 or 01 or 03
		
		GPTest gpTest = new GPTest();		
		AppBusinessT t = new AppBusinessT();		
		GpInterface gp = new GPFactory().getBean("2.2",	securityLevel);
		
		t.setSecurityLevel(securityLevel);
		
		//选择应用
		apdu = gpTest.GP_SelectApp(ssdAID, gp);
		System.out.println(apdu);
		
		//安全通道initUpdate
		String hostChallenge = "3847637108153742";//change it to random
		t.setChannelHostChanllenge(hostChallenge);
		String keyVersion = "00";
		apdu = gpTest.GP_InitalUpdate(keyVersion, hostChallenge, gp);
		System.out.println(apdu);
		
		//安全通道externalAuth
		String initUpdateResp = "8888076C1CAD780050002002000CE139EBBAB4D0726F87EC756424749000";
		String sw = initUpdateResp.substring(initUpdateResp.length()-4, initUpdateResp.length());
		if (!sw.equals("9000")) {
			throw new Exception(
					"initUpdate: without response command SW=" + sw);
		}
		
		apdu = gpTest.GP_ExternalAuth(initUpdateResp, securityLevel, t);
		System.out.println(apdu);
		
		//84820000108238B0DC365D6FDA6FD83174A20CED04
		//下载和安装applet 		
		List<String> result = gpTest.genLoadCommand(t, gp);
		for(int i = 0; i < result.size(); i++)
		{
			//明文指令
			//System.out.println(result.get(i));
		}
		
		result = gpTest.securityManageBySCP(t, result);
		//for(int i = 0; i < result.size(); i++)
	    for(int i = 0; i < 3; i++)
		{
			//密文指令
			System.out.println(result.get(i));
		}
	    //84F220002018D33D718092D808CB82C7335C17D6EFBD03917EBF1EBEFBBAC7DC4E57413784
	    //84E400002018D33D718092D808CB82C7335C17D6EF7A772FA3A0777C4F57BC38ACEB8672D7
	    //84E400802018D33D718092D808CB82C7335C17D6EFBD03917EBF1EBEFB8490FFFE26E077D8
		
		//个人化过程
		String appAid = "A000000333FE00000000000000080001";
		apdu = gpTest.GP_SelectApp(appAid, gp);
		System.out.println(apdu);
		
		hostChallenge = "1122334455667788";//change it to random
		t.setChannelHostChanllenge(hostChallenge);
		apdu = gpTest.GP_InitalUpdate(keyVersion, hostChallenge, gp);
		System.out.println(apdu);
		
		apdu = gpTest.GP_ExternalAuth(initUpdateResp, securityLevel, t);
		System.out.println(apdu);
		
		PersonalHandler personalHander = new PersonalHandler();
		result = personalHander.PersonalStep1(null);
		for(int i = 0; i < result.size(); i++)
		{
			//明文指令
			//System.out.println(result.get(i));
		}
		result = gpTest.securityManageBySCP(t, result);
		for(int i = 0; i < result.size(); i++)
		{
			//密文指令
			System.out.println(result.get(i));
		}
		
		String cardChallengeResp = "11223344556677889000";
		result = personalHander.PersonalStep2(cardChallengeResp);
		for(int i = 0; i < result.size(); i++)
		{
			//明文指令
			//System.out.println(result.get(i));
		}
		result = gpTest.securityManageBySCP(t, result);
		for(int i = 0; i < result.size(); i++)
		{
			//密文指令
			System.out.println(result.get(i));
		}
		
		result = personalHander.PersonalStep3(null);
		for(int i = 0; i < result.size(); i++)
		{
			//明文指令
			//System.out.println(result.get(i));
		}
		result = gpTest.securityManageBySCP(t, result);
		for(int i = 0; i < result.size(); i++)
		{
			//密文指令
			System.out.println(result.get(i));
		}
		
		result = personalHander.PersonalStep4(null);
		for(int i = 0; i < result.size(); i++)
		{
			//明文指令
			//System.out.println(result.get(i));
		}
		result = gpTest.securityManageBySCP(t, result);
		for(int i = 0; i < result.size(); i++)
		{
			//密文指令
			System.out.println(result.get(i));
		}
		
		String pubKeyResp = "994F5940CC9BB7AE733AA7C59D6CD77D7A27D0BFB421AD0F9353D294AB7330B659CD64AC33AF0A43FF798A0334E61E9E39E42BEE27D3201F52A6B13355DF43D976FB1B9AA425524A7D7418732D0FC4C7169A563A3DDD9C118706D8AB419A00417B955954C1815A80A90C2E146D3CB363141C2887D7CC7E3C0B9CFA6B3CDCF0A79000";
		result = personalHander.PersonalStep5(pubKeyResp);
		for(int i = 0; i < result.size(); i++)
		{
			//明文指令
			//System.out.println(result.get(i));
		}
		result = gpTest.securityManageBySCP(t, result);
		for(int i = 0; i < result.size(); i++)
		{
			//密文指令
			System.out.println(result.get(i));
		}
		
		String signResp = "680382FD1556035E5A9D0FEA8ECE0033817ED4E8A75FD3219099BE331478908539573318047E7AF64814C64CB4ED1992591B830E6C6862483CD66FB58A42B3B5093A098D058DD502950057CE1E7A1BB881D1C523908BDB5FEF4276E7A86AA03B1B735A1ED76B88EA31FEC3094707D483A541068304D4A6BFA065A6A436ACB1F49000";
		result = personalHander.PersonalStep6(signResp);
		for(int i = 0; i < result.size(); i++)
		{
			//明文指令
			//System.out.println(result.get(i));
		}
		result = gpTest.securityManageBySCP(t, result);
		for(int i = 0; i < result.size(); i++)
		{
			//密文指令
			System.out.println(result.get(i));
		}
	}
}
