package com.watchdata.test.gp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERBoolean;
import org.bouncycastle.asn1.DERExternal;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;

/**
 * Created by libo on 2016/4/26.
 */
public class WDDerCode {
    public static ASN1Object DNToASN1(String DN)
    {
        String strcn = DN.substring(DN.indexOf("=") + 1, DN.indexOf(","));
        DERObjectIdentifier Identifier = new DERObjectIdentifier("2.5.4.3");
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(Identifier);
        v.add(new DERPrintableString(strcn));

        DERSequence SQ1=new DERSequence(v);
        DERSet ser1=new DERSet(SQ1);

        Identifier = new DERObjectIdentifier("2.5.4.11");
        v = new ASN1EncodableVector();
        v.add(Identifier);
        v.add(new DERPrintableString("Personal Customer"));

        DERSequence SQ2=new DERSequence(v);
        DERSet ser2=new DERSet(SQ2);

        Identifier = new DERObjectIdentifier("2.5.4.10");
        v = new ASN1EncodableVector();
        v.add(Identifier);
        v.add(new DERPrintableString("BOC"));
        DERSequence SQ4=new DERSequence(v);
        DERSet ser4=new DERSet(SQ4);

        Identifier = new DERObjectIdentifier("2.5.4.6");
        v = new ASN1EncodableVector();
        v.add(Identifier);
        v.add(new DERPrintableString("CN"));
        DERSequence SQ5=new DERSequence(v);
        DERSet ser5=new DERSet(SQ5);


        ASN1EncodableVector SQ=new ASN1EncodableVector();
        SQ.add(ser1);
        SQ.add(ser2);
        if(ser4!=null)
            SQ.add(ser4);
       // if(ser5!=null)
       //     SQ.add(ser5);


        return new DERSequence(SQ);
    }

    public static ASN1Object KeyToASN1(byte[]pPub,int nKeyLen)
    {
        DERObjectIdentifier Identifier1 = new DERObjectIdentifier("1.2.840.10045.2.1");
        DERObjectIdentifier Identifier2 = new DERObjectIdentifier("1.2.156.10197.1.301");
        DERObjectIdentifier Identifier1RSA = new DERObjectIdentifier("1.2.840.113549.1.1.1");

        ASN1EncodableVector v0 = new ASN1EncodableVector();
        ASN1EncodableVector v = new ASN1EncodableVector();
        if(nKeyLen==256) {
            v.add(Identifier1);
            v.add(Identifier2);
        }else
        {
            v.add(Identifier1RSA);
            v.add(new DERNull());
        }
        byte[]berKey =null;
        if(nKeyLen==1024)
        {
            String keystr = WDCommInterface.printHexStringlen(pPub,128);
            keystr = "30818902818100"+keystr+"0203010001";
            berKey = WDCommInterface.stringToHexBytes(keystr);
        }else if(nKeyLen==2048)
        {
            String keystr = WDCommInterface.printHexStringlen(pPub,256);
            keystr = "3082010a0282010100"+keystr+"0203010001";
            berKey = WDCommInterface.stringToHexBytes(keystr);
        }else
        {
            String keystr = WDCommInterface.printHexStringlen(pPub,64);
            keystr = "04"+keystr;
            berKey = WDCommInterface.stringToHexBytes(keystr);
        }
        DERSequence SQ = new DERSequence(v);
        DERBitString pubkey =new DERBitString(berKey);
        v0.add(SQ);
        v0.add(pubkey);
        return  new DERSequence(v0);
    }

    public static ASN1Object CertAtrToASN1()
    {
        DERObjectIdentifier Identifier1 = new DERObjectIdentifier("1.3.6.1.4.1.311.2.1.14");
        DERObjectIdentifier Identifier2 = new DERObjectIdentifier("2.5.29.15");
        ASN1EncodableVector v = new ASN1EncodableVector();
        ASN1EncodableVector v0 = new ASN1EncodableVector();
        v.add(Identifier2);
        v.add(new DERBoolean(true));
        byte[]set = {0x03,0x02,0x04,(byte)0x90};
        v.add(new DEROctetString(set));
        DERSequence SQ0= new DERSequence(v);
        DERSequence SQ = new DERSequence(SQ0);
        DERSet Set = new DERSet(SQ);
        v0.add(Identifier1);
        v0.add(Set);
        DERSequence SQ1 = new DERSequence(v0);
        DERSequence SQ2= new DERSequence(SQ1);
        ASN1Primitive cert = SQ2.toASN1Object();
        DERTaggedObject obj = new DERTaggedObject(false,0,cert);
        return obj;

    }

    public static ASN1Object SignAlgToASN1(int nKeyLen,int nHash)
    {
        DERObjectIdentifier Identifier1 = new DERObjectIdentifier("1.2.156.10197.1.501");
        DERObjectIdentifier Identifier1RSAsha1 = new DERObjectIdentifier("1.2.840.113549.1.1.5");
        DERObjectIdentifier Identifier1RSAmd5 = new DERObjectIdentifier("1.2.840.113549.1.1.4");

        ASN1EncodableVector v0 = new ASN1EncodableVector();
        ASN1EncodableVector v = new ASN1EncodableVector();
        if(nKeyLen==256)
        v.add(Identifier1);
        else {
            if(nHash==4)
            v.add(Identifier1RSAsha1);
            if(nHash==3)
                v.add(Identifier1RSAmd5);
            v.add(new DERNull());
        }
        return  new DERSequence(v);
    }

    public static byte[] CreateP10(String DN,int nKeyLen,int nHash,byte[]pPubKey,byte[]signres) {
        ASN1Object obj1 = WDDerCode.DNToASN1(DN);
        ASN1Object obj2 = WDDerCode.CertAtrToASN1();
        byte[]Asn1pub = new byte[nKeyLen/4];
        if(nKeyLen==1024||nKeyLen==2048)
            System.arraycopy(pPubKey,0,Asn1pub,0,nKeyLen/8);
        else
        {
            System.arraycopy(pPubKey,0,Asn1pub,0,64);
        }
        ASN1Object obj3 = WDDerCode.KeyToASN1(Asn1pub, nKeyLen);
        ASN1Object obj4 = WDDerCode.SignAlgToASN1(nKeyLen,nHash);
        ASN1EncodableVector v0 = new ASN1EncodableVector();
        v0.add(new DERInteger(0));
        v0.add(obj1);
        v0.add(obj3);
        v0.add(obj2);
        DERSequence S1 = new DERSequence(v0);

        byte certj[] = new byte[0];
        if(signres!=null) {
            ASN1EncodableVector v1 = new ASN1EncodableVector();
            v1.add(S1);
            v1.add(obj4);
            v1.add(new DERBitString(signres));
            DERSequence S2 = new DERSequence(v1);
            try {
                certj = S2.getEncoded();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        else
        {
            try {
                certj = S1.getEncoded();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return certj;
    }


}
