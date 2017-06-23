package com.watchdata.test.gp;

import java.io.UnsupportedEncodingException;

public class Base64Decode {   
    private static char[] base64EncodeChars = new char[] { 'A', 'B', 'C', 'D',   
            'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',   
            'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',   
            'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',   
            'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3',   
            '4', '5', '6', '7', '8', '9', '+', '/' };   
    private static byte[] base64DecodeChars = new byte[] { -1, -1, -1, -1, -1,   
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,   
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,   
            -1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59,   
            60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,   
            10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1,   
            -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,   
            38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1,   
            -1, -1 };   
       
       
    public static void main(String[] args) {   
        String string="abcd";   
        String encodeStr=encode(string.getBytes());   
        byte[] bytesStr=null;   
        try {   
             bytesStr=decode(encodeStr);   
        } catch (UnsupportedEncodingException e) {   
            // TODO Auto-generated catch block   
            e.printStackTrace();   
        }   
           
        System.out.println(encodeStr);   
        System.out.println(new String(bytesStr));   
        
        String ss = "308201A73082011002010030673110300E06035504030C07636F756E747279310E300C06035504080C0573746174653111300F06035504070C084C6F63616C69747931193017060355040B0C104F7267616E697A6174696F6E556E697431153013060355040A0C0C4F7267616E697A6174696F6E30819F300D06092A864886F70D010101050003818D0030818902818100AC8DC3D98A79190067B50740C8F41253A80C5999CA85660C77240B7BC0DA6A0E70C16FE19B064553AFEB12B73E78AB01E2A94D218318F390E4AB027588F121C491124816D94E99FD6CB521ED6AAEEB6070D3F4C004EE4BC4B76C2DA7213C578FE41C0F198875669CC77C77AB44F6DC727EF1540AAEC22BF1F3E84F1C95FEAF350203010001A000300D06092A864886F70D0101050500038181008013CFFF909BB2CF91998A319F02ABD9B53AA0BE3FAA236CFA98658015E904DAAF9E81FBDBD3DF5E813FA229074FD71E75C830A7200EBA21D509E1234FFEDBE8E53AB34DE1128956EA81ABAD70D3C32512FE1E028F631266291194BEE4BE8F786AA653FF227591D7C7EF0C27B7690B1D7B667C3A4A7D33317CFACB73C9E5140F";
		System.out.println(Base64Decode.encode(Convert.stringToHexBytes(ss)));
           
    }   
    //  编码
    public static String encode(byte[] data) {   
        StringBuffer sb = new StringBuffer();   
        int len = data.length;   
        int i = 0;   
        int b1, b2, b3;   
        while (i < len) {   
            b1 = data[i++] & 0xff;   
            if (i == len) {   
                sb.append(base64EncodeChars[b1 >>> 2]);   
                sb.append(base64EncodeChars[(b1 & 0x3) << 4]);   
                sb.append("==");   
                break;   
            }   
            b2 = data[i++] & 0xff;   
            if (i == len) {   
                sb.append(base64EncodeChars[b1 >>> 2]);   
                sb.append(base64EncodeChars[((b1 & 0x03) << 4)   
                        | ((b2 & 0xf0) >>> 4)]);   
                sb.append(base64EncodeChars[(b2 & 0x0f) << 2]);   
                sb.append("=");   
                break;   
            }   
            b3 = data[i++] & 0xff;   
            sb.append(base64EncodeChars[b1 >>> 2]);   
            sb.append(base64EncodeChars[((b1 & 0x03) << 4)   
                    | ((b2 & 0xf0) >>> 4)]);   
            sb.append(base64EncodeChars[((b2 & 0x0f) << 2)   
                    | ((b3 & 0xc0) >>> 6)]);   
            sb.append(base64EncodeChars[b3 & 0x3f]);   
        }   
        return sb.toString();   
    }   
    // 解码
    public static byte[] decode(String str) throws UnsupportedEncodingException {   
        StringBuffer sb = new StringBuffer();   
        byte[] data = str.getBytes("US-ASCII");   
        int len = data.length;   
        int i = 0;   
        int b1, b2, b3, b4;   
        while (i < len) {   
              
            do {   
                b1 = base64DecodeChars[data[i++]];   
            } while (i < len && b1 == -1);   
            if (b1 == -1)   
                break;   
              
            do {   
                b2 = base64DecodeChars[data[i++]];   
            } while (i < len && b2 == -1);   
            if (b2 == -1)   
                break;   
            sb.append((char) ((b1 << 2) | ((b2 & 0x30) >>> 4)));   
              
            do {   
                b3 = data[i++];   
                if (b3 == 61)   
                    return sb.toString().getBytes("iso8859-1");   
                b3 = base64DecodeChars[b3];   
            } while (i < len && b3 == -1);   
            if (b3 == -1)   
                break;   
            sb.append((char) (((b2 & 0x0f) << 4) | ((b3 & 0x3c) >>> 2)));   
              
            do {   
                b4 = data[i++];   
                if (b4 == 61)   
                    return sb.toString().getBytes("iso8859-1");   
                b4 = base64DecodeChars[b4];   
            } while (i < len && b4 == -1);   
            if (b4 == -1)   
                break;   
            sb.append((char) (((b3 & 0x03) << 6) | b4));   
        }   
        return sb.toString().getBytes("iso8859-1");   
    }   
    
} 
 