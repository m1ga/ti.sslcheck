package ti.sslcheck;

import android.net.http.SslCertificate;

import org.appcelerator.kroll.KrollDict;
import org.appcelerator.kroll.common.Log;

import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import ti.modules.titanium.network.HTTPClientProxy;

public class PinningTrustManager implements X509TrustManager {

    private final HTTPClientProxy proxy;
    private final X509TrustManager standardTrustManager;

    protected PinningTrustManager(HTTPClientProxy proxy, String supportedHosts, int trustChainIndex)
            throws Exception {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init((KeyStore) null);
        TrustManager[] trustmanagers = factory.getTrustManagers();
        if (trustmanagers.length == 0) {
            throw new NoSuchAlgorithmException("No trust-manager found");
        }
        this.standardTrustManager = (X509TrustManager) trustmanagers[0];
        this.proxy = proxy;
    }

    public static String byte2HexFormatted(byte[] arr) {
        StringBuilder str = new StringBuilder(arr.length * 2);
        for (int i = 0; i < arr.length; i++) {
            String h = Integer.toHexString(arr[i]);
            int l = h.length();
            if (l == 1) h = "0" + h;
            if (l > 2) h = h.substring(l - 2, l);
            str.append(h.toUpperCase());
            if (i < (arr.length - 1)) str.append(':');
        }
        return str.toString();
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        this.standardTrustManager.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (this.proxy == null || this.proxy.getValidatesSecureCertificate()) {
            this.standardTrustManager.checkServerTrusted(chain, authType);
        }

        SslCertificate sslCertificate = new SslCertificate(chain[0]);

        MessageDigest md = null;
        byte[] publicKey = new byte[0];
        try {
            md = MessageDigest.getInstance("SHA1");
            publicKey = md.digest(chain[0].getEncoded());
        } catch (NoSuchAlgorithmException e) {
            //
        }
        KrollDict kd= new KrollDict();
        kd.put("fingerprint", byte2HexFormatted(publicKey));
        kd.put("issuedByCName", sslCertificate.getIssuedBy().getCName());
        kd.put("issuedByDName", sslCertificate.getIssuedBy().getDName());
        kd.put("issuedByOName", sslCertificate.getIssuedBy().getOName());
        kd.put("issuedByUName", sslCertificate.getIssuedBy().getUName());

        kd.put("issuedToCName", sslCertificate.getIssuedTo().getCName());
        kd.put("issuedToDName", sslCertificate.getIssuedTo().getDName());
        kd.put("issuedToOName", sslCertificate.getIssuedTo().getOName());
        kd.put("issuedToUName", sslCertificate.getIssuedTo().getUName());
        kd.put("issuedToUName", sslCertificate.getIssuedTo().getUName());

        kd.put("validNotAfter", sslCertificate.getValidNotAfterDate());
        kd.put("validNotBefore", sslCertificate.getValidNotBeforeDate());

        proxy.fireEvent("sslCheck", kd);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return this.standardTrustManager.getAcceptedIssuers();
    }
}
