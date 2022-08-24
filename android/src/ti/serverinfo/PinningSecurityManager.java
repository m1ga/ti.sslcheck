package ti.sslcheck;

import android.net.Uri;

import org.appcelerator.kroll.KrollProxy;
import org.appcelerator.kroll.annotations.Kroll;
import org.appcelerator.kroll.common.Log;

import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import ti.modules.titanium.network.HTTPClientProxy;
import ti.modules.titanium.network.SecurityManagerProtocol;

@Kroll.proxy
public class PinningSecurityManager extends KrollProxy implements SecurityManagerProtocol {
    @Override
    public X509KeyManager[] getKeyManagers(HTTPClientProxy proxy) {
        List<X509KeyManager> managers = new ArrayList<X509KeyManager>();
        return managers.toArray(new X509KeyManager[managers.size()]);
    }

    @Override
    public boolean willHandleURL(Uri uri) {
        return true;
    }

    @Override
    public X509TrustManager[] getTrustManagers(HTTPClientProxy proxy) {
        try {
            PinningTrustManager tm = new PinningTrustManager(proxy, proxy.getLocation(), 0, this);
            return new X509TrustManager[]{tm};
        } catch (Exception e) {
            Log.e(SSLCheckModule.TAG, "Unable to create PinningTrustManager. Returning null.", e);
            return null;
        }
    }

    protected void addProfile(String host, int index) throws Exception {
    }

    protected void addKeyStore(KeyStore keyStore, String password) {
    }

    public int getTrustChainIndex() {
        return 0;
    }

    @Override
    public String getApiName() {
        return "ti.sslcheck.PinningSecurityManager";
    }
}
