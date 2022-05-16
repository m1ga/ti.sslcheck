package ti.sslcheck;

import org.appcelerator.kroll.KrollModule;
import org.appcelerator.kroll.annotations.Kroll;
import org.appcelerator.titanium.TiApplication;

@Kroll.module(name = "SSLCheck", id = "ti.sslcheck")
public class SSLCheckModule extends KrollModule {
    // Standard Debugging variables
    protected static final String TAG = "SSLCheckModule";

    public SSLCheckModule() {
        super();
    }

    @Kroll.onAppCreate
    public static void onAppCreate(TiApplication app) {
    }

    @Kroll.method
    public PinningSecurityManager createSecurityManager(Object[] args) throws Exception {
        PinningSecurityManager manager = new PinningSecurityManager();
        return manager;
    }

    @Override
    public String getApiName() {
        return "ti.sslcheck";
    }
}
