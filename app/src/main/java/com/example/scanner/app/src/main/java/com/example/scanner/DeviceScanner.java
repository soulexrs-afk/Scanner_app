package com.example.scanner;

import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.provider.Settings;
import android.text.TextUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * Runs a set of independent checks for indicators of unauthorized monitoring
 * or control on this device. Every check is read-only — nothing here
 * modifies device state, disables another app, or revokes any permission.
 */
public class DeviceScanner {

    private final Context context;
    private final PackageManager pm;

    public DeviceScanner(Context context) {
        this.context = context.getApplicationContext();
        this.pm = context.getPackageManager();
    }

    public List<Finding> runFullScan() {
        List<Finding> findings = new ArrayList<>();
        findings.addAll(checkDeviceAdmins());
        findings.addAll(checkAccessibilityServices());
        findings.addAll(checkActiveVpn());
        findings.addAll(checkSuspiciousApps());
        findings.addAll(checkUnknownSourcesInstalls());
        return findings;
    }

    private List<Finding> checkDeviceAdmins() {
        List<Finding> results = new ArrayList<>();
        DevicePolicyManager dpm = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
        if (dpm == null) return results;

        List<android.content.ComponentName> activeAdmins = dpm.getActiveAdmins();
        if (activeAdmins == null || activeAdmins.isEmpty()) {
            results.add(new Finding(
                    "No active device admin apps",
                    "No app currently holds Device Admin rights.",
                    Finding.Severity.INFO,
                    null));
            return results;
        }

        for (android.content.ComponentName admin : activeAdmins) {
            String pkg = admin.getPackageName();
            String label = getAppLabel(pkg);
            boolean isOwner = dpm.isDeviceOwnerApp(pkg);
            results.add(new Finding(
                    (isOwner ? "Device Owner app: " : "Device Admin app: ") + label,
                    "Package: " + pkg + (isOwner
                            ? ". This app has full device-owner level control (can silently install/remove apps, wipe the device, and enforce policies)."
                            : ". This app can enforce lock-screen/password policy, lock the screen, and in some cases wipe the device."),
                    isOwner ? Finding.Severity.CRITICAL : Finding.Severity.WARNING,
                    "Settings > Security > Device admin apps (path varies by manufacturer) — "
                            + "review '" + label + "' and deactivate it if you don't recognize it or didn't authorize it. "
                            + "If it's Device Owner and refuses to deactivate, it may require a factory reset to remove — "
                            + "back up personal data you trust first."));
        }
        return results;
    }

    private List<Finding> checkAccessibilityServices() {
        List<Finding> results = new ArrayList<>();
        String enabledServices = Settings.Secure.getString(
                context.getContentResolver(), Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);

        if (TextUtils.isEmpty(enabledServices)) {
            results.add(new Finding(
                    "No accessibility services enabled",
                    "No app currently has accessibility service access.",
                    Finding.Severity.INFO,
                    null));
            return results;
        }

        for (String component : enabledServices.split(":")) {
            if (component.isEmpty()) continue;
            String pkg = component.contains("/") ? component.split("/")[0] : component;
            String label = getAppLabel(pkg);
            results.add(new Finding(
                    "Accessibility service enabled: " + label,
                    "Package: " + pkg + ". Accessibility services can read on-screen text/content and, "
                            + "in some cases, simulate input. Legitimate uses include screen readers and "
                            + "some password managers — but it's also the most common permission spyware abuses.",
                    Finding.Severity.WARNING,
                    "Settings > Accessibility > Installed apps — review '" + label + "' and disable it "
                            + "if you don't recognize it or don't remember granting it."));
        }
        return results;
    }

    private List<Finding> checkActiveVpn() {
        List<Finding> results = new ArrayList<>();
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) return results;

        Network[] networks = cm.getAllNetworks();
        boolean vpnFound = false;
        for (Network net : networks) {
            NetworkCapabilities caps = cm.getNetworkCapabilities(net);
            if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                vpnFound = true;
            }
        }

        if (vpnFound) {
            results.add(new Finding(
                    "Active VPN connection detected",
                    "All or some network traffic is currently being routed through a VPN. "
                            + "If you didn't set this up yourself, this could allow traffic inspection or filtering "
                            + "by whoever controls the VPN endpoint.",
                    Finding.Severity.WARNING,
                    "Settings > Network > VPN — check which VPN profile is active and who configured it. "
                            + "Remove it if you don't recognize it. If it can't be removed and the device shows "
                            + "as 'managed,' see the Device Admin finding above."));
        } else {
            results.add(new Finding(
                    "No active VPN detected",
                    "No VPN transport is currently active on this device.",
                    Finding.Severity.INFO,
                    null));
        }
        return results;
    }

    private List<Finding> checkSuspiciousApps() {
        List<Finding> results = new ArrayList<>();
        List<PackageInfo> packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS);

        String[] sensitivePerms = {
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_SMS",
                "android.permission.READ_CALL_LOG",
                "android.permission.SYSTEM_ALERT_WINDOW"
        };

        for (PackageInfo pkgInfo : packages) {
            if (pkgInfo.requestedPermissions == null) continue;
            ApplicationInfo appInfo = pkgInfo.applicationInfo;
            boolean isSystemApp = (appInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if (isSystemApp) continue;

            int sensitiveCount = 0;
            for (String perm : pkgInfo.requestedPermissions) {
                for (String sensitive : sensitivePerms) {
                    if (sensitive.equals(perm)) sensitiveCount++;
                }
            }

            boolean hasLauncherIcon = pm.getLaunchIntentForPackage(pkgInfo.packageName) != null;

            if (sensitiveCount >= 3 && !hasLauncherIcon) {
                results.add(new Finding(
                        "Hidden app with broad sensitive permissions: " + getAppLabel(pkgInfo.packageName),
                        "Package: " + pkgInfo.packageName + ". This app has no icon in your app drawer "
                                + "and requests " + sensitiveCount + " sensitive permissions (camera/mic/location/SMS/"
                                + "call log/overlay). This combination is common in hidden monitoring apps, "
                                + "though some legitimate system utilities also match this pattern.",
                        Finding.Severity.CRITICAL,
                        "Settings > Apps > See all apps > (enable 'show system apps' if needed) > find '"
                                + getAppLabel(pkgInfo.packageName) + "' > review permissions and uninstall if unrecognized."));
            }
        }
        return results;
    }

    private List<Finding> checkUnknownSourcesInstalls() {
        List<Finding> results = new ArrayList<>();
        List<PackageInfo> packages = pm.getInstalledPackages(0);

        for (PackageInfo pkgInfo : packages) {
            ApplicationInfo appInfo = pkgInfo.applicationInfo;
            if ((appInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0) continue;

            String installerPkg = getInstallerPackageNameCompat(pkgInfo.packageName);
            boolean fromPlayStore = "com.android.vending".equals(installerPkg);
            boolean hasLauncherIcon = pm.getLaunchIntentForPackage(pkgInfo.packageName) != null;

            if (!fromPlayStore && !hasLauncherIcon) {
                results.add(new Finding(
                        "Sideloaded hidden app: " + getAppLabel(pkgInfo.packageName),
                        "Package: " + pkgInfo.packageName + ". Installed from outside the Play Store "
                                + "(installer: " + (installerPkg == null ? "unknown/direct APK install" : installerPkg)
                                + ") and has no app drawer icon.",
                        Finding.Severity.WARNING,
                        "Settings > Apps > See all apps > find '" + getAppLabel(pkgInfo.packageName)
                                + "' > if unrecognized, uninstall it."));
            }
        }
        return results;
    }

    private String getInstallerPackageNameCompat(String packageName) {
        try {
            return pm.getInstallerPackageName(packageName);
        } catch (Exception e) {
            return null;
        }
    }

    private String getAppLabel(String packageName) {
        try {
            ApplicationInfo appInfo = pm.getApplicationInfo(packageName, 0);
            return String.valueOf(pm.getApplicationLabel(appInfo));
        } catch (PackageManager.NameNotFoundException e) {
            return packageName;
        }
    }
}
