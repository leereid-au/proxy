function FindProxyForURL(url, host) {
    var proxy = "PROXY proxy.swg.internal:8080";
 
    // Bypass proxy for plain hostnames
    if (isPlainHostName(host)) {
        return "DIRECT";
    }
 
    // Bypass for private IP ranges
    if (
        isInNet(host, "10.0.0.0", "255.0.0.0") ||
        isInNet(host, "172.16.0.0", "255.240.0.0") ||
        isInNet(host, "192.168.0.0", "255.255.0.0")
    ) {
        return "DIRECT";
    }
 
    // Domain-based bypass
    if (
        shExpMatch(host, "*.dave.com") ||
        shExpMatch(host, "*.swg.internal") ||
        shExpMatch(host, "*.vpn.azure.com") ||
        host === "ocsp.digicert.com" ||
        host === "ocsp.one.digicert.com" ||
        host === "cacerts.one.digicert.com" ||
        shExpMatch(host, "*.endpoint.security.microsoft.com") ||
        shExpMatch(host, "*.manage.microsoft.com") ||
        host === "manage.microsoft.com" ||
        host === "enterpriseenrollment.manage.microsoft.com" ||
        shExpMatch(host, "*.lync.com") ||
        shExpMatch(host, "*.teams.microsoft.com") ||
        host === "teams.microsoft.com" ||
        host === "outlook.cloud.microsoft" ||
        host === "outlook.office.com" ||
        host === "outlook.office365.com" ||
        host === "remotehelp.microsoft.com" ||
        shExpMatch(host, "*.internal.govt") ||
 
        shExpMatch(host, "*.microsoft.com") ||
        shExpMatch(host, "*.microsoftazuread-sso.com") ||
        shExpMatch(host, "*.windows.net") ||
        shExpMatch(host, "*.azure.com") ||
        shExpMatch(host, "*.msftauth.net") ||
        shExpMatch(host, "*.msauth.net") ||
        shExpMatch(host, "*.msftconnecttest.com") ||
        shExpMatch(host, "*.office.com") ||
        shExpMatch(host, "*.live.com") ||
        shExpMatch(host, "*.microsoftonline.com") ||
        shExpMatch(host, "*.microsoftonline-p.com") ||
        shExpMatch(host, "*.login.microsoftonline.com") ||
        shExpMatch(host, "*.aadcdn.msauth.net") ||
        shExpMatch(host, "*.aadcdn.msftauth.net") ||
        shExpMatch(host, "*.blob.core.windows.net") ||
        shExpMatch(host, "*.crl.microsoft.com") ||
        shExpMatch(host, "*.ocsp.msocsp.com") ||
        shExpMatch(host, "*.mscrl.microsoft.com") ||
        shExpMatch(host, "*.sharepoint.com") ||
        shExpMatch(host, "*.sfbassets.com") ||
        shExpMatch(host, "*.akamaiedge.net") ||
        shExpMatch(host, "*.akamaitechnologies.com") ||
        shExpMatch(host, "*.azureedge.net") ||
        shExpMatch(host, "*.aria.microsoft.com") ||
        shExpMatch(host, "*.config.office.com") ||
        shExpMatch(host, "*.graph.microsoft.com") ||
        shExpMatch(host, "*.security.microsoft.com") ||
        shExpMatch(host, "*.defender.microsoft.com") ||
        shExpMatch(host, "*.intune.microsoft.com") ||
        shExpMatch(host, "*.device.login.microsoftonline.com")
    ) {
        return "DIRECT";
    }
 
    // All other traffic goes through proxy
    return proxy;
}
