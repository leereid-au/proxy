/* proxy.pac  –  last updated 2025-05-01
   Implements the same proxy + bypass logic used in Set-SystemProxy.ps1
   Proxy: proxy.swg.internal:8080
*/

/* ---------- CONFIGURATION ---------- */
var PROXY = "PROXY proxy.swg.internal:8080";
var DIRECT_FALLBACK = "DIRECT";          // sent if proxy is unreachable

// Domains (wildcards allowed) that should **bypass** the proxy
var directDomains = [
  "*.dave.com","*.swg.internal", "*.vpn.azure.com",
  "ocsp.digicert.com", "ocsp.one.digicert.com", "cacerts.one.digicert.com",
  "*.endpoint.security.microsoft.com", "*.manage.microsoft.com",
  "manage.microsoft.com", "enterpriseenrollment.manage.microsoft.com",
  "*.lync.com", "*.teams.microsoft.com", "teams.microsoft.com",
  "outlook.cloud.microsoft", "outlook.office.com", "outlook.office365.com",
  "remotehelp.microsoft.com", "*.internal.govt",

  // WinHTTP bypass list
  "*.microsoft.com", "*.windows.net", "*.azure.com", "*.msftauth.net",
  "*.msauth.net", "*.msftconnecttest.com", "*.office.com", "*.live.com",
  "*.microsoftonline.com", "*.microsoftonline-p.com",
  "*.login.microsoftonline.com", "*.aadcdn.msauth.net",
  "*.aadcdn.msftauth.net", "*.blob.core.windows.net", "*.crl.microsoft.com",
  "*.ocsp.msocsp.com", "*.mscrl.microsoft.com",
  "*.sharepoint.com", "*.sfbassets.com", "*.akamaiedge.net",
  "*.akamaitechnologies.com", "*.azureedge.net", "*.aria.microsoft.com",
  "*.config.office.com", "*.graph.microsoft.com", "*.security.microsoft.com",
  "*.defender.microsoft.com", "*.intune.microsoft.com",
  "*.device.login.microsoftonline.com"
];

/* ---------- HELPER ---------- */
function isInDirectList(host) {
  // Loop once through our wildcard table
  for (var i = 0; i < directDomains.length; i++) {
    if (shExpMatch(host, directDomains[i])) {
      return true;
    }
  }
  return false;
}

/* ---------- MAIN ---------- */
function FindProxyForURL(url, host) {

  /* 1.  <local> – hosts with no dots OR RFC-1918/private addresses */
  if (isPlainHostName(host) ||
      isInNet(host, "10.0.0.0",  "255.0.0.0")   ||  // 10/8
      isInNet(host, "172.16.0.0","255.240.0.0") ||  // 172.16-31/12
      isInNet(host, "192.168.0.0","255.255.0.0")) { // 192.168/16
    return DIRECT_FALLBACK;
  }

  /* 2.  Domain-based bypass list */
  if (isInDirectList(host)) {
    return DIRECT_FALLBACK;
  }

  /* 3.  Everything else goes through the proxy */
  return PROXY + "; " + DIRECT_FALLBACK;   // try proxy first, fall back to direct
}
