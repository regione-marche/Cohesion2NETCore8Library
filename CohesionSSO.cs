/*
 
 La classe CohesionSSO fornisce tutti i metodi necessari per poter integrare l'autenticazione Cohesion in siti .NET Core.
 
 Il token XML di autenticazione sarà memorizzato nella variabile di sessione "token" come stringa.
 L'XML con i dati di sessione sarà memorizzato nella variabile di sessione "auth" come stringa.
 
 Esempio impostazione chiavi nell'appsettings.json per utilizzare il login federato:

 "CohesionSettings": {
    "SSOCheckURL": "https://cohesion2.regione.marche.it/SPManager/WAYF.aspx",
    "SSOWebCheckSessionURL": "https://cohesion2.regione.marche.it/SPManager/webCheckSessionSSO.aspx",
    "SSOAdditionalData": "AuthRestriction=0,1,2,3;https://example.it/Home", <!-- Tipi di autenticazione ammessi (0 = autenticazione con utente e password; 1 = autenticazione con utente, password e PIN; 2 = autenticazione Smart Card; 3 = autenticazione di dominio, valida solo per utenti interni alla rete regionale); url di redirect dopo il logout (se non specificato si viene reindirizzati alla pagina iniziale) -->
    "SuccessURL": "https://example.it/Home/AreaRiservata", <!-- Url di redirect in caso di autenticazione avvenuta correttamente -->
    "ErrorURL": "https://example.it/Home/Error", <!-- Url di redirect in caso di errore di autenticazione -->
    "IdSito": "ID-SITO"
  }

 Il nome delle chiavi impostato nell'appsettings.json non è significativo in quanto la classe contiene un unico costruttore a cui vanno passati direttamente i valori.
 Viene utilizzato un modello di programmazione asincrona, per cui i metodi vanno chiamati tramite l'utilizzo dei costrutti async/await.

 Esempio login (MVC in un controller AccountController):

 public async Task Login()
 {
     var cohesionSSO = new CohesionSSO(httpContext, _cohesionOptions.SSOCheckURL, _cohesionOptions.SSOWebCheckSessionURL, _cohesionOptions.SuccessURL, _cohesionOptions.ErrorURL, _cohesionOptions.SSOAdditionalData, _cohesionOptions.IdSito);
     await cohesionSSO.ValidateFE();
 }

 Esempio logout (MVC in un controller AccountController):

 public async Task Logout()
 {
     var cohesionSSO = new CohesionSSO(httpContext, _cohesionOptions.SSOCheckURL, _cohesionOptions.SSOWebCheckSessionURL, _cohesionOptions.SuccessURL, _cohesionOptions.ErrorURL, _cohesionOptions.SSOAdditionalData, _cohesionOptions.IdSito);
     await cohesionSSO.LogoutFE();
 }

*/

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http.Extensions;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Web;
using System.Xml;

namespace ApplicationName.Cohesion.Authentication
{
    public class CohesionSSO
    {
        private readonly HttpContext _httpContext;
        private readonly string _ssoCheckUrl;
        private readonly string _webCheckSessionSSOUrl;
        private readonly string _successUrl;
        private readonly string _errorUrl;
        private readonly string _additionalData;
        private readonly string _idSito;

        public CohesionSSO(HttpContext httpContext, string ssoCheckUrl, string webCheckSessionSSOUrl, string successUrl, string errorUrl, string additionalData, string idSito)
        {
            _httpContext = httpContext;
            _ssoCheckUrl = ssoCheckUrl;
            _webCheckSessionSSOUrl = webCheckSessionSSOUrl;
            _successUrl = successUrl;
            _errorUrl = errorUrl;
            _additionalData = additionalData;
            _idSito = idSito;
        }

        public async Task ValidateFE()
        {
            var request = _httpContext.Request;
            var response = _httpContext.Response;
            var session = _httpContext.Session;

            if (string.IsNullOrEmpty(_ssoCheckUrl) || string.IsNullOrEmpty(_webCheckSessionSSOUrl))
            {
                response.Clear();
                await response.Body.WriteAsync(Encoding.UTF8.GetBytes("I valori di SSOCheckUrl o webCheckSessionSSOUrl non sono stati impostati."));
                return;
            }

            string? authParam = string.Empty;

            if (request.HasFormContentType)
            {
                authParam = request.Form["auth"];
            }

            if (string.IsNullOrEmpty(authParam))
            {
                string urlValidate = request.GetEncodedUrl();
                string auth = "<dsAuth xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"http://tempuri.org/Auth.xsd\"><auth><user /><id_sa /><id_sito>" + _idSito + "</id_sito><esito_auth_sa /><id_sessione_sa /><id_sessione_aspnet_sa /><url_validate>" + urlValidate.Replace("&", "&amp;") + "</url_validate><url_richiesta>" + _successUrl.Replace("&", "&amp;") + "</url_richiesta><esito_auth_sso /><id_sessione_sso /><id_sessione_aspnet_sso /><stilesheet>" + _additionalData + "</stilesheet></auth></dsAuth>";
                auth = Convert.ToBase64String(Encoding.ASCII.GetBytes(auth));
                response.Redirect(_ssoCheckUrl + "?auth=" + HttpUtility.UrlEncode(auth));
            }

            else
            {
                string auth = Encoding.ASCII.GetString(Convert.FromBase64String(authParam));
                XmlDocument authXml = new XmlDocument();
                authXml.LoadXml(auth);
                string? urlRichiesta = authXml.GetElementsByTagName("url_richiesta")[0]?.InnerText;

                if (string.IsNullOrEmpty(urlRichiesta))
                {
                    response.Clear();
                    await response.Body.WriteAsync(Encoding.UTF8.GetBytes("Errore durante l'autenticazione: URL richiesta non valorizzato."));
                    return;
                }

                string? esitoAuthSSO = authXml.GetElementsByTagName("esito_auth_sso")[0]?.InnerText;

                if (!string.IsNullOrEmpty(esitoAuthSSO) && esitoAuthSSO == "OK")
                {
                    string? idSessioneSSO = authXml.GetElementsByTagName("id_sessione_sso")[0]?.InnerText;
                    string? idSessioneSSONET = authXml.GetElementsByTagName("id_sessione_aspnet_sso")[0]?.InnerText;
                    string token = await WebCheckSessionSSO(_webCheckSessionSSOUrl, "GetCredential", idSessioneSSO ?? string.Empty, idSessioneSSONET ?? string.Empty);

                    if (!string.IsNullOrEmpty(token) && !token.Contains("<AUTH>NO</AUTH>"))
                    {
                        token = "<?xml version=\"1.0\"?>" + token;
                        int loginStart = token.IndexOf("<login>") + 7;
                        int loginStop = token.IndexOf("</login>");
                        string login = token.Substring(loginStart, loginStop - loginStart);

                        var claims = new List<Claim>()
                        {
                            new Claim(ClaimTypes.NameIdentifier, login)
                        };

                        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                        var principal = new ClaimsPrincipal(identity);

                        await _httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, new AuthenticationProperties()
                        {
                            IsPersistent = false
                        });

                        session.SetString("token", token);
                        session.SetString("auth", auth);

                        response.Redirect(urlRichiesta);
                    }

                    else
                    {
                        response.Clear();
                        await response.Body.WriteAsync(Encoding.UTF8.GetBytes("Errore durante l'autenticazione.\nInfo token:\n\n<pre>\n" + token + "\n</pre>"));
                    }
                }

                else
                {
                    if (!string.IsNullOrEmpty(_errorUrl))
                    {
                        response.Redirect(_errorUrl);
                    }

                    else
                    {
                        response.Clear();
                        await response.Body.WriteAsync(Encoding.UTF8.GetBytes("Errore durante l'autenticazione.\nInfo auth:\n\n<pre>\n" + auth + "\n</pre>"));
                    }
                }
            }
        }

        public async Task LogoutFE()
        {
            var request = _httpContext.Request;
            var response = _httpContext.Response;
            var session = _httpContext.Session;
            string? auth = session.GetString("auth");
            string? logoutUrl = string.Empty;

            if (!string.IsNullOrEmpty(auth))
            {
                XmlDocument authXml = new XmlDocument();
                authXml.LoadXml(auth);
                string? idSessioneSSO = authXml.GetElementsByTagName("id_sessione_sso")[0]?.InnerText;
                string? idSessioneSSONET = authXml.GetElementsByTagName("id_sessione_aspnet_sso")[0]?.InnerText;
                logoutUrl = authXml.GetElementsByTagName("url_logout")[0]?.InnerText;
                await WebCheckSessionSSO(_webCheckSessionSSOUrl, "LogoutSito", idSessioneSSO ?? string.Empty, idSessioneSSONET ?? string.Empty);
            }

            await _httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            session.Clear();
            _httpContext.Connection.ClientCertificate = null;

            if (string.IsNullOrEmpty(logoutUrl))
            {
                logoutUrl = request.Scheme + "://" + request.Host.Host + (request.Host.Port == 80 ? string.Empty : ":" + request.Host.Port);
            }

            response.Redirect(logoutUrl);
        }

        private async Task<string> WebCheckSessionSSO(string url, string operation, string idSessioneSSO, string idSessioneSSONET)
        {
            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                string token = string.Empty;

                var parameters = new Dictionary<string, string>
                {
                    { "Operation", operation },
                    { "IdSessioneSSO", idSessioneSSO },
                    { "IdSessioneASPNET", idSessioneSSONET }
                };

                using (var client = new HttpClient())
                using (var request = new HttpRequestMessage(HttpMethod.Post, url))
                {
                    request.Content = new FormUrlEncodedContent(parameters);
                    var response = await client.SendAsync(request);

                    if (response.IsSuccessStatusCode)
                    {
                        token = await response.Content.ReadAsStringAsync();
                    }
                }

                return token;
            }

            catch (Exception ex)
            {
                return "<AUTH>NO</AUTH><ERROR>" + ex.Message + "\n" + ex.InnerException + "</ERROR>";
            }
        }
    }
}