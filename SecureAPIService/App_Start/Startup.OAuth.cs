using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.Jwt;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Thinktecture.IdentityModel.Tokens;
using SecureAPIService.Handlers;

namespace SecureAPIService
{
    public partial class Startup
    {
        public void ConfigureOAuth(IAppBuilder app)
        {
            try
            {
                var issuer = ConfigurationManager.AppSettings["issuer"];
                var secret = TextEncodings.Base64Url.Decode(ConfigurationManager.AppSettings["secret"]);
                var audience = ConfigurationManager.AppSettings["audience"];
                //validates token received
                app.UseJwtBearerAuthentication(new JwtBearerAuthenticationOptions
                {                    
                    AuthenticationMode = AuthenticationMode.Active,
                    AllowedAudiences = new[] { audience },                    
                    IssuerSecurityKeyProviders = new Microsoft.Owin.Security.Jwt.IIssuerSecurityKeyProvider[] { new Microsoft.Owin.Security.Jwt.SymmetricKeyIssuerSecurityKeyProvider(issuer, secret) }


                });

                //generates token
                app.UseOAuthAuthorizationServer(new OAuthAuthorizationServerOptions
                {
                    //#if DEBUG
                    //    AllowInsecureHttp = true,
                    //#endif    
                    AllowInsecureHttp = true,
                    TokenEndpointPath = new PathString("/oauth2/token"),
                    AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(20),
                    Provider = new CustomOAuthProvider(),
                    AccessTokenFormat = new CustomJwtFormat(issuer)
                });
            }
            catch(Exception ex)
            {
                throw ex;
            }

        }
    }
}