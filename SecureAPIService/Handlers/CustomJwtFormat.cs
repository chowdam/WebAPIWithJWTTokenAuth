using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace SecureAPIService.Handlers
{
    using System;
    using System.Configuration;
    using System.IdentityModel.Tokens;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.DataHandler.Encoder;
    using Thinktecture.IdentityModel.Tokens;
    using System.IdentityModel.Tokens.Jwt;
    using System.Security.Cryptography;
    using System.Reflection;
    using System.Xml;
    using System.IO;

    public class CustomJwtFormat : ISecureDataFormat<AuthenticationTicket>
    {

        private static readonly byte[] _secret = TextEncodings.Base64Url.Decode(ConfigurationManager.AppSettings["secret"]);
        private readonly string _issuer;

        public CustomJwtFormat(string issuer)
        {
            _issuer = issuer;
        }

        public string SignatureAlgorithm
        {
            get { return "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"; }
        }

        public string DigestAlgorithm
        {
            get { return "http://www.w3.org/2001/04/xmlenc#sha256"; }
        }
        public string Protect(AuthenticationTicket data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

           
            var issued = data.Properties.IssuedUtc;
            var expires = data.Properties.ExpiresUtc;
            var audience = ConfigurationManager.AppSettings["audience"];
            var securedKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(_secret);
            var signingCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(securedKey, SignatureAlgorithm, DigestAlgorithm);

            string tokenGenerated = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(_issuer, audience, data.Identity.Claims, issued.Value.UtcDateTime, expires.Value.UtcDateTime, signingCredentials));
            return tokenGenerated; 
        }

        public AuthenticationTicket Unprotect(string protectedText)
        {
            throw new NotImplementedException();
        }
    }

   

   
}