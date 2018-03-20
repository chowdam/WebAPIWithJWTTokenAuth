using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace SecureAPIService.Handlers
{
    public class CustomOAuthProvider : OAuthAuthorizationServerProvider
    {
        /// <summary>
        /// This emthod validates client id 
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            //here you can validated different clients checking client id is valid to provide access or not

            context.Validated();
            return Task.FromResult<object>(null);
        }

        /// <summary>
        /// This method validated resource owner credentials
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            var allowedOrigin = context.OwinContext.Get<string>("as:clientAllowedOrigin");
            if (allowedOrigin == null) allowedOrigin = "*";

            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { allowedOrigin });

            //here validate username & pwd from database
            
            if (context.UserName != context.Password)            
            {
                //context.SetError("Invalid credentials");
                context.SetError("invalid_grant", "The user name or password is incorrect");
                context.Rejected();
                return Task.FromResult<object>(null);
            }           

            var ticket = new AuthenticationTicket(SetClaimsIdentity(context, context.UserName), new AuthenticationProperties());
            context.Validated(ticket);
            return Task.FromResult<object>(null);
        }

       

        //private static ClaimsIdentity SetClaimsIdentity(OAuthGrantResourceOwnerCredentialsContext context, IdentityUser user)
        private static ClaimsIdentity SetClaimsIdentity(OAuthGrantResourceOwnerCredentialsContext context, string user)
        {
            var identity = new ClaimsIdentity("JWT");
           
            identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));           
            identity.AddClaim(new Claim(ClaimTypes.Role, "user"));
            return identity;
        }
    }
}