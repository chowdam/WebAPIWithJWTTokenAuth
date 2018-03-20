using Microsoft.Owin;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

[assembly: OwinStartup(typeof(SecureAPIService.Startup))]
namespace SecureAPIService
{
    /// <summary>
    /// refer to :  https://www.developerhandbook.com/c-sharp/create-restful-api-authentication-using-web-api-jwt/
    /// </summary>
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
         
           ConfigureOAuth(app);
        }
    }
}