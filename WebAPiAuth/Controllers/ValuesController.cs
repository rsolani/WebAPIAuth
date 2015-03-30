using System.Web.Http;

namespace WebAPiAuth.Controllers
{
    public class ValuesController : ApiController
    {
        //
        // GET: /Values/
        //[System.Web.Http.Authorize(Roles = "User")]
        [Authorize()]
        public string Get()
        {
            return User.Identity.Name;
        }

    }
}
