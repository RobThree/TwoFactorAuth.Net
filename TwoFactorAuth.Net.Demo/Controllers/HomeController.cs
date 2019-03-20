using System.Web.Mvc;
using TwoFactorAuthNet.Demo.Models;

namespace TwoFactorAuthNet.Demo.Controllers
{
    public class HomeController : Controller
    {
        private TwoFactorAuth tfa = new TwoFactorAuth("MyCompany", qrcodeprovider: new QRCoder.QRCoderQRCodeProvider(backgroundColor: System.Drawing.Color.Red));

        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Step1()
        {
            if (string.IsNullOrEmpty((string)Session["secret"]))
                // Though the default is an 80 bits secret (for backwards compatibility reasons) we 
                // recommend creating 160+ bits secrets (see RFC 4226 - Algorithm Requirements)
                Session.Add("secret", tfa.CreateSecret(160));

            return View(tfa);
        }

        [HttpGet]
        public ActionResult Step2()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Step2(string code)
        {
            if (string.IsNullOrEmpty((string)Session["secret"]))
                return View(new VerificationResult { Success = false, Message = "Your session must have expired!? Did you visit step 1?" });

            if (!string.IsNullOrEmpty(code))
            {
                var result = new VerificationResult { Success = tfa.VerifyCode((string)Session["secret"], code) };
                if (result.Success)
                    result.Message = "Yay! Code verified!";
                else
                    result.Message = "Uh oh! The code did not verify :(";

                return View(result);
            }
            else
            {
                return View(new VerificationResult { Success = false, Message = "You need to enter a code..." });
            }
        }


        public ActionResult Step3()
        {
            // Store secret with user
            // ...
            // DONE! YAY!
            return View();
        }
    }
}