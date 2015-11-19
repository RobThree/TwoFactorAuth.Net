using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using TwoFactorAuth.Net;
using TwoFactorAuth.Net.Demo.Models;

namespace TwoFactorAuth.Net.Demo.Controllers
{
    public class HomeController : Controller
    {
        private TwoFactorAuth tfa = new TwoFactorAuth("MyCompany");

        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Step1()
        {
            if (string.IsNullOrEmpty((string)Session["secret"]))
                Session.Add("secret", tfa.CreateSecret());

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