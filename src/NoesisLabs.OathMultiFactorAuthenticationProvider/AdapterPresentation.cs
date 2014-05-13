using Microsoft.IdentityServer.Web.Authentication.External;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NoesisLabs.OathMultiFactorAuthenticationProvider
{
	public class AdapterPresentation : IAdapterPresentationForm
	{
		private string message = String.Empty;

		public AdapterPresentation() { }

		public AdapterPresentation(string message)
		{
			this.message = message;
		}

		/// Returns the HTML Form fragment that contains the adapter user interface. This data will be included in the web page that is presented
		/// to the cient.
		public string GetFormHtml(int lcid)
		{
			//string htmlTemplate = Resource.Form_en_us;

			string html = "";

			if (!String.IsNullOrEmpty(this.message))
			{
				html += "<p><b>" + message + "</b></p>";
			}

			html += Resources.html;

			return html;
		}

		/// Return any external resources, ie references to libraries etc., that should be included in 
		/// the HEAD section of the presentation form html. 
		public string GetFormPreRenderHtml(int lcid)
		{
			return null;
		}

		//returns the title string for the web page which presents the HTML form content to the end user
		public string GetPageTitle(int lcid)
		{
			return "OATH Multi Factor Authentication";
		}
	}
}
