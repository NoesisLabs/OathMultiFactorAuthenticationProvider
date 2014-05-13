using Microsoft.IdentityServer.Web.Authentication.External;
using OtpSharp;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.Linq;
using System.Net;
using System.Runtime.Caching;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace NoesisLabs.OathMultiFactorAuthenticationProvider
{
	public class AuthenticationAdapter : IAuthenticationAdapter
	{
		private const string TOKEN_FORM_FIELD_NAME = "Token";

		private static Dictionary<string, DateTime> usedKeys = new Dictionary<string, DateTime>();

		private ObjectCache cache = MemoryCache.Default;

		private string upn;

		public IAuthenticationAdapterMetadata Metadata
		{
			get { return new AuthenticationAdapterMetadata(); }
		}

		public IAdapterPresentation BeginAuthentication(Claim identityClaim, HttpListenerRequest request, IAuthenticationContext authContext)
		{
			this.upn = identityClaim.Value;

			return new AdapterPresentation();
		}

		public bool IsAvailableForUser(Claim identityClaim, IAuthenticationContext authContext)
		{
			string upn = identityClaim.Value;
			DirectoryEntry entry = new DirectoryEntry();
			DirectorySearcher mySearcher = new DirectorySearcher(entry, "(&(objectClass=user)(objectCategory=person)(userPrincipalName=" + upn + "))");
			SearchResult result = mySearcher.FindOne();
			if (result.Properties["info"].Count == 0) return false;
			string token = (string)result.Properties["info"][0];
			return !String.IsNullOrEmpty(token);
		}

		public void OnAuthenticationPipelineLoad(IAuthenticationMethodConfigData configData)
		{
			//this is where AD FS passes us the config data, if such data was supplied at registration of the adapter
		}

		public void OnAuthenticationPipelineUnload()
		{

		}

		public IAdapterPresentation OnError(HttpListenerRequest request, ExternalAuthenticationException ex)
		{
			//return new instance of IAdapterPresentationForm derived class
			return new AdapterPresentation();
		}

		public IAdapterPresentation TryEndAuthentication(IAuthenticationContext authContext, IProofData proofData, HttpListenerRequest request, out Claim[] outgoingClaims)
		{
			outgoingClaims = new Claim[0];
			if (ValidateProofData(proofData, authContext))
			{
				//authn complete - return authn method
				outgoingClaims = new[] 
					 {
					 // Return the required authentication method claim, indicating the particular authentication method used.
					 new Claim( "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", 
					 "http://schemas.microsoft.com/ws/2012/12/authmethod/otp" )
					 };

				return null;
			}
			else
			{
				//authn not complete - return new instance of IAdapterPresentationForm derived class
				return new AdapterPresentation(Resources.TokenValidationFailedMessage);
			}
		}

		private bool ValidateProofData(IProofData proofData, IAuthenticationContext authContext)
		{
			if (proofData == null || proofData.Properties == null || !proofData.Properties.ContainsKey(TOKEN_FORM_FIELD_NAME))
			{
				throw new ExternalAuthenticationException(Resources.TokenNotFoundMessage, authContext);
			}

			string key = GetEncodedSecretKey(this.upn);

			Totp otp = new Totp(Base32.Base32Encoder.Decode(key));

			long step;

			bool isVerified = otp.VerifyTotp((string)proofData.Properties[TOKEN_FORM_FIELD_NAME], out step, new VerificationWindow(previous: 1, future: 1));

			if (!isVerified) { return false; }

			string cacheKey = this.upn + "_" + step.ToString();

			if (this.cache.Get(cacheKey) != null)
			{
				throw new ExternalAuthenticationException(String.Format(Resources.TokenAlreadyUsedMessage, "[" + this.upn + "] [" + step.ToString() + "]"), authContext);
			}
			else
			{
				var policy = new CacheItemPolicy() { AbsoluteExpiration = DateTime.Now.Add(new TimeSpan(0, 1, 0)) };
				this.cache.AddOrGetExisting(new CacheItem(cacheKey, "used"), policy);
			}

			return true;
		}

		private static string GetEncodedSecretKey(string upn)
		{
			DirectoryEntry entry = new DirectoryEntry();
			DirectorySearcher mySearcher = new DirectorySearcher(entry, "(&(objectClass=user)(objectCategory=person)(userPrincipalName=" + upn + "))");
			SearchResult result = mySearcher.FindOne();
			string deviceId = (string)result.Properties["info"][0];
			return deviceId;
		}
	}
}
