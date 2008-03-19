using System;
using System.Collections.Generic;
using System.Text;
using System.Web;

namespace ClinPhone.BLProtector
{
    public class BlacklistModule : IHttpModule
    {
        public string ModuleName
        {
            get { return "BLProtectorModule"; }
        }

        #region IHttpModule Members

        public void Dispose()
        { }

        public void Init(HttpApplication context)
        {
            context.BeginRequest += new EventHandler(context_BeginRequest);
        }

        void context_BeginRequest(object source, EventArgs e)
        {
            HttpApplication app = (HttpApplication)source;

            if (app.Request.Url.AbsolutePath == BlacklistConfig.GetConfig().BlockedUrl) return;
            if (BlacklistResponse.HasCookie()) return;

            BlacklistResponse response = null;
            if (BlacklistConfig.GetConfig().TestMode)
                response = BlacklistResponse.Test();
            else
                response = new BlacklistResponse(app.Request.ServerVariables[BlacklistConfig.GetConfig().IPHeader]);

            if (response.VisitorType == VisitorTypes.Unknown) return;
			if (BlacklistConfig.GetConfig().IgnoreSearchEngines && response.VisitorType == VisitorTypes.SearchEngine) return;
            if (response.ThreatScore <= BlacklistConfig.GetConfig().Threshold) return;

            app.Response.Redirect(BlacklistConfig.GetConfig().BlockedUrl + response.ToQueryString() + "&l=" + app.Request.Url.ToString());
        }

        #endregion
    }
}
