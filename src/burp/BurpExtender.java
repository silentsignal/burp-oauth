package burp;

import java.util.List;

public class BurpExtender implements IBurpExtender, IHttpListener
{
	protected IExtensionHelpers helpers;
	protected String cookie_value = null;
	public static final String COOKIE_NAME = ".ASPXFORMSAUTH";

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	{
		helpers = callbacks.getHelpers();
		callbacks.setExtensionName("AspxFormAuth");
		callbacks.registerHttpListener(this);
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
	{
		if (messageIsRequest)
		{
			synchronized (this) {
				if (cookie_value == null) return;
			}
			byte[] request = messageInfo.getRequest();
			IRequestInfo ri = helpers.analyzeRequest(request);
			List<IParameter> parameters = ri.getParameters();
			for (IParameter parameter : parameters) {
				if (parameter.getType() == IParameter.PARAM_COOKIE &&
						parameter.getName().equals(COOKIE_NAME)) {
					synchronized (this) {
						messageInfo.setRequest(helpers.updateParameter(request,
									helpers.buildParameter(COOKIE_NAME, cookie_value,
										IParameter.PARAM_COOKIE)));
					}
				}
			}
		}
		else
		{
			IResponseInfo ri = helpers.analyzeResponse(messageInfo.getResponse());
			List<ICookie> cookies = ri.getCookies();
			for (ICookie cookie : cookies) {
				if (cookie.getName().equals(COOKIE_NAME)) {
					synchronized (this) {
						cookie_value = cookie.getValue();
					}
				}
			}
		}
	}
}
