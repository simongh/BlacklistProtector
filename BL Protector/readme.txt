Installation

Blacklist Protector is very easy to install. You'll need an account at www.projecthoneypot.org. Once you've got your account, activate the HTTP Blacklist service.
You'll be issued with an access key. Make a note of this as you'll need it to configure the module.

Drop the BLProtector assembly into your websites bin folder. Open your websites web.config and add the following sections.

<configuration>
	<configSections>
		<section name="blProtector" type="ClinPhone.BLProtector.BlacklistConfig, BLProtector" />
	</configSections>

	<!-- Blacklist Protector config element -->
	<blProtector accessKey="<your access key>" blockedurl="<error page url to show when blocked>" threatThreshold="5" />

	<system.web>
		<httpModules>
			<add name="blProtector" type="ClinPhone.BLProtector.BlacklistModule, BLProtector"/>
		</httpModules>
	</system.web>
</configuration>

Make sure you follow all the appropriate rules when adding the above to your web config, ie if the element exist, add to them, don't duplicate them.
Replace <your access key> with the Access Key you noted earlier. Also enter an address to redirect to when a user is blocked.

The treatThreshold setting allows you to set the maximum level that a matched IP address can have to be allowed to browse your site. The threat threshold is returned
for any IP address tracked by Project Honeypot. Refer to their site for more information on what this value means. The smaller this value, the more restrictive it is,
the more people you will potentially block.

That's all you need. But how do you know if it works?

Test Mode
within the <blProtector /> element you entered, add testMode="true". This puts the module in a test mode whereby rather than use the ip address of the client,
random bad ip addresses are generated and you will always see the redirected page.

Advanced Settings
If your website sits behind a proxy server for instance, the client IP address may not represent the IP address of the actual client. By adding ipHeader="<header name>"
to the config element you can tell the module to get the IP address from another header.

BLProtector can check for the presence of a cookie and use this cookie to skip the IP address check. This could be used on the block page via javascript to prove the
user is human and allow them to continue accessing your site. In the current release this cookie just needs to exist - it's contents are not checked. There are methods
on the BLResponse object for setting and checking this cookie, although you can use whatever method you want to create it.

