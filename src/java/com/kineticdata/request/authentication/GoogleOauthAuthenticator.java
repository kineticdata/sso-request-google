package com.kineticdata.request.authentication;

import com.kd.arsHelpers.ArsPrecisionHelper;
import com.kd.arsHelpers.SimpleEntry;
import com.kd.kineticSurvey.authentication.Authenticator;
import static com.kd.kineticSurvey.authentication.Authenticator.logger;
import com.kd.kineticSurvey.beans.UserContext;
import com.kd.kineticSurvey.impl.RemedyHandler;
import java.util.Properties;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.scribe.builder.ServiceBuilder;
// Google2Api: https://gist.github.com/yincrash/2465453
import org.scribe.builder.api.Google2Api;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;


public class GoogleOauthAuthenticator extends Authenticator {
    // Constants
    // These values represent defaults, but can be overridden in the properties file
    private static final String SOURCE_FORM = "User";
    private static final String SOURCE_LOOKUPFIELD = "Login Name";
    private static final String SOURCE_RETURNFIELD = "101";
    private static final String AUTHENTICATION_URL = "/login.jsp";
    private static final String SCOPE = "profile email";
    private static final String PROTECTED_RESOURCE_URL = "https://www.googleapis.com/plus/v1/people/me";

    // Instance variables
    private String parseScript;
    private String enableLogging;
    private String lookupArs;
    private String sourceForm;
    private String sourceLookupField;
    private String sourceReturnField;
    private String routeLogoutUrl;
    private String routeAuthenticationUrl;
    
    private String googleApiKey;
    private String googleApiSecret;
    private String ssoCallbackUrl;
    
    private boolean isLoggingEnabled = true;
    private boolean lookupFromARS = true;

    /*--------------------------------------------------------------------------------------------
     * CONSTRUCTOR
     --------------------------------------------------------------------------------------------*/    
    /**
     * Set up the properties from the configuration file
     */
    public GoogleOauthAuthenticator() {
        Properties properties = getProperties();

        // Debug logging
        enableLogging = properties.getProperty("GoogleAuthenticator.enableLogging");
        if ("F".equalsIgnoreCase(enableLogging)) { isLoggingEnabled = false; }
        
        // Remedy Lookup
        lookupArs = properties.getProperty("GoogleAuthenticator.lookupARS");
        if ("F".equalsIgnoreCase(lookupArs)) { lookupFromARS = false; }
        
        sourceForm = properties.getProperty("GoogleAuthenticator.source.form");
        if (sourceForm == null || sourceForm.trim().length()==0) { sourceForm = SOURCE_FORM; }
        
        sourceLookupField = properties.getProperty("GoogleAuthenticator.source.lookupField");
        if (sourceLookupField == null || sourceLookupField.trim().length()==0) { sourceLookupField = SOURCE_LOOKUPFIELD; }
        
        sourceReturnField = properties.getProperty("GoogleAuthenticator.source.returnField");
        if (sourceReturnField == null || sourceReturnField.trim().length()==0) { sourceReturnField = SOURCE_RETURNFIELD; }

        // Routes
        routeAuthenticationUrl = properties.getProperty("GoogleAuthenticator.route.authenticationURL");
        if (routeAuthenticationUrl == null || routeAuthenticationUrl.trim().length()==0) {
            routeAuthenticationUrl = AUTHENTICATION_URL;
        }
        
        googleApiKey = properties.getProperty("GoogleAuthenticator.apiKey");
        if (googleApiKey == null || googleApiKey.trim().length()==0) {
            throw new RuntimeException(this.getClass().getSimpleName() + " - The Google OAuth SSO plugin requires the GoogleAuthenticator.apiKey property to be set.");
        }
        
        googleApiSecret = properties.getProperty("GoogleAuthenticator.apiSecret");
        if (googleApiSecret == null || googleApiSecret.trim().length()==0) {
            throw new RuntimeException(this.getClass().getSimpleName() + " - The Google OAuth SSO plugin requires the GoogleAuthenticator.apiSecret property to be set.");
        }
        
        ssoCallbackUrl = properties.getProperty("GoogleAuthenticator.ssoCallbackUrl");
        if (ssoCallbackUrl == null || ssoCallbackUrl.trim().length()==0) {
            throw new RuntimeException(this.getClass().getSimpleName() + " - The Google OAuth SSO plugin requires the GoogleAuthenticator.ssoCallbackUrl property to be set.");
        }

        routeLogoutUrl = properties.getProperty("GoogleAuthenticator.route.logoutURL");
    }
    
    
    /*--------------------------------------------------------------------------------------------
     * IMPLEMENTATION METHODS
     --------------------------------------------------------------------------------------------*/
    
    /**
     * This method checks if the user is authenticated, and if not, redirects the user
     * to the authentication url.
     *
     * Called from the authentication servlet.
     *
     * @return true if user is authenticated, else false
     * @throws Exception
     */
    @Override
    public boolean authorizeSession() throws Exception {
        
        UserContext localUserContext = getUserContext();
        boolean authorized = false;
        
        // build up an object that helps facilitate making Google OAuth urls
        OAuthService service = new ServiceBuilder()
            .provider(Google2Api.class)
            .apiKey(googleApiKey)
            .apiSecret(googleApiSecret)
            .callback(ssoCallbackUrl)
            .scope(SCOPE)
            .build();
        
        //actually authenticated
        if (localUserContext.isAuthenticated()) {
            
            if (isLoggingEnabled && logger.isDebugEnabled()) {
                logger.debug(this.getClass().getSimpleName()
                    + " - User is already authenticated: " + localUserContext.getUserName());
            }
            if (localUserContext.isInRedirect()) {
                // redirect to the destination url with the Remedy Login ID Parameter removed
                if (isLoggingEnabled && logger.isDebugEnabled()) {
                    logger.debug(this.getClass().getSimpleName()
                            +" - Redirecting user to destination url: " + localUserContext.getFullRedirectURL());
                }
                doRedirect(localUserContext.getFullRedirectURL());
                localUserContext.setInRedirect(false);
            } else {
                authorized = true;
            }
            
        
        //not authenticated yet
        } else {
            
            String loginId = null;
            
            //google redirected the user back to us (callback) with an auth code.
            if (getRequest().getParameter("code") != null) {
                
                try {
                    
                    // exchange the authentication code for an access/bearer token.
                    String authCode = getRequest().getParameter("code");
                    Verifier verifier = new Verifier(authCode);
                    Token accessToken = service.getAccessToken(null, verifier);
                    
                    // use the access token to complete a Google+ api call - we want profile details.
                    OAuthRequest request = new OAuthRequest(Verb.GET, PROTECTED_RESOURCE_URL);
                    service.signRequest(accessToken, request);
                    Response response = request.send();
                    
                    if (isLoggingEnabled && logger.isDebugEnabled()) {
                        logger.debug(this.getClass().getSimpleName() + " - JSON DATA: \r\n" + response.getBody());
                    }
                    
                    //parse the API response JSON
                    JSONObject jsonResponse = (JSONObject)JSONValue.parse(response.getBody());
                    //loginId = (String)jsonResponse.get("id");
                    JSONArray emailsArray = (JSONArray)jsonResponse.get("emails");
                    JSONObject emailObject = (JSONObject)emailsArray.get(0);
                    loginId = (String)emailObject.get("value");
                                        
                    // If the Remedy Login Name has been determined, authenticate the user
                    if (loginId != null && loginId.length() > 0) {
                        
                        if (lookupFromARS) {
                            loginId = getRemedyLoginId(loginId);
                        }

                        if (isLoggingEnabled && logger.isDebugEnabled()) {
                            logger.debug(this.getClass().getSimpleName()+" - Authenticating user: "+loginId);
                        }
                        
                        authenticate(loginId, null, null);
                        if (isLoggingEnabled && logger.isDebugEnabled()) {
                            logger.debug(this.getClass().getSimpleName()+" - Authenticated user: "+loginId);
                        }

                        // redirect to the destination url with the Remedy Login ID Parameter removed
                        if (isLoggingEnabled && logger.isDebugEnabled()) {
                            logger.debug(this.getClass().getSimpleName()
                                    +" - Redirecting user to destination url: " + localUserContext.getFullRedirectURL());
                        }
                        getRequest().getSession(true).setAttribute("Google User Profile", jsonResponse);
                        doRedirect(localUserContext.getFullRedirectURL());

                    } else {
                    // Remedy Login Name is null or blank
                        if (isLoggingEnabled && logger.isDebugEnabled()) {
                            logger.debug(this.getClass().getSimpleName()+" - Remedy Login Name was blank");
                        }
                        // Send to authentication URL
                        sendToAuthenticationUrl();
                    }

                } catch (Exception e) {
                    if (isLoggingEnabled) {
                        logger.error(this.getClass().getSimpleName()
                                +" - Error trying to retrieve an access token from Google",e);
                    }
                    sendToAuthenticationUrl();
                }
                
            // no code parameter in URL so we need to initiate OAuth authentication request.
            } else {
                
                // Set the redirection properties in the user context
                String destination = getRequest().getRequestURL() + "?" + getRequest().getQueryString();
                localUserContext.setInRedirect(true);
                localUserContext.setFullRedirectURL(destination);
                // add the authenticated back into the session
                getRequest().getSession(true).setAttribute("UserContext", localUserContext);
                
                doRedirect(service.getAuthorizationUrl(null));
                
            }

        }
        return authorized;
    }

    
    
    
    
    /**
     * Authenticates the user against the Remedy server.
     *
     * @param userName the Remedy LoginId
     * @param password not used in this implementation
     * @param authentication not used in this implementation
     * @throws Exception
     */
    @Override
    public void authenticate(String userName, String password, String authentication) throws Exception {
        if (userName != null && userName.length() > 0) {
            // initialize the user session
            intializeUserSession(userName);
        }
        else {
            String message = "Cannot authenticate with a blank username";
            if (isLoggingEnabled) {
                logger.error(this.getClass().getSimpleName()+" - "+message);
            }
            throw new RuntimeException(message);
        }
    }

    /**
     * Runs when the user logs out of the system.  Simply redirects to the logout page if it
     * is specified in the properties file, otherwise does nothing.
     *
     * @throws Exception
     */
    @Override
    public void logout() throws Exception {
        // set the logout page if it is defined in the properties file
        if ((this.routeLogoutUrl != null) && (this.routeLogoutUrl.length() > 0)) {
            setLogoutPage(this.routeLogoutUrl);
            if (isLoggingEnabled && logger.isDebugEnabled()) {
                logger.debug(this.getClass().getSimpleName()+" - logging out user and redirecting to: "
                        +this.routeLogoutUrl);
            }
            doRedirect(this.routeLogoutUrl);
        }
    }

    /**
     * Runs when a user doesn't have the appropriate permissions to access a specific resource.
     *
     * @param errorMessage The error message returned from the server
     * @throws Exception
     */
    @Override
    public void handleIncorrectPermissions(String errorMessage) throws Exception {
        if (getRequestType().equalsIgnoreCase("XMLHttpRequest")) {
            getResponse().setHeader("X-Error-Message", errorMessage);
            getResponse().sendError(403, errorMessage);
        } else {
            getUserContext().setErrorMessage(errorMessage);
            authorizeSession();
        }
    }
    

    /*--------------------------------------------------------------------------------------------
     * PRIVATE HELPER METHODS
     --------------------------------------------------------------------------------------------*/
    
    /**
     * Lookup the Remedy Login Name from the specified form and fields.  This could be the User 
     * form, the CTM:People form, or some other form that contains a link between the name held in
     * the certificate, and the Remedy Login Name.
     * 
     * @param principalName The value of the distinguished name retrieved from the certificate
     * @return Remedy Login Name that corresponds to the distinguished name in the certificate
     */
    private String getRemedyLoginId(String searchId) {
        String userId = null;
        if (searchId != null && searchId.trim().length() > 0) {
            try {
                // Set the qualification to lookup the record using the certificate's distinguished name
                String qualification = "'"+this.sourceLookupField+"'=\""+searchId+"\"";
                // Use ArsHelpers to avoid calling the Remedy API directly
                ArsPrecisionHelper helper = new ArsPrecisionHelper(RemedyHandler.getDefaultHelperContext());
                SimpleEntry entry = helper.getFirstSimpleEntry(this.sourceForm, qualification, null);
                if (entry != null) {
                    userId = entry.getEntryFieldValue(this.sourceReturnField);
                }
            }
            catch (Exception e) {
                if (isLoggingEnabled) {
                    logger.error(this.getClass().getSimpleName()+" - Error retriving user record from Remedy", e);
                }
            }
        }
        return userId;
    }
    
    
    /**
     * Evaluates the javascript code defined in the properties file to retrieve
     * a unique userid from a string. Not used in this SSO plugin currently,
     * but a nice method that could be used later potentially.
     * 
     * @param sVal The distinguished name pulled from the certificate
     * @param sScript The javascript code from the properties file
     * @return The distinguished name after evaluating the javscript code
     */
    private String evalScript (String sVal, String sScript){
            String output = "";
            ScriptEngineManager factory = new ScriptEngineManager();
            ScriptEngine engine = factory.getEngineByName("javascript");
            if (sScript != null && sScript.length() > 1){
                    try{ 
                            engine.put("userId", sVal);
                            engine.eval("var result='';" + sScript);
                            output = (String)engine.get("result");
                    } catch (ScriptException e) {
            if (isLoggingEnabled) {
                            logger.error(this.getClass().getSimpleName()+" - Error processing script",e);
            }
                    }
            } else {
                    output = sVal;
            }
            return output;
    }
    
    
    private void sendToAuthenticationUrl() throws Exception {
        // check if the service item specifies an Authentication URL
        String authenticationUrl = getUserContext().getAuthenticationURL();
        if (authenticationUrl == null || authenticationUrl.trim().length() == 0) {
            // check if the authentication url has been defined in the properties file
            authenticationUrl = this.routeAuthenticationUrl;
        }

        // send to the Authentication URL if it is defined
        if (authenticationUrl != null && authenticationUrl.trim().length() > 0) {
            String fullRedirectURL = getRequest().getContextPath() + authenticationUrl;
            getUserContext().setInRedirect(true);
            getUserContext().setAuthenticationType(Authenticator.AUTH_TYPE_DEFAULT);
            getRequest().getSession(true).setAttribute("UserContext", getUserContext());
            if (isLoggingEnabled && logger.isDebugEnabled()) {
                logger.debug(this.getClass().getSimpleName()
                        +" - Sending to Authentication URL for direct ARS authentication: "
                        +fullRedirectURL);
            }
            doRedirect(fullRedirectURL);
        }
    }

}
