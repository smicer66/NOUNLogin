package com.noun.sso;
/**
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2011-2013 ForgeRock AS. All Rights Reserved
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://forgerock.org/license/CDDLv1.0.html
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at http://forgerock.org/license/CDDLv1.0.html
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 */


import java.security.Principal;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;

import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.InvalidPasswordException;
import com.sun.identity.authentication.spi.PagePropertiesCallback;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;



public class NounLoginAuth extends AMLoginModule
{

  // Name for the debug-log
  private final static String DEBUG_NAME = "NounLoginAuth";
  

  // Name of the resource bundle
  private final static String amAuthNounLoginAuth = "amAuthNounLoginAuth";

  // User names for authentication logic
  private final static String USERNAME = "test";
  private final static String ERROR_1_NAME = "test1";
  private final static String ERROR_2_NAME = "test2";

  // Orders defined in the callbacks file
  private final static int STATE_BEGIN = 1;
  private final static int STATE_AUTH = 2;
  private final static int STATE_ERROR = 3;

  private final static Debug debug = Debug.getInstance(DEBUG_NAME);

  private Map options;
  private ResourceBundle bundle;
  private String who = null;

  private List internal=null;



  public NounLoginAuth()
  {
    super();
  }



//  @Override
  // This method stores service attributes and localized properties
  // for later use.
  public void init(Subject subject, Map sharedState, Map options)
  {
    if (debug.messageEnabled())
    {
      debug.message("NounLoginAuth::init");
    }
    this.options = options;
    bundle = amCache.getResBundle(amAuthNounLoginAuth, getLoginLocale());
    
  }



//  @Override
  public int process(Callback[] callbacks, int state) throws LoginException
  {

    if (debug.messageEnabled())
    {
      debug.message("NounLoginAuth::process state: " + state);
    }

    switch (state)
    {

    case STATE_BEGIN:
      // No time wasted here - simply modify the UI and
      // proceed to next state
      substituteUIStrings();
      return STATE_AUTH;

    case STATE_AUTH:
      String keyAccess = this.getHttpServletRequest().getParameter("keyAccess");
      if(keyAccess!=null && keyAccess.equalsIgnoreCase("pde"))
      {
    	  who = "pde";
      }else if(keyAccess!=null && keyAccess.equalsIgnoreCase("byc"))
      {
    	  who = "cyb";
      }
      // Get data from callbacks. Refer to callbacks XML file.
      NameCallback nc = (NameCallback) callbacks[0];
      PasswordCallback pc = (PasswordCallback) callbacks[1];
      String username = nc.getName();
      String password = new String(pc.getPassword());

      // First errorstring is stored in "sampleauth-error-1" property.
      if (username.equals(ERROR_1_NAME))
      {
        setErrorText("nounloginauth-error-1");
        return STATE_ERROR;
      }

      // Second errorstring is stored in "sampleauth-error-2" property.
      if (username.equals(ERROR_2_NAME))
      {
        setErrorText("nounloginauth-error-2");
        return STATE_ERROR;
      }

      if (username.equals(USERNAME) && password.equals("password"))
      {
        return ISAuthConstants.LOGIN_SUCCEED;
      }

      throw new InvalidPasswordException("password is wrong", USERNAME);

    case STATE_ERROR:
      return STATE_ERROR;
    default:
      throw new AuthLoginException("invalid state");

    }
  }



//  @Override
  public Principal getPrincipal()
  {
    return new NounLoginAuthPrincipal(USERNAME);
  }



  private void setErrorText(String err) throws AuthLoginException
  {
    // Receive correct string from properties and substitute the
    // header in callbacks order 3.
    substituteHeader(STATE_ERROR, bundle.getString(err));
  }



  private void substituteUIStrings() throws AuthLoginException
  {
    // Get service specific attribute configured in OpenAM
    String ssa = CollectionHelper.getMapAttr(options,
        "nounloginauth-service-specific-attribute");

    // Get property from bundle
    String new_hdr = ssa + " "
        + bundle.getString("nounloginauth-ui-login-header");
    substituteHeader(STATE_AUTH, new_hdr);

    replaceCallback(STATE_AUTH, 0, new NameCallback(bundle
      .getString("nounloginauth-ui-username-prompt")));

    replaceCallback(STATE_AUTH, 1, new PasswordCallback(bundle
            .getString("nounloginauth-ui-password-prompt"), false));
  }
  
  public void substituteHeader(int state, String header) throws AuthLoginException {
	  if (debug.messageEnabled()) {
		  debug.message("substituteHeader : state=" + state + ", header=" + header);
	  }
	  // check state length
	  if (state > 3) {
		  if(bundle!=null)
			  throw new AuthLoginException(header, "invalidState", new Object[]{new Integer(state)});
	  }
	  // check callback length for the state
	  Callback[] ext = getCallback(state);
	  if (ext.length<=0) {
		  if(bundle!=null)
			  throw new AuthLoginException(header, "invalidCallbackIndex", null);
	  }
	  
	  // in internal, first Callback is always PagePropertiesCallback
	  if ((header!=null)&&(header.length() != 0)) {
		  
//		  PagePropertiesCallback pc = (PagePropertiesCallback)((Callback[]) internal.get(state-1))[0];
	  
		  // substitute string
//		  pc.setHeader(header);
	  }
  }

}
