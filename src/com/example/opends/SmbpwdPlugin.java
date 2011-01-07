/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at
 * trunk/opends/resource/legal-notices/OpenDS.LICENSE
 * or https://OpenDS.dev.java.net/OpenDS.LICENSE.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at
 * trunk/opends/resource/legal-notices/OpenDS.LICENSE.  If applicable,
 * add the following below this CDDL HEADER, with the fields enclosed
 * by brackets "[]" replaced with your own identifying * information:
 *      Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 * 
 * Copyright 2010 Spiber inc.
 * 
 */
package com.example.opends;

import static org.opends.server.loggers.ErrorLogger.logError;

import java.util.List;
import java.util.Set;

import org.opends.server.api.plugin.PluginType;
import org.opends.server.api.plugin.PluginResult;
import org.opends.server.api.plugin.DirectoryServerPlugin;
import org.opends.server.config.ConfigException;

import org.opends.server.types.Attribute;
import org.opends.server.types.AttributeType;
import org.opends.server.types.AttributeValue;
import org.opends.server.types.Attributes;
import org.opends.server.types.DirectoryException;
import org.opends.server.types.DN;
import org.opends.server.types.Entry;
import org.opends.server.types.Modification;
import org.opends.server.types.ModificationType;
import org.opends.server.types.ConfigChangeResult;
import org.opends.server.types.InitializationException;
import org.opends.server.types.ResultCode;
import org.opends.server.types.operation.PreOperationModifyOperation;
// TODO : Support PreOperationAddOperation
// import org.opends.server.types.operation.PreOperationAddOperation;

import org.opends.server.admin.server.ConfigurationChangeListener;
import org.opends.messages.Message;


/* JCIFS library for MD4 hashing. */
import java.io.UnsupportedEncodingException;
import jcifs.util.MD4;
import jcifs.util.Hexdump;


import com.example.opends.server.SmbpwdPluginCfg;
import static com.example.opends.messages.SmbpwdPluginMessages.*;


/**
 * The example plugin implementation class. This plugin will output
 * the configured message to the error log during server start up.
 */
public class SmbpwdPlugin extends
  DirectoryServerPlugin<SmbpwdPluginCfg> implements
  ConfigurationChangeListener<SmbpwdPluginCfg> {

  // The current configuration.
  private SmbpwdPluginCfg config;



  /**
   * Default constructor.
   */
  public SmbpwdPlugin() {
    super();
  }


  /**
   * Performs any initialization necessary for this plugin.  This will
   * be called as soon as the plugin has been loaded and before it is
   * registered with the server.
   *
   * @param  pluginTypes    The set of plugin types that indicate the
   *                        ways in which this plugin will be invoked.
   * @param  configuration  The configuration for this plugin.
   *
   * @throws  ConfigException  If the provided entry does not contain
   *                           a valid configuration for this plugin.
   *
   * @throws  InitializationException  If a problem occurs while
   *                                   initializing the plugin that is
   *                                   not related to the server
   *                                   configuration.
   */
  @Override()
  public void initializePlugin(Set<PluginType> pluginTypes,
      SmbpwdPluginCfg configuration)
      throws ConfigException, InitializationException {
	  
	  for (PluginType t : pluginTypes) {
      switch (t) {
      case PRE_OPERATION_MODIFY:
        break;
      default:
        Message message = ERR_INITIALIZE_PLUGIN.get(String.valueOf(t));
        throw new ConfigException(message);
      }
    }

    // Register change listeners. These are not really necessary for
    // this plugin since it is only used during server start-up.
    configuration.addSmbpwdChangeListener(this);

    // Save the configuration.
    this.config = configuration;
  }



  /**
   * Performs any processing that should be done when the Directory
   * Server is in the process of starting.  This method will be called
   * after virtually all other initialization has been performed but
   * before the connection handlers are started.
   *
   * @return  The result of the preOperation plugin processing.
   */
  
  @Override
  public final PluginResult.PreOperation
   doPreOperation(PreOperationModifyOperation modifyOperation){
	String sambaNTPwdOID = "1.3.6.1.4.1.7165.2.1.25"; // oid of sambaNTpassword
	DN entryDN = modifyOperation.getEntryDN();
	Entry entry = modifyOperation.getCurrentEntry();
	
	// Skip NullDN 
	if ( entryDN.isNullDN() ) {
		return PluginResult.PreOperation.continueOperationProcessing();
	}
	// Skip DN without sambaNTPassword
	AttributeType ntpwdType = Attributes.empty(sambaNTPwdOID).getAttributeType();
	if (! entry.hasAttribute(ntpwdType) ) {
		return PluginResult.PreOperation.continueOperationProcessing();
	}
	
	List<AttributeValue> newPasswords = modifyOperation.getNewPasswords();
    
	if (newPasswords != null) {
    	for (AttributeValue v : newPasswords) {
    		/* Create NTHash of new Password */
    		String newNtpwd = generateNTHash(String.valueOf(v.getValue()));
    		
    		if (! newNtpwd.isEmpty()) {
        		Attribute newNtpwdAttribute = Attributes.create(sambaNTPwdOID, newNtpwd);
        		
        		/* REPLACE MOD */
        		Modification replaceNtp = new Modification(ModificationType.valueOf("REPLACE"), newNtpwdAttribute);
        		
        		try {
            		modifyOperation.addModification(replaceNtp);
        		}
        		catch (DirectoryException e) {
            		Message message = NOTE_APPLY_CONFIGURATION_CHANGE.get(
                            "+DirectoryException+",e.getMessage());
            	    logError(message);
            	    return PluginResult.PreOperation.continueOperationProcessing();
        		}
    		}
    	}
    }
	
	return PluginResult.PreOperation.continueOperationProcessing();
  }


    public static String generateNTHash(String cleartext) {
        String ntHash = "";
        MD4 md4 = new MD4();
        byte[] bpass;
        try {
            bpass = cleartext.getBytes("UnicodeLittleUnmarked");

            md4.engineUpdate(bpass, 0, bpass.length);
            byte[] hashbytes = new byte[32];
            hashbytes = md4.engineDigest();
            ntHash = new String(Hexdump.toHexString(hashbytes, 0, hashbytes.length * 2));
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
	return ntHash;
   }

  /**
   * Applies the configuration changes to this change listener.
   *
   * @param config
   *          The new configuration containing the changes.
   * @return Returns information about the result of changing the
   *         configuration.
   */
  public ConfigChangeResult applyConfigurationChange(
      SmbpwdPluginCfg config) {
    // The new configuration has already been validated.

    // Log a message to say that the configuration has changed. This
    // isn't necessary, but we'll do it just to show that the change
    // has taken effect.
    Message message = NOTE_APPLY_CONFIGURATION_CHANGE.get(
                                      String.valueOf(this.config.getMessage()),
                                      String.valueOf(config.getMessage()));
    logError(message);

    // Update the configuration.
    this.config = config;

    // Update was successfull, no restart required.
    return new ConfigChangeResult(ResultCode.SUCCESS, false);
  }
  


  /**
   * Indicates whether the proposed change to the configuration is
   * acceptable to this change listener.
   *
   * @param config
   *          The new configuration containing the changes.
   * @param messages
   *          A list that can be used to hold messages about why the
   *          provided configuration is not acceptable.
   * @return Returns <code>true</code> if the proposed change is
   *         acceptable, or <code>false</code> if it is not.
   */
  public boolean isConfigurationChangeAcceptable(
      SmbpwdPluginCfg config, List<Message> messages) {
    // The only thing that can be validated here is the plugin's
    // message. However, it is always going to be valid, so let's
    // always return true.
    return true;
  }
}
