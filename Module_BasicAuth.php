<?php
namespace GDO\BasicAuth;

use GDO\Core\GDO_Module;
use GDO\Core\GDT_Secret;
use GDO\Core\Application;
use GDO\Core\GDT_Checkbox;
use GDO\User\GDO_User;
use GDO\Login\Method\Form;
use GDO\Util\Common;

/**
 * BasicAuth module for GDOv7.
 * 
 * @author gizmore
 * @version 7.0.1
 * @since 6.11.3
 */
final class Module_BasicAuth extends GDO_Module
{
    ##############
    ### Module ###
    ##############
    public function onLoadLanguage() : void { $this->loadLanguage('lang/basic_auth'); }
    
    ##############
    ### Config ###
    ##############
    public function getConfig() : array
    {
        return [
            GDT_Secret::make('basic_auth_user')->label('user_name'),
            GDT_Secret::make('basic_auth_pass')->label('password'),
        	GDT_Checkbox::make('basic_authentication')->initial('1'),
        	GDT_Checkbox::make('basic_auth_url')->initial('0'),
        ];
    }
    public function cfgUsername() : ?string { return $this->getConfigVar('basic_auth_user'); }
    public function cfgPassword() : ?string { return $this->getConfigVar('basic_auth_pass'); }
    public function cfgAuthentication() : bool { return $this->getConfigValue('basic_authentication'); }
    public function cfgURL() : bool { return $this->getConfigValue('basic_auth_url'); }
    
    ##################
    ### Middleware ###
    ##################
    public function onInit()
    {
    	if ( (@$_SERVER['REQUEST_METHOD'] === 'OPTIONS') ||
    	     (GDO_User::current()->isAuthenticated()) )
    	{
    		return null;
    	}
    	
    	if (Application::instance()->isWebServer())
    	{
	    	$deny = true;

    		if ($this->cfgURL())
    		{
    			$this->setupServerVarsFromURL();
    		}
    		
        	if ( ($username = $this->cfgUsername()) &&
        	     ($password = $this->cfgPassword()) )
        	{
        		if (!isset($_SERVER['PHP_AUTH_USER']))
        		{
        		}
        		elseif (strcasecmp($username, $_SERVER['PHP_AUTH_USER']) !== 0)
        		{
        		}
	        	elseif (strcmp($password, $_SERVER['PHP_AUTH_PW']) !== 0)
	        	{
	        	}
	        	else
	        	{
	        		$deny = false;
	        	}
        	}

        	if ($deny && $this->cfgAuthentication() && module_enabled('Login'))
        	{
        		if (!isset($_SERVER['PHP_AUTH_USER']))
        		{
        		}
        		else
        		{
        			$deny = !$this->tryAuthentication($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']);
        		}
        	}
        	if ($deny)
        	{
        		$this->deny();
        	}
    	}
    	return null;
    }
    
    private function setupServerVarsFromURL()
    {
    	$_SERVER['PHP_AUTH_USER'] = Common::getRequestString('xauth_user', @$_SERVER['PHP_AUTH_USER']);
    	$_SERVER['PHP_AUTH_PW'] = Common::getRequestString('xauth_pass', @$_SERVER['PHP_AUTH_PW']);
    }
    
    private function tryAuthentication($username, $password)
    {
    	if (!GDO_User::current()->isAuthenticated())
    	{
	    	Form::make()->onLogin($username, $password);
    	}
    	return GDO_User::current()->isAuthenticated();
    }
    
    private function deny()
    {
        hdrc('HTTP/1.1 401 Unauthorized');
        hdr('WWW-Authenticate: Basic realm="'.sitename().'"');
        echo t('err_basic_auth');
        exit;
    }
    
}
