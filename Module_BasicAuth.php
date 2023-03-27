<?php
declare(strict_types=1);
namespace GDO\BasicAuth;

use GDO\Core\Application;
use GDO\Core\GDO_Module;
use GDO\Core\GDT_Checkbox;
use GDO\Core\GDT_Secret;
use GDO\Login\Method\Form;
use GDO\User\GDO_User;
use GDO\Util\Common;

/**
 * BasicAuth module for GDOv7.
 *
 * @version 7.0.3
 * @since 6.11.3
 * @author gizmore
 */
final class Module_BasicAuth extends GDO_Module
{

	##############
	### Module ###
	##############
	public function onLoadLanguage(): void { $this->loadLanguage('lang/basic_auth'); }

	##############
	### Config ###
	##############
	public function getConfig(): array
	{
		return [
			GDT_Secret::make('basic_auth_user')->label('user_name'),
			GDT_Secret::make('basic_auth_pass')->label('password'),
			GDT_Checkbox::make('basic_authentication')->initial('1'),
			GDT_Checkbox::make('basic_auth_url')->initial('0'),
		];
	}

	public function onModuleInit(): void
	{
		if (
			($_SERVER['REQUEST_METHOD'] === 'OPTIONS') ||
			(GDO_User::current()->isAuthenticated())
		)
		{
			return;
		}

		if (Application::instance()->isWebServer())
		{
			$deny = true;

			if ($this->cfgURL())
			{
				$this->setupServerVarsFromURL();
			}

			if (
				($username = $this->cfgUsername()) &&
				($password = $this->cfgPassword())
			)
			{
				if ( (isset($_SERVER['PHP_AUTH_USER'])) &&
					(strcasecmp($username, $_SERVER['PHP_AUTH_USER']) === 0) &&
					(strcmp($password, $_SERVER['PHP_AUTH_PW']) === 0) )
				{
					$deny = false;
				}
			}

			if ($deny && $this->cfgAuthentication() && module_enabled('Login'))
			{
				if ( (isset($_SERVER['PHP_AUTH_USER'])) &&
					($this->tryAuthentication($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])) )
				{
					$deny = false;
				}
			}

			if ($deny)
			{
				$this->deny();
			}
		}

	}

	public function cfgURL(): bool { return $this->getConfigValue('basic_auth_url'); }

	private function setupServerVarsFromURL()
	{
		$_SERVER['PHP_AUTH_USER'] = Common::getRequestString('xauth_user', @$_SERVER['PHP_AUTH_USER']);
		$_SERVER['PHP_AUTH_PW'] = Common::getRequestString('xauth_pass', @$_SERVER['PHP_AUTH_PW']);
	}

	public function cfgUsername(): ?string { return $this->getConfigVar('basic_auth_user'); }

	##################
	### Middleware ###
	##################

	public function cfgPassword(): ?string { return $this->getConfigVar('basic_auth_pass'); }

	public function cfgAuthentication(): bool { return $this->getConfigValue('basic_authentication'); }

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
		hdr('WWW-Authenticate: Basic realm="' . sitename() . '"');
		echo t('err_basic_auth');
		exit;
	}

}
