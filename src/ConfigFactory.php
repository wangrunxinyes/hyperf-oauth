<?php

declare(strict_types=1);

namespace Richard\HyperfPassport;

use Hyperf\Di\Annotation\Inject;
use Hyperf\Contract\ConfigInterface;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Psr\Container\ContainerInterface;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\PasswordGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\Grant\ImplicitGrant;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use Whyperf\Whyperf;

class ConfigFactory {
    /**
     * @Inject
     * @var ContainerInterface
     */
    protected $container;

    /**
     * @Inject
     * @var ConfigInterface
     */
    protected $config;

    /**
     * @param  \Psr\Container\ContainerInterface  $container
     * @param  \Hyperf\Contract\ConfigInterface  $config
     * @return void
     */
    public function __construct(ContainerInterface $container, ConfigInterface $config) {
        $this->container = $container;
        $this->config = $config;
    }

    public function __invoke() {
        $class = $this->config->get('passport.jwt_config_class', false);
        if($class === false){
            return $this->buildDefaultConfig();
        }
        return Whyperf::getContainer()->make($class);
    }

    protected function buildDefaultConfig(){
        return Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::base64Encoded($this->getToken())
        );
    }

    protected function getToken(){
        $token = file_get_contents($this->tokenPath());
        if(is_string($token)){
            return $token;
        }

        throw new \Exception(sprintf("load token failed from %s.", $this->tokenPath()));
    }

    /**
     * The location of the token.
     *
     * @return string
     */
    protected function tokenPath() {
        $path = BASE_PATH . DIRECTORY_SEPARATOR . (config('passport.token_store_path') ?? 'storage');
        return $path . DIRECTORY_SEPARATOR . "oauth-jwt-token.key";
    }
}
